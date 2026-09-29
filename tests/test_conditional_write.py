"""
Tests for the conditional-write (compare-and-swap) SFTP extensions:
``get-file-version@paramiko`` and ``conditional-commit@paramiko``.
"""

import threading
from io import BytesIO

import pytest

from paramiko import (
    FileVersionConflict,
    RSAKey,
    SFTPClient,
    SFTPError,
    SFTPServer,
    Transport,
    VersionedSFTPServer,
)
from paramiko.sftp import EXT_CONDITIONAL_COMMIT, EXT_GET_FILE_VERSION

from ._loop import LoopSocket
from ._stub_sftp import StubServer
from ._util import _support


@pytest.fixture
def versioned_server(tmp_path):
    """Loopback SFTP server backed by VersionedSFTPServer in a tmp dir."""
    VersionedSFTPServer.reset_version_tracking()
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc)
    ts = Transport(socks)
    host_key = RSAKey.from_private_key_file(_support("rsa.key"))
    ts.add_server_key(host_key)
    event = threading.Event()
    ts.set_subsystem_handler(
        "sftp", SFTPServer, VersionedSFTPServer, root=str(tmp_path)
    )
    ts.start_server(event, StubServer())
    event.wait(1.0)
    tc.connect(username="slowdive", password="pygmalion")
    yield tc, tmp_path
    tc.close()
    ts.close()


@pytest.fixture
def clients(versioned_server):
    """Two independent SFTP clients against the same versioned server."""
    tc, tmp_path = versioned_server
    return SFTPClient.from_transport(tc), SFTPClient.from_transport(tc)


def seed(tmp_path, name="config.txt", data=b"workers=1\n"):
    (tmp_path / name).write_bytes(data)
    return "/" + name


class TestConditionalWrite:
    def test_extensions_advertised(self, clients):
        alice, _ = clients
        assert EXT_GET_FILE_VERSION in alice.server_extensions
        assert EXT_CONDITIONAL_COMMIT in alice.server_extensions

    def test_get_file_version(self, clients, versioned_server):
        _, tmp_path = versioned_server
        alice, _ = clients
        remote = seed(tmp_path)
        version = alice.get_file_version(remote)
        assert isinstance(version, str) and version
        # stable until the file changes
        assert alice.get_file_version(remote) == version

    def test_get_file_version_missing_file(self, clients):
        alice, _ = clients
        with pytest.raises(IOError):
            alice.get_file_version("/nope.txt")

    def test_conditional_commit_success(self, clients, versioned_server):
        _, tmp_path = versioned_server
        alice, _ = clients
        remote = seed(tmp_path)
        old_version = alice.get_file_version(remote)
        new_version = alice.conditional_putfo(
            BytesIO(b"workers=4\n"), remote, expected_version=old_version
        )
        assert new_version != old_version
        with alice.open(remote, "r") as f:
            assert f.read() == b"workers=4\n"
        # temp file was consumed by the commit
        assert alice.listdir("/") == ["config.txt"]

    def test_two_clients_one_wins_one_conflicts(
        self, clients, versioned_server
    ):
        _, tmp_path = versioned_server
        alice, bob = clients
        remote = seed(tmp_path)

        # both read the same version, both prepare an update
        version_a = alice.get_file_version(remote)
        version_b = bob.get_file_version(remote)
        assert version_a == version_b

        new_version = alice.conditional_putfo(
            BytesIO(b"workers=4\n"), remote, expected_version=version_a
        )
        with pytest.raises(FileVersionConflict):
            bob.conditional_putfo(
                BytesIO(b"workers=99\n"), remote, expected_version=version_b
            )

        # the target is always a complete file: alice's version, untouched
        # by bob's failed commit
        with alice.open(remote, "r") as f:
            assert f.read() == b"workers=4\n"
        assert alice.get_file_version(remote) == new_version
        # bob's client cleaned up only its own temp file
        assert alice.listdir("/") == ["config.txt"]

        # bob can recover by re-reading and retrying
        retry_version = bob.conditional_putfo(
            BytesIO(b"workers=4\ndebug=on\n"),
            remote,
            expected_version=bob.get_file_version(remote),
        )
        with bob.open(remote, "r") as f:
            assert f.read() == b"workers=4\ndebug=on\n"
        assert bob.get_file_version(remote) == retry_version

    def test_conflict_does_not_touch_other_temp_files(
        self, clients, versioned_server
    ):
        _, tmp_path = versioned_server
        alice, bob = clients
        remote = seed(tmp_path)
        # someone else's unrelated temp file sitting next to the target
        (tmp_path / "config.txt.condtmp-other").write_bytes(b"not mine")
        version = alice.get_file_version(remote)
        bob_version = bob.get_file_version(remote)
        alice.conditional_putfo(
            BytesIO(b"workers=2\n"), remote, expected_version=version
        )
        with pytest.raises(FileVersionConflict):
            bob.conditional_putfo(
                BytesIO(b"workers=3\n"), remote, expected_version=bob_version
            )
        # bob's cleanup removed only his own temp file
        assert sorted(alice.listdir("/")) == [
            "config.txt",
            "config.txt.condtmp-other",
        ]

    def test_refused_when_server_lacks_extension(self, sftp):
        # conftest's `sftp` fixture talks to StubSFTPServer, which does not
        # implement the conditional-write extensions
        assert EXT_GET_FILE_VERSION not in sftp.server_extensions
        assert EXT_CONDITIONAL_COMMIT not in sftp.server_extensions
        remote = "{}/config.txt".format(sftp.FOLDER)
        with sftp.open(remote, "w") as f:
            f.write(b"original\n")
        # conditional mode is refused outright -- no stat+rename fallback
        with pytest.raises(SFTPError):
            sftp.get_file_version(remote)
        with pytest.raises(SFTPError):
            sftp.conditional_commit(remote + ".tmp", remote, "v1")
        with pytest.raises(SFTPError):
            sftp.conditional_putfo(BytesIO(b"changed\n"), remote)
        with sftp.open(remote, "r") as f:
            assert f.read() == b"original\n"
        assert sftp.listdir(sftp.FOLDER) == ["config.txt"]
