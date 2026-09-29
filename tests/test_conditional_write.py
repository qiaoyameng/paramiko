"""
Tests for the optional ``conditional-write@paramiko`` SFTP extension.

Covers the client API (version fetch + atomic conditional commit), the
local reference server implementation, refusal when the server does not
support the extension, temporary-file cleanup, and the two-client
read-modify-write race the extension is meant to solve.
"""

import os
import threading

import pytest

from paramiko import (
    ConditionalWriteUnsupported,
    RSAKey,
    SFTP,
    SFTPServer,
    Transport,
    VersionConflictError,
)

from ._loop import LoopSocket
from ._stub_sftp import ConditionalStubSFTPServer, StubServer
from ._util import _support


@pytest.fixture
def cond_transport():
    """Client transport connected to a conditional-write-capable server."""
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc)
    ts = Transport(socks)
    host_key = RSAKey.from_private_key_file(_support("rsa.key"))
    ts.add_server_key(host_key)
    event = threading.Event()
    server = StubServer()
    ts.set_subsystem_handler(
        "sftp", SFTPServer, ConditionalStubSFTPServer
    )
    ts.start_server(event, server)
    event.wait(1.0)
    tc.connect(username="slowdive", password="pygmalion")
    yield tc
    tc.close()
    ts.close()


@pytest.fixture
def remote_root(tmp_path, monkeypatch):
    """Point the reference server at a private local folder."""
    root = tmp_path / "remote"
    root.mkdir()
    monkeypatch.setattr(ConditionalStubSFTPServer, "ROOT", str(root))
    return root


@pytest.fixture
def cond_clients(cond_transport, remote_root):
    """Two independent SFTP client sessions against the same server."""
    return SFTP.from_transport(cond_transport), SFTP.from_transport(
        cond_transport
    )


def _write(path, content):
    with open(str(path), "w") as f:
        f.write(content)


def _read(path):
    with open(str(path)) as f:
        return f.read()


class TestConditionalWrite:
    def test_server_advertises_extension(self, cond_clients):
        client_a, _ = cond_clients
        assert client_a.supports_conditional_write()

    def test_version_token_tracks_content(self, cond_clients, remote_root):
        client_a, _ = cond_clients
        assert client_a.get_remote_version("/config.txt") == ""
        _write(remote_root / "config.txt", "one\n")
        token = client_a.get_remote_version("/config.txt")
        assert token != ""
        _write(remote_root / "config.txt", "two\n")
        assert client_a.get_remote_version("/config.txt") != token

    def test_two_clients_one_commits_other_conflicts(
        self, cond_clients, remote_root, tmp_path
    ):
        client_a, client_b = cond_clients
        _write(remote_root / "config.txt", "original\n")

        # both clients read the same version
        token_a = client_a.get_remote_version("/config.txt")
        token_b = client_b.get_remote_version("/config.txt")
        assert token_a == token_b

        # both prepare a replacement locally
        local_a = tmp_path / "a.txt"
        local_b = tmp_path / "b.txt"
        _write(local_a, "config-from-A\n")
        _write(local_b, "config-from-B\n")

        # client A commits first and wins
        new_token = client_a.put_conditional(
            str(local_a), "/config.txt", token_a
        )
        assert new_token != token_a
        assert _read(remote_root / "config.txt") == "config-from-A\n"

        # client B's commit is rejected: its version is stale
        with pytest.raises(VersionConflictError):
            client_b.put_conditional(str(local_b), "/config.txt", token_b)

        # the target is still A's complete file
        assert _read(remote_root / "config.txt") == "config-from-A\n"
        # B's temporary file was cleaned up; only the target remains
        assert os.listdir(str(remote_root)) == ["config.txt"]
        # and the visible version is the one A's commit returned
        assert client_b.get_remote_version("/config.txt") == new_token

    def test_create_only_if_absent(self, cond_clients, remote_root, tmp_path):
        client_a, _ = cond_clients
        local = tmp_path / "new.txt"
        _write(local, "fresh\n")
        token = client_a.put_conditional(str(local), "/new.txt", "")
        assert token != ""
        assert _read(remote_root / "new.txt") == "fresh\n"

        # a second "create" with an empty expected version now conflicts
        local2 = tmp_path / "new2.txt"
        _write(local2, "other\n")
        with pytest.raises(VersionConflictError):
            client_a.put_conditional(str(local2), "/new.txt", "")
        assert _read(remote_root / "new.txt") == "fresh\n"
        assert os.listdir(str(remote_root)) == ["new.txt"]

    def test_concurrent_commits_exactly_one_wins(
        self, cond_clients, remote_root, tmp_path
    ):
        client_a, client_b = cond_clients
        _write(remote_root / "c.txt", "v0\n")
        token = client_a.get_remote_version("/c.txt")
        results = {}

        def commit(client, name, content):
            local = tmp_path / name
            _write(local, content)
            try:
                client.put_conditional(str(local), "/c.txt", token)
                results[name] = "ok"
            except VersionConflictError:
                results[name] = "conflict"

        threads = [
            threading.Thread(
                target=commit, args=(client_a, "ta.txt", "A\n")
            ),
            threading.Thread(
                target=commit, args=(client_b, "tb.txt", "B\n")
            ),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sorted(results.values()) == ["conflict", "ok"]
        # whoever lost, the target holds one complete file
        assert _read(remote_root / "c.txt") in ("A\n", "B\n")
        assert os.listdir(str(remote_root)) == ["c.txt"]

    def test_unsupported_server_refuses_conditional_mode(
        self, sftp, tmp_path
    ):
        # the default stub server does not implement the extension
        assert not sftp.supports_conditional_write()
        local = tmp_path / "x.txt"
        _write(local, "data\n")
        with pytest.raises(ConditionalWriteUnsupported):
            sftp.put_conditional(str(local), sftp.FOLDER + "/x.txt", "")
        with pytest.raises(ConditionalWriteUnsupported):
            sftp.get_remote_version(sftp.FOLDER + "/x.txt")
        # nothing was uploaded or renamed behind our back
        assert sftp.listdir(sftp.FOLDER) == []

    def test_failed_upload_leaves_no_temp_file(
        self, cond_clients, remote_root, tmp_path
    ):
        client_a, _ = cond_clients
        _write(remote_root / "config.txt", "keepme\n")
        token = client_a.get_remote_version("/config.txt")
        with pytest.raises(OSError):
            client_a.put_conditional(
                str(tmp_path / "does-not-exist.txt"),
                "/config.txt",
                token,
            )
        assert _read(remote_root / "config.txt") == "keepme\n"
        assert os.listdir(str(remote_root)) == ["config.txt"]
