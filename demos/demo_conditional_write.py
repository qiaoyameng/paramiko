"""
Demo: conditional (compare-and-swap) writes over SFTP.

Scenario: two automation clients both read a remote config file, modify it
locally, and write it back.  Without coordination, the second write would
silently overwrite the first.  With the ``get-file-version@paramiko`` /
``conditional-commit@paramiko`` extensions, the first commit succeeds and
the second one fails with `.FileVersionConflict` -- and the target file is
always a complete file, never a partial one.

Run with:  python demos/demo_conditional_write.py
"""

import json
import os
import tempfile
import threading
from io import BytesIO

from paramiko import (
    AUTH_SUCCESSFUL,
    OPEN_SUCCEEDED,
    FileVersionConflict,
    RSAKey,
    SFTPClient,
    SFTPServer,
    ServerInterface,
    Transport,
    VersionedSFTPServer,
)


class LoopSocket:
    """
    An in-memory socket stand-in: data written to one end is readable from
    the other.  Lets the demo run a real SSH/SFTP handshake without any
    network access.  (Mirrors ``tests/_loop.py``.)
    """

    def __init__(self):
        self._in_buffer = bytes()
        self._cv = threading.Condition()
        self._timeout = None
        self._mate = None
        self._closed = False

    @classmethod
    def pair(cls):
        a, b = cls(), cls()
        a._mate = b
        b._mate = a
        return a, b

    def send(self, data):
        if self._mate is None:
            raise EOFError()
        with self._mate._cv:
            self._mate._in_buffer += bytes(data)
            self._mate._cv.notify_all()
        return len(data)

    def recv(self, n):
        with self._cv:
            if self._mate is None:
                return bytes()
            if len(self._in_buffer) == 0:
                self._cv.wait(self._timeout)
            if len(self._in_buffer) == 0:
                raise TimeoutError()
            out = self._in_buffer[:n]
            self._in_buffer = self._in_buffer[n:]
            return out

    def settimeout(self, n):
        self._timeout = n

    def close(self):
        mate, self._mate = self._mate, None
        self._closed = True
        if mate is not None:
            mate.close()


class AnyAuthServer(ServerInterface):
    def check_auth_password(self, username, password):
        return AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED


def start_server(root):
    """Start a loopback SFTP server serving ``root``; return client sock."""
    client_sock, server_sock = LoopSocket.pair()
    server_transport = Transport(server_sock)
    server_transport.add_server_key(RSAKey.generate(2048))
    server_transport.set_subsystem_handler(
        "sftp", SFTPServer, VersionedSFTPServer, root=root
    )
    event = threading.Event()
    server_transport.start_server(event, AnyAuthServer())
    event.wait(1.0)
    return client_sock


def connect(client_sock):
    transport = Transport(client_sock)
    transport.connect(username="automation", password="secret")
    return transport


def read_config(sftp, path):
    with sftp.open(path, "r") as f:
        return json.loads(f.read().decode("utf-8"))


def main():
    root = tempfile.mkdtemp(prefix="sftp-conditional-demo-")
    remote = "/config.json"
    with open(os.path.join(root, "config.json"), "w") as f:
        json.dump({"workers": 1, "debug": False}, f)

    transport = connect(start_server(root))
    alice = SFTPClient.from_transport(transport)
    bob = SFTPClient.from_transport(transport)

    # both clients read the config and note its server-generated version
    config_a = read_config(alice, remote)
    version_a = alice.get_file_version(remote)
    config_b = read_config(bob, remote)
    version_b = bob.get_file_version(remote)
    print("both clients read {} (version {})".format(config_a, version_a))
    assert version_a == version_b

    # both edit locally, then try to write back conditionally
    config_a["workers"] = 4
    config_b["debug"] = True

    new_version = alice.conditional_putfo(
        BytesIO(json.dumps(config_a).encode("utf-8")),
        remote,
        expected_version=version_a,
    )
    print("alice committed: {} (new version {})".format(config_a, new_version))

    try:
        bob.conditional_putfo(
            BytesIO(json.dumps(config_b).encode("utf-8")),
            remote,
            expected_version=version_b,
        )
        print("BUG: bob's commit should have conflicted!")
    except FileVersionConflict as e:
        print("bob's commit was rejected: {}".format(e))

    # the target is always a complete file: alice's full config, with
    # bob's change NOT silently merged or lost into a partial file
    final = read_config(alice, remote)
    assert final == config_a, final
    print("final remote config: {}".format(final))

    # bob's failed commit cleaned up his own temp file; nothing else remains
    leftovers = [n for n in alice.listdir("/") if ".condtmp-" in n]
    assert not leftovers, leftovers
    print("no leftover temp files; bob may retry from version", new_version)

    # bob retries: re-read, re-apply his change on top, commit again
    config_b2 = read_config(bob, remote)
    config_b2["debug"] = True
    final_version = bob.conditional_putfo(
        BytesIO(json.dumps(config_b2).encode("utf-8")),
        remote,
        expected_version=bob.get_file_version(remote),
    )
    print("bob retried and committed (version {})".format(final_version))
    print("final remote config: {}".format(read_config(alice, remote)))

    alice.close()
    bob.close()
    transport.close()


if __name__ == "__main__":
    main()
