"""
Demo of the optional ``conditional-write@paramiko`` SFTP extension.

Scenario: an automation reads a remote config file, rewrites it locally,
and uploads it again.  Without a conditional write, a second automation
doing the same concurrently would silently overwrite the first one's
update.  With the extension:

* reading hands out a server-generated version token
  (``SFTPClient.get_remote_version``);
* the new content is uploaded to a temporary file and committed with
  ``SFTPClient.put_conditional``, which atomically checks the version and
  replaces the target on the server;
* exactly one of two racing clients wins; the other gets
  ``VersionConflictError`` and its temporary file is cleaned up;
* the target file is always complete -- readers never see a partial write.

Run from the repository root:

    python demos/conditional_write_demo.py
"""

import os
import shutil
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from paramiko import (  # noqa: E402
    AUTH_SUCCESSFUL,
    OPEN_SUCCEEDED,
    RSAKey,
    SFTPServer,
    ServerInterface,
    Transport,
    VersionConflictError,
)
from paramiko.sftp_client import SFTPClient  # noqa: E402

from tests._loop import LoopSocket  # noqa: E402
from tests._stub_sftp import ConditionalStubSFTPServer  # noqa: E402


class DemoServer(ServerInterface):
    def check_auth_password(self, username, password):
        return AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED


def start_server(remote_root):
    """Start a loopback SSH/SFTP server; return the client transport."""
    ConditionalStubSFTPServer.ROOT = remote_root
    sock_server = LoopSocket()
    sock_client = LoopSocket()
    sock_client.link(sock_server)
    server_transport = Transport(sock_server)
    server_transport.add_server_key(RSAKey.generate(2048))
    server_transport.set_subsystem_handler(
        "sftp", SFTPServer, ConditionalStubSFTPServer
    )
    started = threading.Event()
    server_transport.start_server(started, DemoServer())
    started.wait(1.0)
    client_transport = Transport(sock_client)
    client_transport.connect(username="demo", password="demo")
    return client_transport


def read_config(sftp, remote_path, local_path):
    """Download the remote config and note its version token."""
    sftp.get(remote_path, local_path)
    return sftp.get_remote_version(remote_path)


def main():
    workdir = tempfile.mkdtemp(prefix="condwrite-demo-")
    try:
        remote_root = os.path.join(workdir, "remote")
        os.mkdir(remote_root)
        remote_path = "/app.conf"
        with open(os.path.join(remote_root, "app.conf"), "w") as f:
            f.write("timeout = 30\nretries = 3\n")

        transport = start_server(remote_root)
        client_a = SFTPClient.from_transport(transport)
        client_b = SFTPClient.from_transport(transport)
        print("server supports conditional write:", end=" ")
        print(client_a.supports_conditional_write())

        # both automations read the config and its version token
        local_a = os.path.join(workdir, "app-a.conf")
        local_b = os.path.join(workdir, "app-b.conf")
        version_a = read_config(client_a, remote_path, local_a)
        version_b = read_config(client_b, remote_path, local_b)
        print("client A read version:", version_a)
        print("client B read version:", version_b)

        # both edit their local copy
        with open(local_a, "a") as f:
            f.write("feature_x = on\n")
        with open(local_b, "a") as f:
            f.write("feature_y = on\n")

        # client A commits first: success, and a new version comes back
        new_version = client_a.put_conditional(
            local_a, remote_path, version_a
        )
        print("client A committed; new version:", new_version)

        # client B commits with the now-stale version: conflict
        try:
            client_b.put_conditional(local_b, remote_path, version_b)
            print("ERROR: client B should have conflicted!")
            return 1
        except VersionConflictError as e:
            print("client B was rejected:", e)

        # the target always holds one complete file: A's version
        with open(os.path.join(remote_root, "app.conf")) as f:
            final = f.read()
        print("final remote config:")
        print("".join("    " + line for line in final.splitlines(True)))
        assert final == "timeout = 30\nretries = 3\nfeature_x = on\n"

        leftovers = os.listdir(remote_root)
        print("remote dir contents:", leftovers)
        assert leftovers == ["app.conf"], "temporary file was not cleaned up"

        client_a.close()
        client_b.close()
        transport.close()
        print("demo finished: one commit won, one conflicted, "
              "target is a complete file, no temp files left behind")
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
