"""
Unit tests for OpenSSH host certificate validation against known_hosts
@cert-authority (and @revoked) entries.

CA keys, host keys and certificates are generated locally with ssh-keygen
at test time.
"""

import os
import shutil
import subprocess
import unittest
from base64 import decodebytes
from tempfile import TemporaryDirectory

from paramiko.hostkeys import HostKeys
from paramiko.pkey import PKey
from paramiko.util import b


GOOD_HOST = "good.example.com"
OTHER_HOST = "evil.example.com"


def require_ssh_keygen():
    if shutil.which("ssh-keygen") is None:
        raise unittest.SkipTest("ssh-keygen is not available")


class HostCertTestCase(unittest.TestCase):
    def setUp(self):
        require_ssh_keygen()
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name
        self._keygen("ca")
        self._keygen("host")
        with open(self._path("ca.pub")) as f:
            self.ca_pub_line = f.read().strip()
        with open(self._path("host.pub")) as f:
            self.host_pub_line = f.read().strip()

    def _path(self, name):
        return os.path.join(self.dir, name)

    def _keygen(self, name):
        subprocess.check_call(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "rsa",
                "-b",
                "2048",
                "-f",
                self._path(name),
                "-N",
                "",
            ]
        )

    def _sign(self, *args):
        # Sign the host public key, producing host-cert.pub.
        subprocess.check_call(
            ["ssh-keygen", "-q", "-s", self._path("ca"), "-I", "test"]
            + list(args)
            + [self._path("host.pub")]
        )
        with open(self._path("host-cert.pub")) as f:
            line = f.read().strip()
        key_type, key_b64 = line.split()[:2]
        return PKey.from_type_string(key_type, decodebytes(b(key_b64)))

    def _sign_host_cert(self, principals=GOOD_HOST, validity="+52w", *extra):
        args = ["-h", "-n", principals, "-V", validity]
        return self._sign(*(list(args) + list(extra)))

    def _host_keys(self, *lines):
        path = self._path("known_hosts")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return HostKeys(path)

    def _ca_line(self, hostnames=GOOD_HOST, marker="@cert-authority"):
        parts = self.ca_pub_line.split()
        return "{} {} {} {}".format(marker, hostnames, parts[0], parts[1])

    def test_valid_host_cert_is_accepted(self):
        cert = self._sign_host_cert()
        host_keys = self._host_keys(self._ca_line())
        assert host_keys.check(GOOD_HOST, cert)

    def test_wrong_hostname_is_rejected(self):
        cert = self._sign_host_cert()
        host_keys = self._host_keys(self._ca_line())
        # Cert principals do not cover this hostname.
        assert not host_keys.check(OTHER_HOST, cert)
        # CA entry is for a different host than the one we connect to.
        host_keys = self._host_keys(self._ca_line(hostnames=OTHER_HOST))
        assert not host_keys.check(GOOD_HOST, cert)

    def test_expired_cert_is_rejected(self):
        cert = self._sign_host_cert(validity="20200101:20200102")
        host_keys = self._host_keys(self._ca_line())
        assert not host_keys.check(GOOD_HOST, cert)

    def test_not_yet_valid_cert_is_rejected(self):
        cert = self._sign_host_cert(validity="20300101:20300102")
        host_keys = self._host_keys(self._ca_line())
        assert not host_keys.check(GOOD_HOST, cert)

    def test_unknown_critical_option_is_rejected(self):
        cert = self._sign_host_cert(
            GOOD_HOST, "+52w", "-O", "critical:bogus@example.com=1"
        )
        host_keys = self._host_keys(self._ca_line())
        assert not host_keys.check(GOOD_HOST, cert)

    def test_user_cert_is_not_accepted_as_host_cert(self):
        # No -h flag: this produces a user (client) certificate.
        cert = self._sign("-n", GOOD_HOST, "-V", "+52w")
        host_keys = self._host_keys(self._ca_line())
        assert not host_keys.check(GOOD_HOST, cert)

    def test_hashed_hostname_entry_is_matched(self):
        cert = self._sign_host_cert()
        hashed = HostKeys.hash_host(GOOD_HOST)
        host_keys = self._host_keys(self._ca_line(hostnames=hashed))
        assert host_keys.check(GOOD_HOST, cert)

    def test_wrong_ca_is_rejected(self):
        cert = self._sign_host_cert()
        # Trust a different CA than the one which signed the cert.
        self._keygen("other-ca")
        with open(self._path("other-ca.pub")) as f:
            other = f.read().strip().split()
        host_keys = self._host_keys(
            "@cert-authority {} {} {}".format(GOOD_HOST, other[0], other[1])
        )
        assert not host_keys.check(GOOD_HOST, cert)

    def test_revoked_key_takes_priority_over_valid_cert(self):
        cert = self._sign_host_cert()
        parts = self.host_pub_line.split()
        revoked = "@revoked {} {} {}".format(GOOD_HOST, parts[0], parts[1])
        host_keys = self._host_keys(self._ca_line(), revoked)
        assert not host_keys.check(GOOD_HOST, cert)

    def test_plain_host_key_still_uses_original_flow(self):
        parts = self.host_pub_line.split()
        host_keys = self._host_keys(
            self._ca_line(),
            "{} {} {}".format(GOOD_HOST, parts[0], parts[1]),
        )
        raw_key = PKey.from_type_string(parts[0], decodebytes(b(parts[1])))
        assert host_keys.check(GOOD_HOST, raw_key)

    def test_ca_entry_does_not_trust_bare_host_key(self):
        # A @cert-authority entry alone must not authenticate the raw host
        # key, only certificates signed by the CA.
        parts = self.host_pub_line.split()
        host_keys = self._host_keys(self._ca_line())
        raw_key = PKey.from_type_string(parts[0], decodebytes(b(parts[1])))
        assert not host_keys.check(GOOD_HOST, raw_key)
        # Nor should the CA entry show up as a regular host key.
        assert host_keys.lookup(GOOD_HOST) is None

    def test_marker_round_trips_through_save(self):
        host_keys = self._host_keys(self._ca_line())
        out = self._path("known_hosts.out")
        host_keys.save(out)
        with open(out) as f:
            saved = f.read()
        assert saved.startswith("@cert-authority ")
        reloaded = HostKeys(out)
        cert = self._sign_host_cert()
        assert reloaded.check(GOOD_HOST, cert)
