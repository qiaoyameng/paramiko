"""
Unit tests for OpenSSH host certificate support in HostKeys.

CA keys and certificates are generated locally at test time; no external
fixtures or network access are required.
"""

import os
import tempfile
import time
import unittest

from paramiko import HostKeys, RSAKey, Ed25519Key, PKey
from paramiko.hostkeys import (
    CERT_TYPE_HOST,
    CERT_TYPE_USER,
    HostKeyEntry,
    parse_certificate,
)
from paramiko.message import Message

from ._util import _support


NOW = int(time.time())
# "Forever" per PROTOCOL.certkeys
UINT64_MAX = 0xFFFFFFFFFFFFFFFF


def make_rsa_cert_blob(
    ca_key,
    host_key,
    principals,
    cert_type=CERT_TYPE_HOST,
    valid_after=0,
    valid_before=UINT64_MAX,
    critical_options=(),
    serial=1,
    key_id="paramiko-test",
    advertised_ca_key=None,
):
    """
    Build (and sign with ``ca_key``) an ``ssh-rsa-cert-v01@openssh.com``
    certificate for ``host_key``.
    """
    m = Message()
    m.add_string("ssh-rsa-cert-v01@openssh.com")
    m.add_string(os.urandom(16))  # nonce
    m.add_mpint(host_key.public_numbers.e)
    m.add_mpint(host_key.public_numbers.n)
    m.add_int64(serial)
    m.add_int(cert_type)
    m.add_string(key_id)
    packed = Message()
    for name in principals:
        packed.add_string(name)
    m.add_string(packed.asbytes())
    m.add_int64(valid_after)
    m.add_int64(valid_before)
    packed = Message()
    for name, data in critical_options:
        packed.add_string(name)
        packed.add_string(data)
    m.add_string(packed.asbytes())
    m.add_string(b"")  # extensions
    m.add_string(b"")  # reserved
    if advertised_ca_key is None:
        advertised_ca_key = ca_key
    m.add_string(advertised_ca_key.asbytes())
    sig = ca_key.sign_ssh_data(m.asbytes(), algorithm="rsa-sha2-512")
    m.add_string(sig.asbytes())
    return m.asbytes()


def make_ed25519_cert_blob(ca_key, host_key, principals):
    """
    Build an ``ssh-ed25519-cert-v01@openssh.com`` certificate (signed by an
    RSA CA) for ``host_key``.
    """
    m = Message()
    m.add_string("ssh-ed25519-cert-v01@openssh.com")
    m.add_string(os.urandom(16))  # nonce
    m.add_string(host_key.verifying_key.encode())
    m.add_int64(1)  # serial
    m.add_int(CERT_TYPE_HOST)
    m.add_string("paramiko-test")
    packed = Message()
    for name in principals:
        packed.add_string(name)
    m.add_string(packed.asbytes())
    m.add_int64(0)
    m.add_int64(UINT64_MAX)
    m.add_string(b"")  # critical options
    m.add_string(b"")  # extensions
    m.add_string(b"")  # reserved
    m.add_string(ca_key.asbytes())
    sig = ca_key.sign_ssh_data(m.asbytes(), algorithm="rsa-sha2-512")
    m.add_string(sig.asbytes())
    return m.asbytes()


def rsa_cert_key(ca_key, host_key, principals, **kwargs):
    blob = make_rsa_cert_blob(ca_key, host_key, principals, **kwargs)
    return PKey.from_type_string("ssh-rsa-cert-v01@openssh.com", blob)


class HostCertificateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_key = RSAKey.generate(2048)
        cls.other_ca_key = RSAKey.generate(2048)
        cls.host_key = RSAKey.generate(2048)
        cls.hostname = "cert.example.com"

    def load_hostkeys(self, lines):
        fd, path = tempfile.mkstemp(suffix=".known_hosts")
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        return HostKeys(path)

    def ca_line(self, hostname=None, ca_key=None):
        if hostname is None:
            hostname = self.hostname
        if ca_key is None:
            ca_key = self.ca_key
        return "@cert-authority {} ssh-rsa {}".format(
            hostname, ca_key.get_base64()
        )

    def good_cert(self, **kwargs):
        kwargs.setdefault("principals", [self.hostname])
        return rsa_cert_key(self.ca_key, self.host_key, **kwargs)

    def test_valid_certificate_accepted(self):
        hostkeys = self.load_hostkeys([self.ca_line()])
        assert hostkeys.check_cert(self.hostname, self.good_cert())

    def test_certificate_for_other_host_rejected(self):
        hostkeys = self.load_hostkeys([self.ca_line()])
        cert = self.good_cert(principals=["other.example.com"])
        assert not hostkeys.check_cert(self.hostname, cert)

    def test_certificate_rejected_when_ca_not_trusted_for_host(self):
        # CA is only trusted for some other hostname.
        hostkeys = self.load_hostkeys(
            [self.ca_line(hostname="other.example.com")]
        )
        cert = self.good_cert(principals=["other.example.com"])
        assert not hostkeys.check_cert(self.hostname, cert)

    def test_expired_certificate_rejected(self):
        hostkeys = self.load_hostkeys([self.ca_line()])
        cert = self.good_cert(valid_after=0, valid_before=NOW - 100)
        assert not hostkeys.check_cert(self.hostname, cert)

    def test_not_yet_valid_certificate_rejected(self):
        hostkeys = self.load_hostkeys([self.ca_line()])
        cert = self.good_cert(
            valid_after=NOW + 3600, valid_before=NOW + 7200
        )
        assert not hostkeys.check_cert(self.hostname, cert)

    def test_unknown_critical_option_rejected(self):
        hostkeys = self.load_hostkeys([self.ca_line()])
        cert = self.good_cert(
            critical_options=[("force-command", b"/bin/false")]
        )
        assert not hostkeys.check_cert(self.hostname, cert)

    def test_user_certificate_rejected(self):
        hostkeys = self.load_hostkeys([self.ca_line()])
        cert = self.good_cert(cert_type=CERT_TYPE_USER)
        assert not hostkeys.check_cert(self.hostname, cert)

    def test_untrusted_ca_rejected(self):
        hostkeys = self.load_hostkeys([self.ca_line()])
        # Signed by a CA we do not trust at all.
        cert = rsa_cert_key(
            self.other_ca_key, self.host_key, [self.hostname]
        )
        assert not hostkeys.check_cert(self.hostname, cert)
        # Claims to be our CA, but signed by someone else.
        cert = rsa_cert_key(
            self.other_ca_key,
            self.host_key,
            [self.hostname],
            advertised_ca_key=self.ca_key,
        )
        assert not hostkeys.check_cert(self.hostname, cert)

    def test_hashed_hostname_ca_entry(self):
        hashed = HostKeys.hash_host(self.hostname)
        hostkeys = self.load_hostkeys([self.ca_line(hostname=hashed)])
        assert hostkeys.check_cert(self.hostname, self.good_cert())
        # A different hostname must not match the hashed entry.
        cert = self.good_cert(principals=["other.example.com"])
        assert not hostkeys.check_cert("other.example.com", cert)

    def test_revoked_host_key_rejected_despite_valid_cert(self):
        revoked = "@revoked {} ssh-rsa {}".format(
            self.hostname, self.host_key.get_base64()
        )
        hostkeys = self.load_hostkeys([self.ca_line(), revoked])
        assert not hostkeys.check_cert(self.hostname, self.good_cert())

    def test_revoked_ca_key_rejected(self):
        revoked = "@revoked {} ssh-rsa {}".format(
            self.hostname, self.ca_key.get_base64()
        )
        hostkeys = self.load_hostkeys([self.ca_line(), revoked])
        assert not hostkeys.check_cert(self.hostname, self.good_cert())

    def test_revoked_plain_key_takes_precedence(self):
        plain = "{} ssh-rsa {}".format(
            self.hostname, self.host_key.get_base64()
        )
        revoked = "@revoked {} ssh-rsa {}".format(
            self.hostname, self.host_key.get_base64()
        )
        hostkeys = self.load_hostkeys([plain, revoked])
        assert not hostkeys.check(self.hostname, self.host_key)

    def test_plain_host_key_flow_unchanged(self):
        plain = "{} ssh-rsa {}".format(
            self.hostname, self.host_key.get_base64()
        )
        hostkeys = self.load_hostkeys([self.ca_line(), plain])
        # Plain keys still verify exactly as before...
        assert hostkeys.check(self.hostname, self.host_key)
        # ...and CA entries are not handed out as host keys.
        assert self.ca_key.get_base64() not in [
            k.get_base64() for k in hostkeys[self.hostname].values()
        ]

    def test_non_certificate_key_rejected(self):
        hostkeys = self.load_hostkeys([self.ca_line()])
        assert not hostkeys.check_cert(self.hostname, self.host_key)

    def test_ed25519_certificate_accepted(self):
        host_key = Ed25519Key.from_private_key_file(_support("ed25519.key"))
        blob = make_ed25519_cert_blob(
            self.ca_key, host_key, [self.hostname]
        )
        cert = Ed25519Key(data=blob)
        hostkeys = self.load_hostkeys([self.ca_line()])
        assert hostkeys.check_cert(self.hostname, cert)

    def test_tampered_certificate_rejected(self):
        blob = bytearray(
            make_rsa_cert_blob(self.ca_key, self.host_key, [self.hostname])
        )
        # Flip a bit inside the signed region.
        blob[len(blob) // 2] ^= 0x01
        cert = PKey.from_type_string(
            "ssh-rsa-cert-v01@openssh.com", bytes(blob)
        )
        hostkeys = self.load_hostkeys([self.ca_line()])
        assert not hostkeys.check_cert(self.hostname, cert)

    def test_marker_roundtrip(self):
        line = self.ca_line()
        entry = HostKeyEntry.from_line(line)
        assert entry.marker == "@cert-authority"
        assert entry.to_line().strip() == line
        revoked = "@revoked {} ssh-rsa {}".format(
            self.hostname, self.host_key.get_base64()
        )
        entry = HostKeyEntry.from_line(revoked)
        assert entry.marker == "@revoked"
        assert entry.to_line().strip() == revoked

    def test_unknown_marker_ignored(self):
        entry = HostKeyEntry.from_line(
            "@banana {} ssh-rsa {}".format(
                self.hostname, self.host_key.get_base64()
            )
        )
        assert entry is None

    def test_parse_certificate_fields(self):
        cert = self.good_cert()
        info = parse_certificate(cert.public_blob.key_blob)
        assert info.key_type == "ssh-rsa-cert-v01@openssh.com"
        assert info.cert_type == CERT_TYPE_HOST
        assert info.principals == [self.hostname]
        assert info.valid_after == 0
        assert info.valid_before == UINT64_MAX
        assert info.critical_options == []
        assert info.signature_key == self.ca_key.asbytes()


class PortQualifiedHostnameTest(unittest.TestCase):
    def test_bracketed_port_hostname(self):
        ca_key = RSAKey.generate(2048)
        host_key = RSAKey.generate(2048)
        hostname = "cert.example.com"
        with tempfile.NamedTemporaryFile(
            "w", suffix=".known_hosts", delete=False
        ) as f:
            # OpenSSH stores nonstandard-port hosts as [host]:port.
            f.write(
                "@cert-authority [{}]:2222 ssh-rsa {}\n".format(
                    hostname, ca_key.get_base64()
                )
            )
            path = f.name
        self.addCleanup(os.unlink, path)
        hostkeys = HostKeys(path)
        cert = rsa_cert_key(ca_key, host_key, [hostname])
        assert hostkeys.check_cert("[{}]:2222".format(hostname), cert)
