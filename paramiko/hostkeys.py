# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.


import binascii
import os
import re
import time
from base64 import decodebytes, encodebytes
from collections.abc import MutableMapping
from hashlib import sha1
from hmac import HMAC

from paramiko.message import Message
from paramiko.pkey import PKey, UnknownKeyType
from paramiko.ssh_exception import SSHException
from paramiko.util import b, constant_time_bytes_eq, get_logger, u


# known_hosts line markers (see sshd(8) "SSH_KNOWN_HOSTS FILE FORMAT")
MARKER_CERT_AUTHORITY = "@cert-authority"
MARKER_REVOKED = "@revoked"
KNOWN_MARKERS = (MARKER_CERT_AUTHORITY, MARKER_REVOKED)

# OpenSSH certificate types (see PROTOCOL.certkeys)
CERT_TYPE_USER = 1
CERT_TYPE_HOST = 2

CERT_SUFFIX = "-cert-v01@openssh.com"

# Public key fields appearing between the nonce and the serial number in an
# OpenSSH certificate blob, per underlying (non-cert) key type.
_CERT_PUBLIC_FIELDS = {
    "ssh-rsa": ("mpint", "mpint"),
    "rsa-sha2-256": ("mpint", "mpint"),
    "rsa-sha2-512": ("mpint", "mpint"),
    "ssh-dss": ("mpint", "mpint", "mpint", "mpint"),
    "ssh-ed25519": ("string",),
    "ecdsa-sha2-nistp256": ("string", "string"),
    "ecdsa-sha2-nistp384": ("string", "string"),
    "ecdsa-sha2-nistp521": ("string", "string"),
}


class OpenSSHCertificate:
    """
    Parsed representation of an OpenSSH public key certificate blob, as
    described in PROTOCOL.certkeys. Only the fields needed for host
    certificate validation are interpreted.
    """

    def __init__(self):
        self.key_type = None
        self.serial = None
        self.cert_type = None
        self.key_id = None
        self.principals = []
        self.valid_after = 0
        self.valid_before = 0
        self.critical_options = {}
        self.extensions = {}
        self.signature_key = None
        self.signature = None
        # Raw bytes covered by the signature (everything up to, but not
        # including, the signature field itself).
        self.signed_data = None

    @classmethod
    def from_key(cls, key):
        """
        Parse the certificate attached to a `.PKey` (its ``public_blob``).

        :raises: `.SSHException` -- if the key does not carry a certificate
        """
        blob = getattr(key, "public_blob", None)
        if blob is None or not blob.key_type.endswith(CERT_SUFFIX):
            raise SSHException("Key does not contain an OpenSSH certificate")
        return cls.from_blob(blob.key_blob)

    @classmethod
    def from_blob(cls, blob):
        """
        Parse a raw certificate blob (as found in a ``*-cert-v01@openssh.com``
        public key).

        :raises: `.SSHException` -- if the blob is not a supported certificate
        """
        msg = Message(blob)
        cert = cls()
        cert.key_type = msg.get_text()
        if not cert.key_type.endswith(CERT_SUFFIX):
            raise SSHException(
                "Key blob is not an OpenSSH certificate: {}".format(
                    cert.key_type
                )
            )
        base_type = cert.key_type[: -len(CERT_SUFFIX)]
        if base_type not in _CERT_PUBLIC_FIELDS:
            raise SSHException(
                "Unsupported certificate key type: {}".format(cert.key_type)
            )
        msg.get_string()  # nonce
        for field_kind in _CERT_PUBLIC_FIELDS[base_type]:
            if field_kind == "mpint":
                msg.get_mpint()
            else:
                msg.get_string()
        cert.serial = msg.get_int64()
        cert.cert_type = msg.get_int()
        cert.key_id = msg.get_text()
        cert.principals = _read_name_list(msg.get_string())
        cert.valid_after = msg.get_int64()
        cert.valid_before = msg.get_int64()
        cert.critical_options = _read_options(msg.get_string())
        cert.extensions = _read_options(msg.get_string())
        msg.get_string()  # reserved
        cert.signature_key = msg.get_string()
        # Everything before the signature field is what the CA signed.
        cert.signed_data = msg.get_so_far()
        cert.signature = msg.get_string()
        return cert

    def is_valid_at(self, when):
        """
        Return True if ``when`` (a unix timestamp) falls within the
        certificate's validity interval.
        """
        return self.valid_after <= when <= self.valid_before


def _read_name_list(data):
    """
    Parse a packed sequence of SSH strings (e.g. the certificate principals
    field) into a list of text values.
    """
    names = []
    msg = Message(data)
    while msg.get_remainder():
        names.append(msg.get_text())
    return names


def _read_options(data):
    """
    Parse a packed sequence of SSH string pairs (name, data), as used by the
    certificate critical options and extensions fields, into a dict.
    """
    options = {}
    msg = Message(data)
    while msg.get_remainder():
        options[msg.get_text()] = msg.get_string()
    return options


class HostKeys(MutableMapping):
    """
    Representation of an OpenSSH-style "known hosts" file.  Host keys can be
    read from one or more files, and then individual hosts can be looked up to
    verify server keys during SSH negotiation.

    A `.HostKeys` object can be treated like a dict; any dict lookup is
    equivalent to calling `lookup`.

    .. versionadded:: 1.5.3
    """

    def __init__(self, filename=None):
        """
        Create a new HostKeys object, optionally loading keys from an OpenSSH
        style host-key file.

        :param str filename: filename to load host keys from, or ``None``
        """
        # emulate a dict of { hostname: { keytype: PKey } }
        self._entries = []
        if filename is not None:
            self.load(filename)

    def add(self, hostname, keytype, key):
        """
        Add a host key entry to the table.  Any existing entry for a
        ``(hostname, keytype)`` pair will be replaced.

        :param str hostname: the hostname (or IP) to add
        :param str keytype: key type (in ``"ssh-<type>"`` format)
        :param .PKey key: the key to add
        """
        for e in self._entries:
            if (hostname in e.hostnames) and (e.key.get_name() == keytype):
                e.key = key
                return
        self._entries.append(HostKeyEntry([hostname], key))

    def load(self, filename):
        """
        Read a file of known SSH host keys, in the format used by OpenSSH.
        This type of file unfortunately doesn't exist on Windows, but on
        posix, it will usually be stored in
        ``os.path.expanduser("~/.ssh/known_hosts")``.

        If this method is called multiple times, the host keys are merged,
        not cleared.  So multiple calls to `load` will just call `add`,
        replacing any existing entries and adding new ones.

        :param str filename: name of the file to read host keys from

        :raises: ``IOError`` -- if there was an error reading the file
        """
        with open(filename, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if (len(line) == 0) or (line[0] == "#"):
                    continue
                try:
                    entry = HostKeyEntry.from_line(line, lineno)
                except SSHException:
                    continue
                if entry is not None:
                    _hostnames = entry.hostnames
                    for h in _hostnames:
                        # Marked entries (@cert-authority, @revoked) are not
                        # regular host keys and are exempt from this dedup.
                        if entry.marker is None and self.check(h, entry.key):
                            entry.hostnames.remove(h)
                    if len(entry.hostnames):
                        self._entries.append(entry)

    def save(self, filename):
        """
        Save host keys into a file, in the format used by OpenSSH.  The order
        of keys in the file will be preserved when possible (if these keys were
        loaded from a file originally).  The single exception is that combined
        lines will be split into individual key lines, which is arguably a bug.

        :param str filename: name of the file to write

        :raises: ``IOError`` -- if there was an error writing the file

        .. versionadded:: 1.6.1
        """
        with open(filename, "w") as f:
            for e in self._entries:
                line = e.to_line()
                if line:
                    f.write(line)

    def lookup(self, hostname):
        """
        Find a hostkey entry for a given hostname or IP.  If no entry is found,
        ``None`` is returned.  Otherwise a dictionary of keytype to key is
        returned.

        :param str hostname: the hostname (or IP) to lookup
        :return: dict of `str` -> `.PKey` keys associated with this host
            (or ``None``)
        """

        class SubDict(MutableMapping):
            def __init__(self, hostname, entries, hostkeys):
                self._hostname = hostname
                self._entries = entries
                self._hostkeys = hostkeys

            def __iter__(self):
                for k in self.keys():
                    yield k

            def __len__(self):
                return len(self.keys())

            def __delitem__(self, key):
                for e in list(self._entries):
                    if e.key.get_name() == key:
                        self._entries.remove(e)
                        break
                else:
                    raise KeyError(key)

            def __getitem__(self, key):
                for e in self._entries:
                    if e.key.get_name() == key:
                        return e.key
                raise KeyError(key)

            def __setitem__(self, key, val):
                for e in self._entries:
                    if e.key is None:
                        continue
                    if e.key.get_name() == key:
                        # replace
                        e.key = val
                        break
                else:
                    # add a new one
                    e = HostKeyEntry([hostname], val)
                    self._entries.append(e)
                    self._hostkeys._entries.append(e)

            def keys(self):
                return [
                    e.key.get_name()
                    for e in self._entries
                    if e.key is not None
                ]

        entries = []
        for e in self._entries:
            # CA (@cert-authority) and revoked (@revoked) entries are not
            # host keys and must not be returned by a plain lookup.
            if e.marker is None and self._hostname_matches(hostname, e):
                entries.append(e)
        if len(entries) == 0:
            return None
        return SubDict(hostname, entries, self)

    def _hostname_matches(self, hostname, entry):
        """
        Tests whether ``hostname`` string matches given SubDict ``entry``.

        :returns bool:
        """
        for h in entry.hostnames:
            if (
                h == hostname
                or h.startswith("|1|")
                and not hostname.startswith("|1|")
                and constant_time_bytes_eq(self.hash_host(hostname, h), h)
            ):
                return True
        return False

    def check(self, hostname, key):
        """
        Return True if the given key is associated with the given hostname
        in this dictionary.

        If the given key is an OpenSSH host certificate, it is validated
        against any ``@cert-authority`` entries for the hostname instead:
        the certificate must be a host certificate, be within its validity
        period, cover the hostname in its principals, carry no unknown
        critical options, and be signed by a trusted CA key. ``@revoked``
        entries always take priority and cause this method to return
        ``False``.

        :param str hostname: hostname (or IP) of the SSH server
        :param .PKey key: the key to check
        :return:
            ``True`` if the key is associated with the hostname; else ``False``
        """
        if self._is_revoked(hostname, key):
            return False
        if self._is_certificate(key):
            return self._check_certificate(hostname, key)
        k = self.lookup(hostname)
        if k is None:
            return False
        host_key = k.get(key.get_name(), None)
        if host_key is None:
            return False
        return host_key.asbytes() == key.asbytes()

    @staticmethod
    def _is_certificate(key):
        blob = getattr(key, "public_blob", None)
        return blob is not None and blob.key_type.endswith(CERT_SUFFIX)

    def _is_revoked(self, hostname, key):
        """
        Return True if ``key`` has been revoked for ``hostname`` via a
        ``@revoked`` known_hosts entry.
        """
        for e in self._entries:
            if e.marker != MARKER_REVOKED:
                continue
            if not self._hostname_matches(hostname, e):
                continue
            if e.key.asbytes() == key.asbytes():
                return True
            # A certificate may also be revoked wholesale, by its full blob.
            revoked_blob = getattr(e.key, "public_blob", None)
            key_blob = getattr(key, "public_blob", None)
            if (
                revoked_blob is not None
                and key_blob is not None
                and revoked_blob.key_blob == key_blob.key_blob
            ):
                return True
        return False

    def _check_certificate(self, hostname, key):
        """
        Validate an OpenSSH host certificate against the ``@cert-authority``
        CA keys trusted for ``hostname``.
        """
        log = get_logger("paramiko.hostkeys")
        try:
            cert = OpenSSHCertificate.from_key(key)
        except SSHException as e:
            log.info("Unable to parse host certificate: {}".format(e))
            return False
        # Only host certificates are acceptable here; a user certificate
        # must never be treated as proof of a server's identity.
        if cert.cert_type != CERT_TYPE_HOST:
            log.info(
                "Rejecting non-host certificate (type {})".format(
                    cert.cert_type
                )
            )
            return False
        if not cert.is_valid_at(time.time()):
            log.info("Host certificate is expired or not yet valid")
            return False
        # Host certificates are matched by hostname only; strip any
        # "[host]:port" decoration before comparing with principals.
        principal = hostname
        m = re.match(r"^\[(.*)\]:\d+$", hostname)
        if m:
            principal = m.group(1)
        if cert.principals and principal not in cert.principals:
            log.info(
                "Hostname {!r} not in certificate principals {!r}".format(
                    principal, cert.principals
                )
            )
            return False
        # No critical options are defined for host certificates; any
        # critical option we don't recognize must sink the certificate.
        if cert.critical_options:
            log.info(
                "Host certificate carries unknown critical "
                "options: {!r}".format(sorted(cert.critical_options))
            )
            return False
        for e in self._entries:
            if e.marker != MARKER_CERT_AUTHORITY:
                continue
            if not self._hostname_matches(hostname, e):
                continue
            ca_key = e.key
            # The CA key in known_hosts must be the one named by the
            # certificate's signature-key field.
            if ca_key.asbytes() != cert.signature_key:
                continue
            if ca_key.verify_ssh_sig(
                cert.signed_data, Message(cert.signature)
            ):
                return True
        log.info("No trusted CA key validated the host certificate")
        return False

    def clear(self):
        """
        Remove all host keys from the dictionary.
        """
        self._entries = []

    def __iter__(self):
        for k in self.keys():
            yield k

    def __len__(self):
        return len(self.keys())

    def __getitem__(self, key):
        ret = self.lookup(key)
        if ret is None:
            raise KeyError(key)
        return ret

    def __delitem__(self, key):
        index = None
        for i, entry in enumerate(self._entries):
            if self._hostname_matches(key, entry):
                index = i
                break
        if index is None:
            raise KeyError(key)
        self._entries.pop(index)

    def __setitem__(self, hostname, entry):
        # don't use this please.
        if len(entry) == 0:
            self._entries.append(HostKeyEntry([hostname], None))
            return
        for key_type in entry.keys():
            found = False
            for e in self._entries:
                if (hostname in e.hostnames) and e.key.get_name() == key_type:
                    # replace
                    e.key = entry[key_type]
                    found = True
            if not found:
                self._entries.append(HostKeyEntry([hostname], entry[key_type]))

    def keys(self):
        ret = []
        for e in self._entries:
            for h in e.hostnames:
                if h not in ret:
                    ret.append(h)
        return ret

    def values(self):
        ret = []
        for k in self.keys():
            ret.append(self.lookup(k))
        return ret

    @staticmethod
    def hash_host(hostname, salt=None):
        """
        Return a "hashed" form of the hostname, as used by OpenSSH when storing
        hashed hostnames in the known_hosts file.

        :param str hostname: the hostname to hash
        :param str salt: optional salt to use when hashing
            (must be 20 bytes long)
        :return: the hashed hostname as a `str`
        """
        if salt is None:
            salt = os.urandom(sha1().digest_size)
        else:
            if salt.startswith("|1|"):
                salt = salt.split("|")[2]
            salt = decodebytes(b(salt))
        assert len(salt) == sha1().digest_size
        hmac = HMAC(salt, b(hostname), sha1).digest()
        hostkey = "|1|{}|{}".format(u(encodebytes(salt)), u(encodebytes(hmac)))
        return hostkey.replace("\n", "")


class InvalidHostKey(Exception):
    def __init__(self, line, exc):
        self.line = line
        self.exc = exc
        self.args = (line, exc)


class HostKeyEntry:
    """
    Representation of a line in an OpenSSH-style "known hosts" file.
    """

    def __init__(self, hostnames=None, key=None, marker=None):
        self.valid = (hostnames is not None) and (key is not None)
        self.hostnames = hostnames
        self.key = key
        self.marker = marker

    @classmethod
    def from_line(cls, line, lineno=None):
        """
        Parses the given line of text to find the names for the host,
        the type of key, and the key data. The line is expected to be in the
        format used by the OpenSSH known_hosts file. Fields are separated by a
        single space or tab.

        Lines are expected to not have leading or trailing whitespace.
        We don't bother to check for comments or empty lines.  All of
        that should be taken care of before sending the line to us.

        :param str line: a line from an OpenSSH known_hosts file
        """
        log = get_logger("paramiko.hostkeys")
        fields = re.split(" |\t", line)
        # Lines may be prefixed with a marker such as @cert-authority or
        # @revoked; unrecognized markers cause the line to be skipped, as
        # OpenSSH does.
        marker = None
        if fields[0].startswith("@"):
            marker = fields.pop(0)
            if marker not in KNOWN_MARKERS:
                log.info(
                    "Skipping known_hosts line {} with unknown "
                    "marker {!r}".format(lineno, marker)
                )
                return None
        if len(fields) < 3:
            # Bad number of fields
            msg = "Not enough fields found in known_hosts in line {} ({!r})"
            log.info(msg.format(lineno, line))
            return None
        fields = fields[:3]

        names, key_type, key = fields
        names = names.split(",")

        # Decide what kind of key we're looking at and create an object
        # to hold it accordingly.
        try:
            # TODO: this grew organically and doesn't seem /wrong/ per se (file
            # read -> unicode str -> bytes for base64 decode -> decoded bytes);
            # but in Python 3 forever land, can we simply use
            # `base64.b64decode(str-from-file)` here?
            key_bytes = decodebytes(b(key))
        except binascii.Error as e:
            raise InvalidHostKey(line, e)

        try:
            return cls(
                names,
                PKey.from_type_string(key_type, key_bytes),
                marker=marker,
            )
        except UnknownKeyType:
            # TODO (backwards incompat): consider changing HostKeys API so this
            # just raises naturally and the exception is muted higher up in the
            # stack?
            log.info("Unable to handle key of type {}".format(key_type))
            return None

    def to_line(self):
        """
        Returns a string in OpenSSH known_hosts file format, or None if
        the object is not in a valid state.  A trailing newline is
        included.
        """
        if self.valid:
            marker = "{} ".format(self.marker) if self.marker else ""
            return "{}{} {} {}\n".format(
                marker,
                ",".join(self.hostnames),
                self.key.get_name(),
                self.key.get_base64(),
            )
        return None

    def __repr__(self):
        return "<HostKeyEntry {!r}: {!r}>".format(self.hostnames, self.key)
