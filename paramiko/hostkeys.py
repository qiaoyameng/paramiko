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
import struct
import time
from base64 import decodebytes, encodebytes
from collections.abc import MutableMapping
from hashlib import sha1
from hmac import HMAC

from paramiko.message import Message
from paramiko.pkey import PKey, UnknownKeyType
from paramiko.ssh_exception import SSHException
from paramiko.util import b, constant_time_bytes_eq, get_logger, u


# OpenSSH certificate types (see PROTOCOL.certkeys)
CERT_TYPE_USER = 1
CERT_TYPE_HOST = 2

CERT_SUFFIX = "-cert-v01@openssh.com"


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
                    # Marker entries (@cert-authority, @revoked) are not
                    # interchangeable with plain host-key entries, so they
                    # are never deduplicated against existing entries.
                    if entry.marker is None:
                        _hostnames = entry.hostnames
                        for h in _hostnames:
                            if self.check(h, entry.key):
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
            # CA (@cert-authority) and @revoked entries are not host keys
            # and must never be handed out as such.
            if e.marker is not None:
                continue
            if self._hostname_matches(hostname, e):
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

        :param str hostname: hostname (or IP) of the SSH server
        :param .PKey key: the key to check
        :return:
            ``True`` if the key is associated with the hostname; else ``False``
        """
        # Revoked keys are never acceptable, no matter what else matches.
        if self.is_revoked(key):
            return False
        k = self.lookup(hostname)
        if k is None:
            return False
        host_key = k.get(key.get_name(), None)
        if host_key is None:
            return False
        return host_key.asbytes() == key.asbytes()

    def is_revoked(self, key):
        """
        Return True if the given key appears in any ``@revoked`` entry.

        Revoked entries apply to all hosts, regardless of the hostnames
        stored on the entry line (matching OpenSSH behavior).

        :param .PKey key: the key to check
        :return: ``True`` if the key has been revoked; else ``False``

        .. versionadded:: 4.1
        """
        return self._blob_is_revoked(key.asbytes())

    def _blob_is_revoked(self, blob):
        for e in self._entries:
            if e.marker == HostKeyEntry.MARKER_REVOKED and e.key is not None:
                if e.key.asbytes() == blob:
                    return True
        return False

    def check_cert(self, hostname, key):
        """
        Return True if the given host certificate is valid for the given
        hostname and was signed by a CA trusted via a ``@cert-authority``
        entry in this dictionary.

        The certificate's type, validity window, principals, critical
        options and CA signature are all verified, and ``@revoked`` entries
        take precedence over any trust anchor. User certificates are never
        accepted as host certificates.

        :param str hostname: hostname (or IP) of the SSH server, in the same
            form used for `lookup` (i.e. ``[host]:port`` for nonstandard
            ports)
        :param .PKey key: the certificate-bearing key presented by the server
        :return: ``True`` if the certificate is valid and trusted

        .. versionadded:: 4.1
        """
        try:
            self._verify_host_certificate(hostname, key)
        except SSHException as e:
            log = get_logger("paramiko.hostkeys")
            log.info(
                "Host certificate rejected for {}: {}".format(hostname, e)
            )
            return False
        return True

    def _verify_host_certificate(self, hostname, key):
        public_blob = getattr(key, "public_blob", None)
        if public_blob is None or not public_blob.key_type.endswith(
            CERT_SUFFIX
        ):
            raise SSHException("Key is not an OpenSSH certificate")
        cert = parse_certificate(public_blob.key_blob)
        # Revocation trumps everything else: check both the certified key
        # and the CA key before doing any further work.
        if self._blob_is_revoked(key.asbytes()):
            raise SSHException("Certificate's key has been revoked")
        if self._blob_is_revoked(cert.signature_key):
            raise SSHException("Certificate's CA key has been revoked")
        # Only host certificates may authenticate a server; user certs are
        # not valid here no matter who signed them.
        if cert.cert_type != CERT_TYPE_HOST:
            raise SSHException(
                "Certificate is not a host certificate "
                "(type {})".format(cert.cert_type)
            )
        now = int(time.time())
        if not (cert.valid_after <= now <= cert.valid_before):
            raise SSHException(
                "Certificate is not valid at the current time "
                "(valid {} to {}, now {})".format(
                    cert.valid_after, cert.valid_before, now
                )
            )
        # Host certificates must name the host being connected to. Strip
        # any "[host]:port" wrapper first; principals never carry ports.
        principal_host = hostname
        m = re.match(r"^\[(.*)\]:\d+$", hostname)
        if m is not None:
            principal_host = m.group(1)
        if not cert.principals:
            raise SSHException("Host certificate has no principals")
        if principal_host not in cert.principals:
            raise SSHException(
                "Hostname {!r} is not a principal of the "
                "certificate".format(principal_host)
            )
        # No critical options are defined for host certificates, so any
        # present option is, by definition, unrecognized.
        if cert.critical_options:
            raise SSHException(
                "Certificate has unrecognized critical options: "
                + ", ".join(cert.critical_options)
            )
        # Finally, the signature must come from a CA we trust for this host.
        for e in self._entries:
            if e.marker != HostKeyEntry.MARKER_CA or e.key is None:
                continue
            if not self._hostname_matches(hostname, e):
                continue
            if e.key.asbytes() != cert.signature_key:
                continue
            if e.key.verify_ssh_sig(
                cert.signed_data, Message(cert.signature)
            ):
                return
        raise SSHException(
            "Host certificate was not signed by a trusted CA"
        )

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

    #: known_hosts marker designating a certificate-authority key
    MARKER_CA = "@cert-authority"
    #: known_hosts marker designating a revoked key
    MARKER_REVOKED = "@revoked"
    #: all recognized line markers
    VALID_MARKERS = (MARKER_CA, MARKER_REVOKED)

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

        Lines may begin with a marker such as ``@cert-authority`` (the key
        is a CA trusted to sign host certificates for the given hosts) or
        ``@revoked`` (the key must never be accepted).

        Lines are expected to not have leading or trailing whitespace.
        We don't bother to check for comments or empty lines.  All of
        that should be taken care of before sending the line to us.

        :param str line: a line from an OpenSSH known_hosts file
        """
        log = get_logger("paramiko.hostkeys")
        fields = re.split(" |\t", line)
        marker = None
        if fields and fields[0].startswith("@"):
            marker = fields.pop(0)
            if marker not in cls.VALID_MARKERS:
                log.info(
                    "Ignoring known_hosts line {} with unknown "
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
            marker = ""
            if self.marker is not None:
                marker = self.marker + " "
            return "{}{} {} {}\n".format(
                marker,
                ",".join(self.hostnames),
                self.key.get_name(),
                self.key.get_base64(),
            )
        return None

    def __repr__(self):
        return "<HostKeyEntry {!r}: {!r}>".format(self.hostnames, self.key)


class CertificateInfo:
    """
    Parsed contents of an OpenSSH certificate (see PROTOCOL.certkeys).

    Only the fields needed for host certificate verification are exposed.

    .. versionadded:: 4.1
    """

    def __init__(
        self,
        key_type,
        serial,
        cert_type,
        key_id,
        principals,
        valid_after,
        valid_before,
        critical_options,
        signature_key,
        signature,
        signed_data,
    ):
        #: certificate key type, e.g. ``ssh-rsa-cert-v01@openssh.com``
        self.key_type = key_type
        #: serial number
        self.serial = serial
        #: `CERT_TYPE_USER` or `CERT_TYPE_HOST`
        self.cert_type = cert_type
        #: free-form key ID
        self.key_id = key_id
        #: list of valid principal names
        self.principals = principals
        #: start of validity window (seconds since epoch)
        self.valid_after = valid_after
        #: end of validity window (seconds since epoch)
        self.valid_before = valid_before
        #: list of critical option names
        self.critical_options = critical_options
        #: raw bytes of the signing (CA) public key
        self.signature_key = signature_key
        #: raw bytes of the signature field
        self.signature = signature
        #: the bytes covered by the signature (everything up to it)
        self.signed_data = signed_data


def _read_string_list(blob):
    """
    Parse a packed sequence of SSH strings (as used for certificate
    principals) into a list of text values.
    """
    values = []
    m = Message(blob)
    while m.packet.tell() < len(blob):
        values.append(m.get_text())
    return values


def _read_name_data_pairs(blob):
    """
    Parse a packed sequence of name/data string pairs (as used for
    certificate critical options and extensions), returning the names.
    """
    names = []
    m = Message(blob)
    while m.packet.tell() < len(blob):
        names.append(m.get_text())
        m.get_string()  # option data; not interpreted
    return names


def parse_certificate(blob):
    """
    Parse an OpenSSH certificate blob into a `.CertificateInfo`.

    :param bytes blob: the raw certificate (as found in a ``-cert.pub``
        file's base64 payload or on the wire)
    :raises: `.SSHException` -- if the blob is not a well-formed certificate

    .. versionadded:: 4.1
    """
    try:
        m = Message(blob)
        key_type = m.get_text()
        if not key_type.endswith(CERT_SUFFIX):
            raise SSHException(
                "Not an OpenSSH certificate: {!r}".format(key_type)
            )
        m.get_string()  # nonce
        # Skip the certified public key's numbers; how many there are
        # depends on the key type.
        base_type = key_type[: -len(CERT_SUFFIX)]
        if base_type in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
            m.get_mpint()  # e
            m.get_mpint()  # n
        elif base_type == "ssh-dss":
            for _ in range(4):
                m.get_mpint()  # p, q, g, y
        elif base_type.startswith("ecdsa-sha2-"):
            m.get_string()  # curve name
            m.get_string()  # public point
        elif base_type == "ssh-ed25519":
            m.get_string()  # public key
        else:
            raise SSHException(
                "Unsupported certificate key type: {!r}".format(key_type)
            )
        serial = m.get_int64()
        cert_type = m.get_int()
        key_id = m.get_text()
        principals = _read_string_list(m.get_string())
        valid_after = m.get_int64()
        valid_before = m.get_int64()
        critical_options = _read_name_data_pairs(m.get_string())
        m.get_string()  # extensions; none are defined for host certs
        m.get_string()  # reserved
        signature_key = m.get_string()
        # The signature covers everything up to (not including) itself.
        signed_data = blob[: m.packet.tell()]
        signature = m.get_string()
    except SSHException:
        raise
    except (struct.error, IndexError, UnicodeDecodeError) as e:
        raise SSHException("Unparseable certificate: {}".format(e))
    return CertificateInfo(
        key_type=key_type,
        serial=serial,
        cert_type=cert_type,
        key_id=key_id,
        principals=principals,
        valid_after=valid_after,
        valid_before=valid_before,
        critical_options=critical_options,
        signature_key=signature_key,
        signature=signature,
        signed_data=signed_data,
    )
