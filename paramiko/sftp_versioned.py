# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
# more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Reference implementation of a local-filesystem SFTP server supporting
conditional (compare-and-swap) writes.

`.VersionedSFTPServer` backs the ``get-file-version@paramiko`` and
``conditional-commit@paramiko`` vendor extensions: every file has a
server-generated, opaque version tag, and a temp file is committed onto its
target only if the target's version still matches the tag the client based
its edit on.  The version check and the atomic replace happen under a single
lock, so the target is always observed as a complete file and a concurrent
writer is never silently overwritten.
"""

import os
import threading

from paramiko.common import o666
from paramiko.sftp import (
    SFTP_FAILURE,
    SFTP_NO_SUCH_FILE,
    SFTP_OK,
    SFTP_PERMISSION_DENIED,
    FileVersionConflict,
)
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle
from paramiko.sftp_server import SFTPServer
from paramiko.sftp_si import SFTPServerInterface


class VersionedSFTPHandle(SFTPHandle):
    def stat(self):
        try:
            return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def chattr(self, attr):
        try:
            SFTPServer.set_file_attr(self.filename, attr)
            return SFTP_OK
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)


class VersionedSFTPServer(SFTPServerInterface):
    """
    A local-filesystem `.SFTPServerInterface` with conditional-write support.

    Version tags are shared by all sessions of a server class (they are
    process-global, keyed by real path), so concurrent clients observe a
    consistent view of each file's version.

    :param root: local directory to serve as the SFTP root.
    """

    # shared across sessions, so that two clients connected to the same
    # server see the same version tags
    _version_lock = threading.Lock()
    _versions = {}
    _version_counter = 0

    def __init__(self, server, root=None, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.ROOT = root if root is not None else os.getcwd()

    @classmethod
    def reset_version_tracking(cls):
        """
        Forget all known version tags (mostly useful for tests).
        """
        with cls._version_lock:
            cls._versions = {}
            cls._version_counter = 0

    @classmethod
    def _next_version(cls):
        cls._version_counter += 1
        return "v{:d}".format(cls._version_counter)

    @classmethod
    def _bump(cls, realpath):
        # assign & return a fresh version tag; caller must hold the lock
        version = cls._next_version()
        cls._versions[realpath] = version
        return version

    @classmethod
    def _current_version(cls, realpath):
        # caller must hold the lock
        version = cls._versions.get(realpath)
        if version is None and os.path.exists(realpath):
            # first time we see this pre-existing file: start tracking it
            version = cls._bump(realpath)
        return version

    def _realpath(self, path):
        return self.ROOT + self.canonicalize(path)

    # --- conditional-write extension -------------------------------

    def get_file_version(self, path):
        path = self._realpath(path)
        with self._version_lock:
            if not os.path.exists(path):
                return SFTP_NO_SUCH_FILE
            return self._current_version(path)

    def conditional_commit(self, tmp_path, target_path, expected_version):
        tmp_path = self._realpath(tmp_path)
        target_path = self._realpath(target_path)
        with self._version_lock:
            current = self._current_version(target_path)
            if current is None:
                # target does not exist; only an expected version of "0"
                # ("must not exist yet") may commit
                current = "0"
            if current != expected_version:
                return FileVersionConflict(
                    "expected {!r}, current is {!r} for {!r}".format(
                        expected_version, current, target_path
                    )
                )
            try:
                # atomic replace: readers only ever see the old or the new
                # complete file, never a partial one
                os.replace(tmp_path, target_path)
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            return self._bump(target_path)

    # --- regular file operations ------------------------------------

    def list_folder(self, path):
        path = self._realpath(path)
        try:
            out = []
            for fname in os.listdir(path):
                attr = SFTPAttributes.from_stat(
                    os.stat(os.path.join(path, fname))
                )
                attr.filename = fname
                out.append(attr)
            return out
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        path = self._realpath(path)
        try:
            return SFTPAttributes.from_stat(os.stat(path))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        path = self._realpath(path)
        try:
            return SFTPAttributes.from_stat(os.lstat(path))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        path = self._realpath(path)
        try:
            binary_flag = getattr(os, "O_BINARY", 0)
            flags |= binary_flag
            mode = getattr(attr, "st_mode", None)
            if mode is not None:
                fd = os.open(path, flags, mode)
            else:
                # os.open() defaults to 0777 which is
                # an odd default mode for files
                fd = os.open(path, flags, o666)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        if (flags & os.O_CREAT) and (attr is not None):
            attr._flags &= ~attr.FLAG_PERMISSIONS
            SFTPServer.set_file_attr(path, attr)
        if flags & os.O_WRONLY:
            if flags & os.O_APPEND:
                fstr = "ab"
            else:
                fstr = "wb"
        elif flags & os.O_RDWR:
            if flags & os.O_APPEND:
                fstr = "a+b"
            else:
                fstr = "r+b"
        else:
            # O_RDONLY (== 0)
            fstr = "rb"
        try:
            f = os.fdopen(fd, fstr)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        # a write-mode open may change the contents, so it must invalidate
        # any version tag clients may have fetched
        if flags & (os.O_WRONLY | os.O_RDWR) and not flags & os.O_APPEND:
            with self._version_lock:
                self._bump(path)
        fobj = VersionedSFTPHandle(flags)
        fobj.filename = path
        fobj.readfile = f
        fobj.writefile = f
        return fobj

    def remove(self, path):
        path = self._realpath(path)
        try:
            os.remove(path)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        with self._version_lock:
            self._versions.pop(path, None)
        return SFTP_OK

    def rename(self, oldpath, newpath):
        oldpath = self._realpath(oldpath)
        newpath = self._realpath(newpath)
        if os.path.exists(newpath):
            return SFTP_FAILURE
        try:
            os.rename(oldpath, newpath)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        with self._version_lock:
            self._versions.pop(oldpath, None)
            self._bump(newpath)
        return SFTP_OK

    def posix_rename(self, oldpath, newpath):
        oldpath = self._realpath(oldpath)
        newpath = self._realpath(newpath)
        try:
            os.rename(oldpath, newpath)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        with self._version_lock:
            self._versions.pop(oldpath, None)
            self._bump(newpath)
        return SFTP_OK

    def mkdir(self, path, attr):
        path = self._realpath(path)
        try:
            os.mkdir(path)
            if attr is not None:
                SFTPServer.set_file_attr(path, attr)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def rmdir(self, path):
        path = self._realpath(path)
        try:
            os.rmdir(path)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def chattr(self, path, attr):
        path = self._realpath(path)
        try:
            SFTPServer.set_file_attr(path, attr)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def symlink(self, target_path, path):
        path = self._realpath(path)
        if (len(target_path) > 0) and (target_path[0] == "/"):
            # absolute symlink
            return SFTP_PERMISSION_DENIED
        try:
            os.symlink(target_path, path)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def readlink(self, path):
        path = self._realpath(path)
        try:
            symlink = os.readlink(path)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        # if it's absolute, remove the root
        if os.path.isabs(symlink):
            if symlink[: len(self.ROOT)] != self.ROOT:
                return SFTP_NO_SUCH_FILE
            symlink = symlink[len(self.ROOT):]
        return symlink
