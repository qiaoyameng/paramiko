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
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
SFTP file object
"""


from binascii import hexlify
from collections import deque
import socket
import threading
import time
from paramiko.common import DEBUG, io_sleep

from paramiko.file import BufferedFile
from paramiko.util import u
from paramiko.sftp import (
    CMD_CLOSE,
    CMD_READ,
    CMD_DATA,
    SFTPError,
    CMD_WRITE,
    CMD_STATUS,
    CMD_FSTAT,
    CMD_ATTRS,
    CMD_FSETSTAT,
    CMD_EXTENDED,
    int64,
)
from paramiko.sftp_attr import SFTPAttributes


class SFTPFile(BufferedFile):
    """
    Proxy object for a file on the remote server, in client mode SFTP.

    Instances of this class may be used as context managers in the same way
    that built-in Python file objects are.
    """

    # Some sftp servers will choke if you send read/write requests larger than
    # this size.
    MAX_REQUEST_SIZE = 32768

    def __init__(self, sftp, handle, mode="r", bufsize=-1):
        BufferedFile.__init__(self)
        self.sftp = sftp
        self.handle = handle
        BufferedFile._set_mode(self, mode, bufsize)
        self.pipelined = False
        self._prefetching = False
        self._prefetch_done = False
        self._prefetch_data = {}
        self._prefetch_extents = {}
        self._prefetch_lock = threading.Lock()
        self._prefetch_condition = threading.Condition(self._prefetch_lock)
        self._prefetch_pending = deque()
        self._prefetch_ranges = None
        self._prefetch_cached_bytes = 0
        self._prefetch_peak_cached_bytes = 0
        self._prefetch_byte_budget = None
        self._prefetch_generation = 0
        self._prefetch_active = False
        self._prefetch_thread_handle = None
        self._prefetch_closing = False
        self._prefetch_mode = None
        self._prefetch_waiting_offset = None
        self._prefetch_max_concurrent_requests = None
        self._saved_exception = None
        self._reqs = deque()

    def __del__(self):
        self._close(async_=True)

    def close(self):
        """
        Close the file.
        """
        self._close(async_=False)

    def _close(self, async_=False):
        # We allow double-close without signaling an error, because real
        # Python file objects do.  However, we must protect against actually
        # sending multiple CMD_CLOSE packets, because after we close our
        # handle, the same handle may be re-allocated by the server, and we
        # may end up mysteriously closing some random other file.  (This is
        # especially important because we unconditionally call close() from
        # __del__.)
        if self._closed:
            return
        self.sftp._log(DEBUG, "close({})".format(u(hexlify(self.handle))))
        if self.pipelined:
            self.sftp._finish_responses(self)
        thread = None
        with self._prefetch_condition:
            self._prefetch_closing = True
            self._prefetch_active = False
            self._prefetch_pending.clear()
            self._prefetch_generation += 1
            self._prefetch_condition.notify_all()
            thread = self._prefetch_thread_handle
        if thread is not None and thread is not threading.current_thread():
            thread.join()
        exception = None
        if not async_:
            try:
                self.sftp._finish_responses(self)
                self._check_exception()
            except Exception as e:
                exception = e
        BufferedFile.close(self)
        try:
            if async_:
                # GC'd file handle could be called from an arbitrary thread
                # -- don't wait for a response
                self.sftp._async_request(type(None), CMD_CLOSE, self.handle)
            else:
                self.sftp._request(CMD_CLOSE, self.handle)
        except EOFError:
            # may have outlived the Transport connection
            pass
        except (IOError, socket.error):
            # may have outlived the Transport connection
            pass
        if exception is not None:
            raise exception

    def _data_in_prefetch_requests(self, offset, size):
        with self._prefetch_condition:
            intervals = [
                (request_offset, request_offset + length)
                for request_offset, length, *_ in (
                    list(self._prefetch_extents.values())
                    + list(self._prefetch_pending)
                )
            ]

            def covered(start, end):
                candidates = [
                    interval_end
                    for interval_start, interval_end in intervals
                    if interval_start <= start < interval_end
                ]
                if not candidates:
                    return False
                next_end = max(candidates)
                return next_end >= end or covered(next_end, end)

            return covered(offset, offset + size)

    def _data_in_prefetch_buffers(self, offset):
        """
        if a block of data is present in the prefetch buffers, at the given
        offset, return the offset of the relevant prefetch buffer.  otherwise,
        return None.  this guarantees nothing about the number of bytes
        collected in the prefetch buffer so far.
        """
        with self._prefetch_condition:
            return self._data_in_prefetch_buffers_locked(offset)

    def _data_in_prefetch_buffers_locked(self, offset):
        keys = [i for i in self._prefetch_data.keys() if i <= offset]
        if not keys:
            return None
        index = max(keys)
        if offset - index >= len(self._prefetch_data[index]):
            return None
        return index

    def _add_prefetch_data_locked(self, offset, data):
        old_data = self._prefetch_data.get(offset, b"")
        self._prefetch_cached_bytes += len(data) - len(old_data)
        self._prefetch_data[offset] = data
        self._prefetch_peak_cached_bytes = max(
            self._prefetch_peak_cached_bytes,
            self._prefetch_cached_bytes,
        )

    def _remove_prefetch_data_locked(self, offset):
        data = self._prefetch_data.pop(offset, b"")
        self._prefetch_cached_bytes -= len(data)
        return data

    @staticmethod
    def _merge_ranges(ranges):
        ranges = sorted(
            (start, end) for start, end in ranges if start < end
        )
        merged = []
        for start, end in ranges:
            if not merged or start >= merged[-1][1]:
                merged.append([start, end])
            else:
                merged[-1][1] = max(merged[-1][1], end)
        return [(start, end) for start, end in merged]

    @classmethod
    def _range_intersects(cls, ranges, start, end):
        return any(
            start < range_end and range_start < end
            for range_start, range_end in ranges
        )

    @classmethod
    def _subtract_range(cls, ranges, start, end):
        result = []
        for range_start, range_end in ranges:
            if end <= range_start or start >= range_end:
                result.append((range_start, range_end))
            else:
                if range_start < start:
                    result.append((range_start, start))
                if end < range_end:
                    result.append((end, range_end))
        return result

    def _discard_unwanted_prefetch_data_locked(self):
        ranges = self._prefetch_ranges or []
        for data_offset in list(self._prefetch_data):
            data = self._prefetch_data[data_offset]
            data_end = data_offset + len(data)
            kept = None
            for range_start, range_end in ranges:
                if data_offset < range_end and range_start < data_end:
                    kept = (
                        max(data_offset, range_start),
                        min(data_end, range_end),
                    )
                    break
            if kept is None:
                self._remove_prefetch_data_locked(data_offset)
            elif kept != (data_offset, data_end):
                start, end = kept
                trimmed = data[start - data_offset : end - data_offset]
                self._remove_prefetch_data_locked(data_offset)
                self._add_prefetch_data_locked(start, trimmed)

    def _coverage_end_locked(self, offset, exclude_pending=False):
        candidates = []
        for data_offset, data in self._prefetch_data.items():
            data_end = data_offset + len(data)
            if data_offset <= offset < data_end:
                candidates.append(data_end)
        requests = list(self._prefetch_extents.values())
        if not exclude_pending:
            requests += list(self._prefetch_pending)
        for request_offset, length, *_ in requests:
            request_end = request_offset + length
            if request_offset <= offset < request_end:
                candidates.append(request_end)
        return max(candidates, default=offset)

    def _add_missing_prefetch_chunks_locked(self, position):
        if self._prefetch_mode != "sequential" or not self._prefetch_ranges:
            return
        end = self._prefetch_ranges[-1][1]
        missing = []
        offset = position
        while offset < end:
            coverage_end = self._coverage_end_locked(offset)
            if coverage_end > offset:
                offset = coverage_end
                continue
            length = min(self.MAX_REQUEST_SIZE, end - offset)
            missing.append((offset, length))
            offset += length
        if not missing:
            return
        missing_keys = set(missing)
        retained = deque(
            chunk
            for chunk in self._prefetch_pending
            if (chunk[0], chunk[1]) not in missing_keys
        )
        generation = self._prefetch_generation
        self._prefetch_pending = deque(
            (offset, length, generation) for offset, length in missing
        )
        self._prefetch_pending.extend(retained)

    def _update_sequential_demand_locked(self, position):
        if self._prefetch_mode != "sequential":
            return
        end = self._prefetch_ranges[-1][1] if self._prefetch_ranges else 0
        if position >= end:
            self._prefetch_ranges = []
        else:
            self._prefetch_ranges = self._merge_ranges([(position, end)])
        generation = self._prefetch_generation
        self._prefetch_pending = deque(
            chunk
            for chunk in self._prefetch_pending
            if chunk[2] == generation
            and self._range_intersects(
                self._prefetch_ranges, chunk[0], chunk[0] + chunk[1]
            )
        )
        self._discard_unwanted_prefetch_data_locked()
        self._add_missing_prefetch_chunks_locked(position)

    def _seek_prefetch(self, position):
        with self._prefetch_condition:
            self._prefetch_waiting_offset = position
            if self._prefetch_mode == "sequential":
                self._prefetch_done = False
                self._update_sequential_demand_locked(position)
            else:
                for index, chunk in enumerate(self._prefetch_pending):
                    chunk_offset, chunk_length, _ = chunk
                    if (
                        chunk_offset <= position
                        < chunk_offset + chunk_length
                    ):
                        self._prefetch_pending.rotate(-index)
                        break
            self._prefetch_condition.notify_all()

    def cancel_prefetch(self):
        """
        Cancel prefetch requests which have not been sent yet.

        Data already received remains readable. Responses for requests already
        in flight are consumed and discarded instead of being mistaken for
        another request's response.
        """
        thread = None
        with self._prefetch_condition:
            self._prefetch_generation += 1
            self._prefetch_active = False
            self._prefetch_pending.clear()
            self._prefetch_ranges = []
            self._prefetch_mode = None
            self._prefetch_done = True
            self._prefetch_closing = False
            self._prefetch_condition.notify_all()
            thread = self._prefetch_thread_handle
        if thread is not None and thread is not threading.current_thread():
            thread.join()

    def _read_prefetch(self, size):
        """
        read data out of the prefetch buffer, if possible.  if the data isn't
        in the buffer, return None.  otherwise, behaves like a normal read.
        """
        # while not closed, and haven't fetched past the current position,
        # and haven't reached EOF...
        while True:
            with self._prefetch_condition:
                self._prefetch_waiting_offset = self._realpos
                offset = self._data_in_prefetch_buffers_locked(
                    self._realpos
                )
                done = self._prefetch_done or self._closed
                exception = self._saved_exception is not None
                should_notify = offset is None
                if should_notify:
                    self._prefetch_condition.notify_all()
            if offset is not None or done or exception:
                break
            self.sftp._read_response()
            self._check_exception()
        with self._prefetch_condition:
            if offset is None:
                if self._prefetch_done:
                    self._prefetching = False
                return None
            start = self._realpos
            prefetch = self._remove_prefetch_data_locked(offset)
            prefetch = prefetch[start - offset :]
            if size < len(prefetch):
                self._add_prefetch_data_locked(
                    start + size, prefetch[size:]
                )
                prefetch = prefetch[:size]
            self._prefetch_ranges = self._subtract_range(
                self._prefetch_ranges, start, start + len(prefetch)
            )
            self._discard_unwanted_prefetch_data_locked()
            self._prefetch_condition.notify_all()
        return prefetch

    def _read(self, size):
        size = min(size, self.MAX_REQUEST_SIZE)
        if self._prefetching:
            data = self._read_prefetch(size)
            if data is not None:
                return data
        t, msg = self.sftp._request(
            CMD_READ, self.handle, int64(self._realpos), int(size)
        )
        if t != CMD_DATA:
            raise SFTPError("Expected data")
        return msg.get_string()

    def _write(self, data):
        # may write less than requested if it would exceed max packet size
        chunk = min(len(data), self.MAX_REQUEST_SIZE)
        sftp_async_request = self.sftp._async_request(
            type(None),
            CMD_WRITE,
            self.handle,
            int64(self._realpos),
            data[:chunk],
        )
        self._reqs.append(sftp_async_request)
        if not self.pipelined or (
            len(self._reqs) > 100 and self.sftp.sock.recv_ready()
        ):
            while len(self._reqs):
                req = self._reqs.popleft()
                t, msg = self.sftp._read_response(req)
                if t != CMD_STATUS:
                    raise SFTPError("Expected status")
                # convert_status already called
        return chunk

    def settimeout(self, timeout):
        """
        Set a timeout on read/write operations on the underlying socket or
        ssh `.Channel`.

        :param float timeout:
            seconds to wait for a pending read/write operation before raising
            ``socket.timeout``, or ``None`` for no timeout

        .. seealso:: `.Channel.settimeout`
        """
        self.sftp.sock.settimeout(timeout)

    def gettimeout(self):
        """
        Returns the timeout in seconds (as a `float`) associated with the
        socket or ssh `.Channel` used for this file.

        .. seealso:: `.Channel.gettimeout`
        """
        return self.sftp.sock.gettimeout()

    def setblocking(self, blocking):
        """
        Set blocking or non-blocking mode on the underiying socket or ssh
        `.Channel`.

        :param int blocking:
            0 to set non-blocking mode; non-0 to set blocking mode.

        .. seealso:: `.Channel.setblocking`
        """
        self.sftp.sock.setblocking(blocking)

    def seekable(self):
        """
        Check if the file supports random access.

        :return:
            `True` if the file supports random access. If `False`,
            :meth:`seek` will raise an exception
        """
        return True

    def seek(self, offset, whence=0):
        """
        Set the file's current position.

        See `file.seek` for details.
        """
        self.flush()
        if whence == self.SEEK_SET:
            self._realpos = self._pos = offset
        elif whence == self.SEEK_CUR:
            self._pos += offset
            self._realpos = self._pos
        else:
            self._realpos = self._pos = self._get_size() + offset
        self._rbuffer = bytes()
        self._seek_prefetch(self._realpos)

    def stat(self):
        """
        Retrieve information about this file from the remote system.  This is
        exactly like `.SFTPClient.stat`, except that it operates on an
        already-open file.

        :returns:
            an `.SFTPAttributes` object containing attributes about this file.
        """
        t, msg = self.sftp._request(CMD_FSTAT, self.handle)
        if t != CMD_ATTRS:
            raise SFTPError("Expected attributes")
        return SFTPAttributes._from_msg(msg)

    def chmod(self, mode):
        """
        Change the mode (permissions) of this file.  The permissions are
        unix-style and identical to those used by Python's `os.chmod`
        function.

        :param int mode: new permissions
        """
        self.sftp._log(
            DEBUG, "chmod({}, {!r})".format(hexlify(self.handle), mode)
        )
        attr = SFTPAttributes()
        attr.st_mode = mode
        self.sftp._request(CMD_FSETSTAT, self.handle, attr)

    def chown(self, uid, gid):
        """
        Change the owner (``uid``) and group (``gid``) of this file.  As with
        Python's `os.chown` function, you must pass both arguments, so if you
        only want to change one, use `stat` first to retrieve the current
        owner and group.

        :param int uid: new owner's uid
        :param int gid: new group id
        """
        self.sftp._log(
            DEBUG,
            "chown({}, {!r}, {!r})".format(hexlify(self.handle), uid, gid),
        )
        attr = SFTPAttributes()
        attr.st_uid, attr.st_gid = uid, gid
        self.sftp._request(CMD_FSETSTAT, self.handle, attr)

    def utime(self, times):
        """
        Set the access and modified times of this file.  If
        ``times`` is ``None``, then the file's access and modified times are
        set to the current time.  Otherwise, ``times`` must be a 2-tuple of
        numbers, of the form ``(atime, mtime)``, which is used to set the
        access and modified times, respectively.  This bizarre API is mimicked
        from Python for the sake of consistency -- I apologize.

        :param tuple times:
            ``None`` or a tuple of (access time, modified time) in standard
            internet epoch time (seconds since 01 January 1970 GMT)
        """
        if times is None:
            times = (time.time(), time.time())
        self.sftp._log(
            DEBUG, "utime({}, {!r})".format(hexlify(self.handle), times)
        )
        attr = SFTPAttributes()
        attr.st_atime, attr.st_mtime = times
        self.sftp._request(CMD_FSETSTAT, self.handle, attr)

    def truncate(self, size):
        """
        Change the size of this file.  This usually extends
        or shrinks the size of the file, just like the ``truncate()`` method on
        Python file objects.

        :param size: the new size of the file
        """
        self.sftp._log(
            DEBUG, "truncate({}, {!r})".format(hexlify(self.handle), size)
        )
        attr = SFTPAttributes()
        attr.st_size = size
        self.sftp._request(CMD_FSETSTAT, self.handle, attr)

    def check(self, hash_algorithm, offset=0, length=0, block_size=0):
        """
        Ask the server for a hash of a section of this file.  This can be used
        to verify a successful upload or download, or for various rsync-like
        operations.

        The file is hashed from ``offset``, for ``length`` bytes.
        If ``length`` is 0, the remainder of the file is hashed.  Thus, if both
        ``offset`` and ``length`` are zero, the entire file is hashed.

        Normally, ``block_size`` will be 0 (the default), and this method will
        return a byte string representing the requested hash (for example, a
        string of length 16 for MD5, or 20 for SHA-1).  If a non-zero
        ``block_size`` is given, each chunk of the file (from ``offset`` to
        ``offset + length``) of ``block_size`` bytes is computed as a separate
        hash.  The hash results are all concatenated and returned as a single
        string.

        For example, ``check('sha1', 0, 1024, 512)`` will return a string of
        length 40.  The first 20 bytes will be the SHA-1 of the first 512 bytes
        of the file, and the last 20 bytes will be the SHA-1 of the next 512
        bytes.

        :param str hash_algorithm:
            the name of the hash algorithm to use (normally ``"sha1"`` or
            ``"md5"``)
        :param offset:
            offset into the file to begin hashing (0 means to start from the
            beginning)
        :param length:
            number of bytes to hash (0 means continue to the end of the file)
        :param int block_size:
            number of bytes to hash per result (must not be less than 256; 0
            means to compute only one hash of the entire segment)
        :return:
            `str` of bytes representing the hash of each block, concatenated
            together

        :raises:
            ``IOError`` -- if the server doesn't support the "check-file"
            extension, or possibly doesn't support the hash algorithm requested

        .. note:: Many (most?) servers don't support this extension yet.

        .. versionadded:: 1.4
        """
        t, msg = self.sftp._request(
            CMD_EXTENDED,
            "check-file",
            self.handle,
            hash_algorithm,
            int64(offset),
            int64(length),
            block_size,
        )
        msg.get_text()  # ext
        msg.get_text()  # alg
        data = msg.get_remainder()
        return data

    def set_pipelined(self, pipelined=True):
        """
        Turn on/off the pipelining of write operations to this file.  When
        pipelining is on, paramiko won't wait for the server response after
        each write operation.  Instead, they're collected as they come in. At
        the first non-write operation (including `.close`), all remaining
        server responses are collected.  This means that if there was an error
        with one of your later writes, an exception might be thrown from within
        `.close` instead of `.write`.

        By default, files are not pipelined.

        :param bool pipelined:
            ``True`` if pipelining should be turned on for this file; ``False``
            otherwise

        .. versionadded:: 1.5
        """
        self.pipelined = pipelined

    def prefetch(
        self,
        file_size=None,
        max_concurrent_requests=None,
        *,
        max_prefetch_bytes=None,
    ):
        """
        Pre-fetch the remaining contents of this file in anticipation of future
        `.read` calls.  If reading the entire file, pre-fetching can
        dramatically improve the download speed by avoiding roundtrip latency.
        The file's contents are incrementally buffered in a background thread.

        The prefetched data is stored in a buffer until read via the `.read`
        method.  Once data has been read, it's removed from the buffer.  The
        data may be read in a random order (using `.seek`); chunks of the
        buffer that haven't been read will continue to be buffered.

        :param int file_size:
            When this is ``None`` (the default), this method calls `stat` to
            determine the remote file size. In some situations, doing so can
            cause exceptions or hangs (see `#562
            <https://github.com/paramiko/paramiko/pull/562>`_); as a
            workaround, one may call `stat` explicitly and pass its value in
            via this parameter.
        :param int max_concurrent_requests:
            The maximum number of concurrent read requests to prefetch. See
            `.SFTPClient.get` (its ``max_concurrent_prefetch_requests`` param)
            for details.
        :param int max_prefetch_bytes:
            Maximum number of bytes allowed in unread prefetch data and
            responses already in flight. When the limit is reached, the
            background thread pauses until `.read`, `.seek`, or
            `.cancel_prefetch` frees space.

        .. versionadded:: 1.5.1
        .. versionchanged:: 1.16.0
            The ``file_size`` parameter was added (with no default value).
        .. versionchanged:: 1.16.1
            The ``file_size`` parameter was made optional for backwards
            compatibility.
        .. versionchanged:: 3.3
            Added ``max_concurrent_requests``.
        .. versionchanged:: 5.0
            Added ``max_prefetch_bytes`` and cancellation-aware seek behavior.
        """
        if file_size is None:
            file_size = self.stat().st_size

        # queue up async reads for the rest of the file
        chunks = []
        n = self._realpos
        ranges = [(n, file_size)]
        while n < file_size:
            chunk = min(self.MAX_REQUEST_SIZE, file_size - n)
            chunks.append((n, chunk))
            n += chunk
        if len(chunks) > 0:
            self._start_prefetch(
                chunks,
                max_concurrent_requests,
                max_prefetch_bytes=max_prefetch_bytes,
                ranges=ranges,
                mode="sequential",
            )

    def readv(
        self,
        chunks,
        max_concurrent_prefetch_requests=None,
        *,
        max_prefetch_bytes=None,
    ):
        """
        Read a set of blocks from the file by (offset, length).  This is more
        efficient than doing a series of `.seek` and `.read` calls, since the
        prefetch machinery is used to retrieve all the requested blocks at
        once.

        :param chunks:
            a list of ``(offset, length)`` tuples indicating which sections of
            the file to read
        :param int max_concurrent_prefetch_requests:
            The maximum number of concurrent read requests to prefetch. See
            `.SFTPClient.get` (its ``max_concurrent_prefetch_requests`` param)
            for details.
        :param int max_prefetch_bytes:
            Maximum number of bytes allowed in unread prefetch data and
            responses already in flight.
        :return: a list of blocks read, in the same order as in ``chunks``

        .. versionadded:: 1.5.4
        .. versionchanged:: 3.3
            Added ``max_concurrent_prefetch_requests``.
        .. versionchanged:: 5.0
            Added ``max_prefetch_bytes``.
        """
        self.sftp._log(
            DEBUG, "readv({}, {!r})".format(hexlify(self.handle), chunks)
        )

        read_chunks = []
        for offset, size in chunks:
            # don't fetch data that's already in the prefetch buffer
            if self._data_in_prefetch_buffers(
                offset
            ) or self._data_in_prefetch_requests(offset, size):
                continue

            # break up anything larger than the max read size
            while size > 0:
                chunk_size = min(size, self.MAX_REQUEST_SIZE)
                read_chunks.append((offset, chunk_size))
                offset += chunk_size
                size -= chunk_size

        ranges = self._merge_ranges(
            [(offset, offset + size) for offset, size in chunks]
        )
        self._start_prefetch(
            read_chunks,
            max_concurrent_prefetch_requests,
            max_prefetch_bytes=max_prefetch_bytes,
            ranges=ranges,
            mode="readv",
            waiting_offset=chunks[0][0],
        )
        # now we can just devolve to a bunch of read()s :)
        for x in chunks:
            self.seek(x[0])
            yield self.read(x[1])

    # ...internals...

    def _get_size(self):
        try:
            return self.stat().st_size
        except:
            return 0

    def _start_prefetch(
        self,
        chunks,
        max_concurrent_requests=None,
        max_prefetch_bytes=None,
        ranges=None,
        mode=None,
        waiting_offset=None,
    ):
        if (
            max_concurrent_requests is not None
            and max_concurrent_requests <= 0
        ):
            raise ValueError("max_concurrent_requests must be positive")
        if max_prefetch_bytes is not None and max_prefetch_bytes < 0:
            raise ValueError("max_prefetch_bytes must be non-negative")

        start_thread = False
        thread = None
        with self._prefetch_condition:
            self._prefetching = True
            self._prefetch_done = False
            self._prefetch_closing = False
            self._prefetch_active = True
            self._prefetch_mode = mode
            self._prefetch_waiting_offset = (
                waiting_offset
                if waiting_offset is not None
                else self._realpos
            )
            self._prefetch_max_concurrent_requests = (
                max_concurrent_requests
            )
            self._prefetch_byte_budget = max_prefetch_bytes
            self._prefetch_ranges = self._merge_ranges(
                (self._prefetch_ranges or []) + (ranges or [])
            )

            generation = self._prefetch_generation
            existing = {
                (extent[0], extent[1])
                for extent in self._prefetch_extents.values()
            }
            for offset, length in chunks:
                if (offset, length) in existing:
                    continue
                existing.add((offset, length))
                self._prefetch_pending.append((offset, length, generation))
            self._discard_unwanted_prefetch_data_locked()

            start_thread = (
                self._prefetch_thread_handle is None
                or not self._prefetch_thread_handle.is_alive()
            )
            if start_thread:
                thread = threading.Thread(
                    target=self._prefetch_thread,
                    args=(generation,),
                )
                thread.daemon = True
                self._prefetch_thread_handle = thread
            self._prefetch_condition.notify_all()
        if start_thread:
            thread.start()

    def _prefetch_thread(self, generation):
        # do these read requests in a temporary thread because there may be
        # a lot of them, so it may block.
        try:
            while True:
                with self._prefetch_condition:
                    while True:
                        if (
                            self._prefetch_closing
                            or generation != self._prefetch_generation
                        ):
                            return
                        current_generation = self._prefetch_generation
                        while self._prefetch_pending:
                            offset, length, chunk_generation = (
                                self._prefetch_pending[0]
                            )
                            if chunk_generation != current_generation:
                                self._prefetch_pending.popleft()
                                continue
                            if self._range_intersects(
                                self._prefetch_ranges,
                                offset,
                                offset + length,
                            ):
                                break
                            self._prefetch_pending.popleft()
                        else:
                            if not self._prefetch_active:
                                if not self._prefetch_extents:
                                    self._prefetch_done = True
                                    self._prefetch_condition.notify_all()
                                return
                            self._prefetch_condition.wait(io_sleep)
                            continue

                        waiting = self._prefetch_waiting_offset
                        urgent = (
                            waiting is not None
                            and offset <= waiting < offset + length
                            and self._coverage_end_locked(
                                waiting, exclude_pending=True
                            )
                            <= waiting
                        )
                        current_extents = [
                            extent
                            for extent in self._prefetch_extents.values()
                            if extent[2] == current_generation
                        ]
                        in_flight_bytes = sum(
                            extent[1] for extent in current_extents
                        )
                        limit = self._prefetch_max_concurrent_requests
                        limit_ok = (
                            limit is None
                            or len(current_extents) < limit
                        )
                        budget = self._prefetch_byte_budget
                        budget_ok = (
                            budget is None
                            or self._prefetch_cached_bytes + in_flight_bytes
                            < budget
                        )
                        if limit_ok and (budget_ok or urgent):
                            self._prefetch_pending.popleft()
                            break
                        self._prefetch_condition.wait(io_sleep)
                        continue

                request_number = self.sftp._request_number()
                with self._prefetch_condition:
                    if (
                        self._prefetch_closing
                        or generation != self._prefetch_generation
                    ):
                        return
                    self._prefetch_extents[request_number] = (
                        offset,
                        length,
                        generation,
                    )
                    self._prefetch_condition.notify_all()
                try:
                    self.sftp._async_request_with_number(
                        request_number,
                        self,
                        CMD_READ,
                        self.handle,
                        int64(offset),
                        int(length),
                    )
                except Exception:
                    with self._prefetch_condition:
                        self._prefetch_extents.pop(request_number, None)
                        self._prefetch_condition.notify_all()
                    raise
        except Exception as e:
            with self._prefetch_condition:
                self._saved_exception = e
                self._prefetch_done = True
                self._prefetch_condition.notify_all()

    def _async_response(self, t, msg, num):
        with self._prefetch_condition:
            extent = self._prefetch_extents.pop(num, None)
        if extent is None:
            return
        offset, length, generation = extent
        if t == CMD_STATUS:
            try:
                self.sftp._convert_status(msg)
            except Exception as e:
                with self._prefetch_condition:
                    self._saved_exception = e
                    self._finish_prefetch_response_locked()
            else:
                with self._prefetch_condition:
                    self._finish_prefetch_response_locked()
            return
        if t != CMD_DATA:
            raise SFTPError("Expected data")
        data = msg.get_string()
        with self._prefetch_condition:
            end = offset + min(len(data), length)
            if self._range_intersects(
                self._prefetch_ranges or [], offset, end
            ) and data:
                self._add_prefetch_data_locked(offset, data[:length])
            self._finish_prefetch_response_locked()

    def _finish_prefetch_response_locked(self):
        if not self._prefetch_extents and not self._prefetch_pending:
            self._prefetch_done = True
        self._prefetch_condition.notify_all()

    def _check_exception(self):
        """if there's a saved exception, raise & clear it"""
        if self._saved_exception is not None:
            x = self._saved_exception
            self._saved_exception = None
            raise x
