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
from paramiko.ssh_exception import SSHException
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
        self._prefetch_cancelled = set()
        self._prefetch_bytes = 0
        self._prefetch_inflight = 0
        self._prefetch_peak_bytes = 0
        self._prefetch_max_bytes = None
        self._prefetch_stop = threading.Event()
        self._prefetch_threads = []
        self._prefetch_lock = threading.Condition()
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
        self._stop_prefetch(async_=async_)
        if self.pipelined:
            self.sftp._finish_responses(self)
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

    def _stop_prefetch(self, async_=False):
        """
        Terminate any background prefetch threads, and arrange for the
        responses to requests they already sent to be consumed and
        discarded, so they can't be mistaken for another file's response.
        """
        if not getattr(self, "_prefetch_threads", None):
            return
        # tell the prefetch threads to stop, and wake any that are paused
        # waiting for buffer space.
        self._prefetch_stop.set()
        with self._prefetch_lock:
            self._prefetch_lock.notify_all()
        current = threading.current_thread()
        for t in self._prefetch_threads:
            if t is not current and t.is_alive():
                t.join()
        self._prefetch_threads = []
        with self._prefetch_lock:
            # cancel anything still outstanding; late responses will be
            # discarded as they arrive.
            for num in list(self._prefetch_extents):
                self._prefetch_cancelled.add(num)
            self._prefetch_extents.clear()
            self._prefetch_data.clear()
            self._prefetch_bytes = 0
            self._prefetch_inflight = 0
            self._prefetch_done = True
            self._prefetch_lock.notify_all()
        if async_:
            return
        # consume late responses now, while we still own the handle.
        try:
            while self in self.sftp._expecting.values():
                self.sftp._read_response()
        except (EOFError, IOError, socket.error, SSHException):
            # may have outlived the Transport connection
            pass
        if self._saved_exception is not None:
            # a prefetch request failed, but there's no future file
            # operation to raise it into; don't let it leak out of close.
            self.sftp._log(
                DEBUG,
                "Swallowing prefetch exception on close: {!r}".format(
                    self._saved_exception
                ),
            )
            self._saved_exception = None

    def _data_in_prefetch_requests(self, offset, size):
        k = [
            x for x in list(self._prefetch_extents.values()) if x[0] <= offset
        ]
        if len(k) == 0:
            return False
        k.sort(key=lambda x: x[0])
        buf_offset, buf_size = k[-1]
        if buf_offset + buf_size <= offset:
            # prefetch request ends before this one begins
            return False
        if buf_offset + buf_size >= offset + size:
            # inclusive
            return True
        # well, we have part of the request.  see if another chunk has
        # the rest.
        return self._data_in_prefetch_requests(
            buf_offset + buf_size, offset + size - buf_offset - buf_size
        )

    def _data_in_prefetch_buffers(self, offset):
        """
        if a block of data is present in the prefetch buffers, at the given
        offset, return the offset of the relevant prefetch buffer.  otherwise,
        return None.  this guarantees nothing about the number of bytes
        collected in the prefetch buffer so far.
        """
        k = [i for i in self._prefetch_data.keys() if i <= offset]
        if len(k) == 0:
            return None
        index = max(k)
        buf_offset = offset - index
        if buf_offset >= len(self._prefetch_data[index]):
            # it's not here
            return None
        return index

    def _read_prefetch(self, size):
        """
        read data out of the prefetch buffer, if possible.  if the data isn't
        in the buffer, return None.  otherwise, behaves like a normal read.
        """
        # while not closed, and haven't fetched past the current position,
        # and haven't reached EOF...
        while True:
            offset = self._data_in_prefetch_buffers(self._realpos)
            if offset is not None:
                break
            if self._prefetch_done or self._closed:
                break
            if not self._data_in_prefetch_requests(self._realpos, 1):
                # The data we need isn't buffered, and no outstanding
                # request covers it (it was cancelled after a seek, or the
                # prefetch thread is paused because the buffer is full).
                # Request it directly so the read can't deadlock.
                self._issue_prefetch_request(
                    self._realpos, min(size, self.MAX_REQUEST_SIZE)
                )
            self.sftp._read_response()
            self._check_exception()
        if offset is None:
            self._prefetching = False
            return None
        prefetch = self._prefetch_data[offset]
        del self._prefetch_data[offset]

        buf_offset = self._realpos - offset
        if buf_offset > 0:
            self._prefetch_data[offset] = prefetch[:buf_offset]
            prefetch = prefetch[buf_offset:]
        if size < len(prefetch):
            self._prefetch_data[self._realpos + size] = prefetch[size:]
            prefetch = prefetch[:size]
        with self._prefetch_lock:
            # the returned chunk leaves the cache; wake the prefetch
            # thread if it was paused on the byte budget.
            self._prefetch_bytes -= len(prefetch)
            self._prefetch_lock.notify_all()
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
        if self._prefetching:
            # data ending before the new position won't be needed any time
            # soon; drop it (cancelling matching in-flight requests) so it
            # stops counting against the prefetch byte budget.
            self._cancel_prefetch_before(self._realpos)

    def cancel_prefetch(self):
        """
        Cancel any outstanding prefetch requests and discard all prefetched
        data currently in the buffer.

        Responses for requests that are already in flight are still
        consumed (and discarded) as they arrive, so they can't interfere
        with subsequent requests made by this or any other file on the
        same `.SFTPClient`.

        .. versionadded:: 5.0
        """
        self._prefetch_stop.set()
        with self._prefetch_lock:
            self._drop_prefetch_locked(None)

    def _cancel_prefetch_before(self, offset):
        """
        Discard buffered data and cancel in-flight prefetch requests that
        end at or before ``offset``.
        """
        with self._prefetch_lock:
            self._drop_prefetch_locked(offset)

    def _drop_prefetch_locked(self, offset):
        # caller must hold ``self._prefetch_lock``.  an ``offset`` of None
        # drops everything.
        for buf_offset in list(self._prefetch_data):
            data = self._prefetch_data[buf_offset]
            if offset is None or buf_offset + len(data) <= offset:
                del self._prefetch_data[buf_offset]
                self._prefetch_bytes -= len(data)
        for num, extent in list(self._prefetch_extents.items()):
            req_offset, req_length = extent
            if offset is None or req_offset + req_length <= offset:
                del self._prefetch_extents[num]
                self._prefetch_cancelled.add(num)
                self._prefetch_inflight -= req_length
        if len(self._prefetch_extents) == 0:
            self._prefetch_done = True
        self._prefetch_lock.notify_all()

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
        max_concurrent_bytes=None,
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
        :param int max_concurrent_bytes:
            The maximum number of bytes of prefetched data to buffer (plus
            the size of any in-flight prefetch responses) before the
            background prefetch thread pauses, waiting for the reader to
            catch up. When this is ``None`` (the default), the amount of
            buffered prefetch data is not limited.

        .. versionadded:: 1.5.1
        .. versionchanged:: 1.16.0
            The ``file_size`` parameter was added (with no default value).
        .. versionchanged:: 1.16.1
            The ``file_size`` parameter was made optional for backwards
            compatibility.
        .. versionchanged:: 3.3
            Added ``max_concurrent_requests``.
        .. versionchanged:: 5.0
            Added ``max_concurrent_bytes``.
        """
        if file_size is None:
            file_size = self.stat().st_size

        # queue up async reads for the rest of the file
        chunks = []
        n = self._realpos
        while n < file_size:
            chunk = min(self.MAX_REQUEST_SIZE, file_size - n)
            chunks.append((n, chunk))
            n += chunk
        if len(chunks) > 0:
            self._start_prefetch(
                chunks, max_concurrent_requests, max_concurrent_bytes
            )

    def readv(
        self,
        chunks,
        max_concurrent_prefetch_requests=None,
        max_concurrent_prefetch_bytes=None,
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
        :param int max_concurrent_prefetch_bytes:
            The maximum number of bytes of prefetched data to buffer before
            pausing. See `.prefetch` (its ``max_concurrent_bytes`` param)
            for details.
        :return: a list of blocks read, in the same order as in ``chunks``

        .. versionadded:: 1.5.4
        .. versionchanged:: 3.3
            Added ``max_concurrent_prefetch_requests``.
        .. versionchanged:: 5.0
            Added ``max_concurrent_prefetch_bytes``.
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

        self._start_prefetch(
            read_chunks,
            max_concurrent_prefetch_requests,
            max_concurrent_prefetch_bytes,
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
        self, chunks, max_concurrent_requests=None, max_concurrent_bytes=None
    ):
        self._prefetching = True
        self._prefetch_done = False
        self._prefetch_max_bytes = max_concurrent_bytes
        self._prefetch_stop.clear()

        t = threading.Thread(
            target=self._prefetch_thread,
            args=(chunks, max_concurrent_requests),
        )
        t.daemon = True
        t.start()
        self._prefetch_threads.append(t)

    def _issue_prefetch_request(self, offset, length):
        num = self.sftp._async_request(
            self, CMD_READ, self.handle, int64(offset), int(length)
        )
        with self._prefetch_lock:
            if self._prefetch_stop.is_set():
                # cancelled or closed while the request was being sent;
                # make sure its response is discarded when it arrives.
                self._prefetch_cancelled.add(num)
            else:
                self._prefetch_extents[num] = (offset, length)
                self._prefetch_inflight += length
            self._prefetch_lock.notify_all()

    def _prefetch_thread(self, chunks, max_concurrent_requests):
        # do these read requests in a temporary thread because there may be
        # a lot of them, so it may block.
        try:
            for offset, length in chunks:
                # Limit the number of concurrent requests, and the amount
                # of memory used by prefetched data, by pausing until the
                # reader catches up.
                with self._prefetch_lock:
                    while not self._prefetch_stop.is_set():
                        if (
                            max_concurrent_requests is not None
                            and len(self._prefetch_extents)
                            >= max_concurrent_requests
                        ):
                            self._prefetch_lock.wait(io_sleep)
                            continue
                        if (
                            self._prefetch_max_bytes is not None
                            and self._prefetch_bytes
                            + self._prefetch_inflight
                            >= self._prefetch_max_bytes
                        ):
                            self._prefetch_lock.wait(io_sleep)
                            continue
                        break
                if self._prefetch_stop.is_set():
                    break
                self._issue_prefetch_request(offset, length)
        except Exception as e:
            # don't kill the process with an unhandled thread exception if
            # e.g. the connection drops; the reader will hit the same
            # problem on its next operation.
            self.sftp._log(
                DEBUG, "Prefetch thread terminated: {!r}".format(e)
            )

    def _async_response(self, t, msg, num):
        if t == CMD_STATUS:
            # save exception and re-raise it on next file operation
            try:
                self.sftp._convert_status(msg)
            except Exception as e:
                self._saved_exception = e
            with self._prefetch_lock:
                # the failed request is no longer in flight
                if num in self._prefetch_extents:
                    offset, length = self._prefetch_extents[num]
                    del self._prefetch_extents[num]
                    self._prefetch_inflight -= length
                self._prefetch_cancelled.discard(num)
                if len(self._prefetch_extents) == 0:
                    self._prefetch_done = True
                self._prefetch_lock.notify_all()
            return
        if t != CMD_DATA:
            raise SFTPError("Expected data")
        data = msg.get_string()
        with self._prefetch_lock:
            # normally the extent is already registered, but a fast server
            # may respond before the prefetch thread records its request
            while (
                num not in self._prefetch_extents
                and num not in self._prefetch_cancelled
                and not self._prefetch_stop.is_set()
            ):
                self._prefetch_lock.wait(io_sleep)
            if num in self._prefetch_extents:
                offset, length = self._prefetch_extents[num]
                del self._prefetch_extents[num]
                self._prefetch_inflight -= length
                self._prefetch_data[offset] = data
                self._prefetch_bytes += len(data)
                if self._prefetch_bytes > self._prefetch_peak_bytes:
                    self._prefetch_peak_bytes = self._prefetch_bytes
            # else: the request was cancelled (or the file closed) before
            # its response arrived; discard the data.
            if len(self._prefetch_extents) == 0:
                self._prefetch_done = True
            self._prefetch_lock.notify_all()

    def _check_exception(self):
        """if there's a saved exception, raise & clear it"""
        if self._saved_exception is not None:
            x = self._saved_exception
            self._saved_exception = None
            raise x
