"""
Unit tests for prefetch byte budgets, prefetch cancellation, and close
behavior, using an in-process stub SFTP server that returns read responses
out of order.
"""

import os
import shutil
import struct
import threading

import pytest

from paramiko import (
    RSAKey,
    SFTP,
    SFTP_BAD_MESSAGE,
    SFTP_EOF,
    SFTPServer,
    Transport,
)
from paramiko.sftp import CMD_DATA, CMD_READ
from paramiko.sftp_file import SFTPFile

from ._loop import LoopSocket
from ._stub_sftp import StubServer, StubSFTPServer
from ._util import _support

CHUNK = SFTPFile.MAX_REQUEST_SIZE
NCHUNKS = 16
FILE_SIZE = CHUNK * NCHUNKS
# position-verifiable content: every 4 bytes are their own index
CONTENT = b"".join(struct.pack(">I", i) for i in range(FILE_SIZE // 4))


class OutOfOrderSFTPServer(SFTPServer):
    """
    An `.SFTPServer` that defers CMD_READ responses and releases them in
    reverse (LIFO) batches, so the client sees out-of-order responses.

    Every read request's (offset, length) is recorded in the class-level
    ``read_requests`` list for test inspection.
    """

    reorder_window = 3
    flush_interval = 0.2
    read_requests = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._held = []
        self._flush_timer = None
        self._send_lock = threading.Lock()

    def _process(self, t, request_number, msg):
        if t != CMD_READ:
            with self._send_lock:
                # preserve read-before-anything-else ordering
                self._flush_locked()
                super()._process(t, request_number, msg)
            return
        handle = msg.get_binary()
        offset = msg.get_int64()
        length = msg.get_int()
        self.read_requests.append((offset, length))
        if handle not in self.file_table:
            with self._send_lock:
                self._send_status(
                    request_number, SFTP_BAD_MESSAGE, "Invalid handle"
                )
            return
        data = self.file_table[handle].read(offset, length)
        with self._send_lock:
            self._held.append((request_number, data))
            if len(self._held) >= self.reorder_window:
                self._flush_locked()
            elif self._flush_timer is None:
                self._flush_timer = threading.Timer(
                    self.flush_interval, self._flush
                )
                self._flush_timer.daemon = True
                self._flush_timer.start()

    def _flush(self):
        try:
            with self._send_lock:
                self._flush_locked()
        except Exception:
            # channel may have been closed by test teardown
            pass

    def _flush_locked(self):
        held = self._held
        self._held = []
        if self._flush_timer is not None:
            self._flush_timer.cancel()
            self._flush_timer = None
        for request_number, data in reversed(held):
            if isinstance(data, (bytes, str)):
                if len(data) == 0:
                    self._send_status(request_number, SFTP_EOF)
                else:
                    self._response(request_number, CMD_DATA, data)
            else:
                self._send_status(request_number, data)


@pytest.fixture
def ooo_sftp():
    """
    Yield an SFTP client connected to an out-of-order stub SFTP server.
    """
    OutOfOrderSFTPServer.read_requests = []
    socks, sockc = LoopSocket(), LoopSocket()
    sockc.link(socks)
    tc, ts = Transport(sockc), Transport(socks)
    host_key = RSAKey.from_private_key_file(_support("rsa.key"))
    ts.add_server_key(host_key)
    event = threading.Event()
    ts.set_subsystem_handler("sftp", OutOfOrderSFTPServer, StubSFTPServer)
    ts.start_server(event, StubServer())
    event.wait(1.0)
    tc.connect(username="slowdive", password="pygmalion")
    client = SFTP.from_transport(tc)
    folder = "paramiko-test-ooo"
    shutil.rmtree(folder, ignore_errors=True)
    os.mkdir(folder)
    client.FOLDER = folder
    try:
        yield client
    finally:
        client.close()
        tc.close()
        ts.close()
        shutil.rmtree(folder, ignore_errors=True)


@pytest.fixture
def ooo_file(ooo_sftp):
    """
    Write the test pattern to a remote file and return its path.
    """
    path = ooo_sftp.FOLDER + "/ooo.bin"
    with ooo_sftp.open(path, "wb") as f:
        f.write(CONTENT)
    return path


def _assert_valid_ranges(file_size=FILE_SIZE):
    requested = OutOfOrderSFTPServer.read_requests
    assert len(requested) > 0
    for offset, length in requested:
        # (a request exactly at file_size is how EOF is detected)
        assert 0 <= offset <= file_size
        assert 0 < length <= CHUNK
    # everything ever read must have been requested at some point
    covered = bytearray(file_size)
    for offset, length in requested:
        end = min(offset + length, file_size)
        covered[offset:end] = b"\x01" * (end - offset)
    assert covered == b"\x01" * file_size
    return requested


class TestPrefetchByteBudget:
    def test_backward_seek(self, ooo_sftp, ooo_file):
        """
        With a byte budget, a backward seek must not deadlock: the
        currently-needed range is re-requested on demand, and the cache
        never grows (much) past the budget.
        """
        budget = 4 * CHUNK
        with ooo_sftp.open(ooo_file, "rb") as f:
            f.prefetch(FILE_SIZE, max_concurrent_bytes=budget)
            # read forward a little, then jump back to the start
            assert f.read(CHUNK) == CONTENT[:CHUNK]
            assert f.read(CHUNK) == CONTENT[CHUNK : 2 * CHUNK]
            f.seek(0)
            assert f.read() == CONTENT
            # peak cache stayed within the budget (plus one chunk of slack
            # for the on-demand request that prevents deadlock)
            assert 0 < f._prefetch_peak_bytes <= budget + CHUNK
            # the budget actually limited buffering: without it, the whole
            # file (16 chunks) could be cached at once
            assert f._prefetch_peak_bytes < FILE_SIZE
        requested = _assert_valid_ranges()
        # the backward seek forced some ranges to be requested twice
        assert len(requested) > NCHUNKS

    def test_repeated_ranges(self, ooo_sftp, ooo_file):
        """
        readv over repeated/overlapping ranges returns correct data even
        though responses arrive out of order.
        """
        chunks = [
            (0, 100),
            (0, 100),  # exact repeat
            (50, 100),  # overlap
            (CHUNK, 200),
            (0, 100),  # repeat again, after seeking away
        ]
        with ooo_sftp.open(ooo_file, "rb") as f:
            results = list(
                f.readv(chunks, max_concurrent_prefetch_bytes=4 * CHUNK)
            )
            assert results == [
                CONTENT[offset : offset + length]
                for offset, length in chunks
            ]
            assert f._prefetch_peak_bytes <= 4 * CHUNK + CHUNK
        requested = OutOfOrderSFTPServer.read_requests
        assert len(requested) > 0
        for offset, length in requested:
            assert 0 <= offset < FILE_SIZE
            assert 0 < length <= CHUNK

    def test_cancel_prefetch(self, ooo_sftp, ooo_file):
        """
        cancel_prefetch drops buffered data and outstanding requests;
        subsequent reads still return correct data.
        """
        with ooo_sftp.open(ooo_file, "rb") as f:
            f.prefetch(FILE_SIZE, max_concurrent_bytes=2 * CHUNK)
            f.read(CHUNK)
            f.cancel_prefetch()
            assert f._prefetch_bytes == 0
            assert len(f._prefetch_extents) == 0
            # reading still works after cancellation
            f.seek(3 * CHUNK)
            assert f.read(100) == CONTENT[3 * CHUNK : 3 * CHUNK + 100]
            f.seek(0)
            assert f.read(CHUNK) == CONTENT[:CHUNK]

    def test_close_stops_prefetch(self, ooo_sftp, ooo_file):
        """
        close terminates the prefetch thread and consumes late responses,
        so they can't leak into another file's requests.
        """
        f = ooo_sftp.open(ooo_file, "rb")
        f.prefetch(FILE_SIZE, max_concurrent_bytes=CHUNK)
        assert f.read(CHUNK) == CONTENT[:CHUNK]
        threads = list(f._prefetch_threads)
        assert len(threads) > 0
        f.close()
        # prefetch thread was terminated
        for t in threads:
            t.join(timeout=5)
            assert not t.is_alive()
        # no responses for this file are still expected
        assert f not in ooo_sftp._expecting.values()
        # a second file on the same client is unaffected by late responses
        other = ooo_sftp.FOLDER + "/other.bin"
        with ooo_sftp.open(other, "wb") as g:
            g.write(CONTENT)
        with ooo_sftp.open(other, "rb") as g:
            assert g.read() == CONTENT
        # the late responses were consumed, not delivered to the new file
        assert f not in ooo_sftp._expecting.values()
