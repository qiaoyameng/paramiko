import threading

import pytest

from paramiko.message import Message
from paramiko.sftp import CMD_DATA
from paramiko.sftp_file import SFTPFile


class OutOfOrderSFTP:
    def __init__(
        self,
        data,
        *,
        fail_request=None,
        response_delay=0.0,
        auto_respond=True,
    ):
        self.data = data
        self.fail_request = fail_request
        self.response_delay = response_delay
        self.auto_respond = auto_respond
        self.request_number = 1
        self.requests = []
        self._lock = threading.Lock()
        self._expecting = {}
        self._pending_responses = {}

    def _log(self, level, message):
        pass

    def _request_number(self):
        with self._lock:
            number = self.request_number
            self.request_number += 1
        return number

    def _async_request_with_number(
        self, number, fileobj, command, handle, offset, length
    ):
        offset = int(offset)
        length = int(length)
        self.requests.append((offset, length))
        response = threading.Event()
        with self._lock:
            self._expecting[number] = fileobj
            self._pending_responses[number] = response
        thread = threading.Thread(
            target=self._respond_when_ready,
            args=(number, response, offset, length),
            daemon=True,
        )
        thread.start()

    def deliver(self, number):
        with self._lock:
            event = self._pending_responses[number]
        event.set()

    def _respond_when_ready(self, number, event, offset, length):
        if self.auto_respond:
            event.wait(self.response_delay or None)
        else:
            event.wait()
        self._respond(number, offset, length)

    def _respond(self, number, offset, length):
        if self.fail_request == number:
            message = Message()
            message.add_int(1)
            message.add_string("forced prefetch failure")
            message.add_string("en")
            t = 101
        else:
            message = Message()
            message.add_string(self.data[offset : offset + length])
            t = CMD_DATA
        message.rewind()
        with self._lock:
            fileobj = self._expecting.pop(number)
            self._pending_responses.pop(number, None)
        fileobj._async_response(t, message, number)

    def _read_response(self, waitfor=None):
        return None, None

    def _finish_responses(self, fileobj):
        deadline = threading.Event()
        while not deadline.wait(0.001):
            with self._lock:
                if not self._expecting:
                    return

    def _convert_status(self, msg):
        code = msg.get_int()
        text = msg.get_text()
        raise OSError(code, text)

    def _request(self, command, handle):
        self.requests.append(("close", handle))

    def _async_request(self, fileobj, command, *args):
        self.requests.append(("close", args[0] if args else None))


def make_file(sftp, max_request_size=4):
    fileobj = SFTPFile(sftp, b"handle", "rb")
    fileobj.MAX_REQUEST_SIZE = max_request_size
    return fileobj


def wait_until(predicate, timeout=2):
    deadline = threading.Event()
    while not predicate():
        if deadline.wait(0.001) or timeout <= 0:
            raise AssertionError("timed out waiting for prefetch condition")
        timeout -= 0.001


def test_prefetch_byte_budget_and_backward_seek():
    data = bytes(range(64))
    sftp = OutOfOrderSFTP(data, auto_respond=False)
    fileobj = make_file(sftp)

    fileobj.prefetch(len(data), max_prefetch_bytes=8)
    wait_until(lambda: len(sftp.requests) == 2)
    assert fileobj._prefetch_cached_bytes == 0

    sftp.deliver(1)
    sftp.deliver(2)
    wait_until(lambda: fileobj._prefetch_cached_bytes == 8)
    assert fileobj._prefetch_peak_cached_bytes == 8
    assert len(fileobj._prefetch_extents) == 0
    assert len(sftp.requests) == 2

    fileobj.seek(0)
    assert fileobj.read(8) == data[0:8]
    wait_until(lambda: len(sftp.requests) == 4)

    sftp.deliver(3)
    sftp.deliver(4)
    fileobj.seek(8)
    assert fileobj.read(8) == data[8:16]
    wait_until(lambda: len(sftp.requests) == 6)
    sftp.deliver(5)
    sftp.deliver(6)
    fileobj.seek(16)
    assert fileobj.read(8) == data[16:24]
    wait_until(lambda: len(sftp.requests) == 8)
    sftp.deliver(7)
    sftp.deliver(8)
    fileobj.seek(24)
    assert fileobj.read(8) == data[24:32]
    wait_until(lambda: len(sftp.requests) == 10)
    sftp.deliver(9)
    sftp.deliver(10)
    fileobj.seek(32)
    assert fileobj.read(8) == data[32:40]
    wait_until(lambda: len(sftp.requests) == 12)
    sftp.deliver(11)
    sftp.deliver(12)
    fileobj.seek(40)
    assert fileobj.read(8) == data[40:48]
    wait_until(lambda: len(sftp.requests) == 14)
    sftp.deliver(13)
    sftp.deliver(14)
    fileobj.seek(48)
    assert fileobj.read(8) == data[48:56]
    wait_until(lambda: len(sftp.requests) == 16)
    sftp.deliver(15)
    sftp.deliver(16)
    fileobj.seek(56)
    assert fileobj.read(8) == data[56:64]

    fileobj.close()
    read_requests = [
        request for request in sftp.requests if request[0] != "close"
    ]
    assert fileobj._prefetch_peak_cached_bytes <= 8
    assert len(read_requests) == len(data) // 4
    assert read_requests == sorted(read_requests)


def test_zero_byte_budget_does_not_deadlock_current_read():
    data = bytes(range(8))
    sftp = OutOfOrderSFTP(data, response_delay=0.001)
    fileobj = make_file(sftp)

    fileobj.prefetch(len(data), max_prefetch_bytes=0)
    assert fileobj.read(4) == data[:4]
    assert fileobj.read(4) == data[4:]
    fileobj.close()


def test_prefetch_repeated_ranges_do_not_duplicate_requests():
    data = bytes(range(32))
    sftp = OutOfOrderSFTP(data, auto_respond=False)
    fileobj = make_file(sftp)

    fileobj.prefetch(len(data), max_concurrent_requests=2)
    wait_until(lambda: len(sftp.requests) == 2)

    sftp.deliver(1)
    fileobj.seek(8)
    wait_until(lambda: (8, 4) in sftp.requests)
    fileobj.seek(0)
    fileobj.seek(8)
    assert fileobj._realpos == 8

    delivered = {1}
    for expected_request in range(3, 9):
        wait_until(lambda: len(sftp.requests) == expected_request)
        request_number = expected_request
        if request_number not in delivered:
            sftp.deliver(request_number)
            delivered.add(request_number)
    sftp.deliver(2)

    assert fileobj.read(24) == data[8:32]
    fileobj.close()

    read_requests = [
        request for request in sftp.requests if request[0] != "close"
    ]
    assert read_requests == [
        (0, 4),
        (4, 4),
        (8, 4),
        (12, 4),
        (16, 4),
        (20, 4),
        (24, 4),
        (28, 4),
    ]


def test_readv_promotes_current_range_with_full_request_window():
    data = bytes(range(12))
    sftp = OutOfOrderSFTP(data, auto_respond=False)
    fileobj = make_file(sftp)
    chunks = [(0, 4), (4, 4), (8, 4)]

    fileobj._start_prefetch(
        chunks,
        max_concurrent_requests=2,
        ranges=[(0, 4), (4, 8), (8, 12)],
        mode="readv",
        waiting_offset=0,
    )
    wait_until(lambda: len(sftp.requests) == 2)

    fileobj.seek(8)
    sftp.deliver(1)
    wait_until(lambda: (8, 4) in sftp.requests)
    sftp.deliver(3)
    wait_until(lambda: fileobj._prefetch_data.get(8))
    assert fileobj.read(4) == data[8:12]
    sftp.deliver(2)
    fileobj.close()


def test_close_consumes_late_responses():
    data = bytes(range(16))
    sftp = OutOfOrderSFTP(data, response_delay=0.01)
    fileobj = make_file(sftp)

    fileobj.prefetch(len(data))
    fileobj.close()

    assert not fileobj._prefetch_thread_handle.is_alive()
    assert not sftp._expecting
    assert ("close", b"handle") in sftp.requests


def test_cancel_prefetch_consumes_in_flight_responses():
    data = bytes(range(32))
    sftp = OutOfOrderSFTP(data, response_delay=0.01)
    fileobj = make_file(sftp)

    fileobj.prefetch(
        len(data),
        max_concurrent_requests=2,
        max_prefetch_bytes=8,
    )
    wait_until(lambda: len(sftp.requests) == 2)

    fileobj.cancel_prefetch()
    assert len(sftp.requests) == 2
    assert not fileobj._prefetch_thread_handle.is_alive()
    assert len(fileobj._prefetch_pending) == 0

    fileobj.close()
    assert not sftp._expecting


def test_close_raises_pending_prefetch_exception():
    data = bytes(range(16))
    sftp = OutOfOrderSFTP(data, fail_request=2, response_delay=0.01)
    fileobj = make_file(sftp)

    fileobj.prefetch(len(data))
    wait_until(lambda: fileobj._saved_exception is not None)

    with pytest.raises(OSError, match="forced prefetch failure"):
        fileobj.close()
    assert not fileobj._prefetch_thread_handle.is_alive()
    assert not sftp._expecting
