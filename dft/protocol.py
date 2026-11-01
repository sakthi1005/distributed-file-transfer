"""Wire protocol shared by senders and receivers.

Discovery (UDP, JSON, HMAC-signed):
    DISCOVER  receiver -> senders   {type, filename, nonce, ts, mac}
    OFFER     sender   -> receiver  {type, sender_id, filename, size, sha256,
                                     tcp_port, load, tls, nonce, ts, mac}

Transfer (TCP, optionally wrapped in TLS):
    request   one JSON line:  {"op":"GET","file":..,"offset":..,"length":..}
                              {"op":"PING"}
    response  fixed 21-byte header + payload:
              magic(4) status(1) offset(8) length(4) crc32(4) | payload
"""
from __future__ import annotations

import hashlib
import hmac
import json
import socket
import struct
import time

MAGIC = b"DFTP"
DEFAULT_DISCOVERY_PORT = 50000
DEFAULT_CHUNK_SIZE = 256 * 1024
MAX_CHUNK_SIZE = 8 * 1024 * 1024
MAX_MESSAGE_AGE = 30.0  # seconds; an older DISCOVER is treated as a replay
DEFAULT_SECRET = "change-me-dev-secret"

HEADER = struct.Struct(">4sBQII")
STATUS_OK = 0
STATUS_NOT_FOUND = 1
STATUS_BAD_RANGE = 2


class ProtocolError(Exception):
    """Raised when the peer violates the wire protocol."""


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign(message: dict, secret: str) -> dict:
    body = {k: v for k, v in message.items() if k != "mac"}
    body["mac"] = hmac.new(secret.encode(), _canonical(body), hashlib.sha256).hexdigest()
    return body


def verify(message: dict, secret: str) -> bool:
    mac = message.get("mac")
    if not isinstance(mac, str):
        return False
    body = {k: v for k, v in message.items() if k != "mac"}
    expected = hmac.new(secret.encode(), _canonical(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected)


def is_fresh(message: dict) -> bool:
    ts = message.get("ts")
    return isinstance(ts, (int, float)) and abs(time.time() - ts) <= MAX_MESSAGE_AGE


def pack_header(status: int, offset: int, length: int, crc: int) -> bytes:
    return HEADER.pack(MAGIC, status, offset, length, crc)


def unpack_header(raw: bytes):
    magic, status, offset, length, crc = HEADER.unpack(raw)
    if magic != MAGIC:
        raise ProtocolError("bad magic in frame header")
    return status, offset, length, crc


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise EOFError (TCP is a stream, not messages)."""
    buf = bytearray(n)
    view = memoryview(buf)
    got = 0
    while got < n:
        r = sock.recv_into(view[got:], n - got)
        if r == 0:
            raise EOFError("connection closed by peer")
        got += r
    return bytes(buf)
