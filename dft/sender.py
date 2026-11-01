
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import socketserver
import ssl
import sys
import threading
import time
from pathlib import Path

from . import protocol as P
from .auditlog import AuditLog
from .integrity import crc32, sha256_file


class FileIndex:
    """Hashes every shared file once and re-hashes only if size/mtime change."""

    def __init__(self, directory):
        self.dir = Path(directory).resolve()
        self._cache = {}
        self._lock = threading.Lock()
        for p in self.dir.iterdir():
            if p.is_file():
                self.lookup(p.name)

    def lookup(self, name):
        if not name or name != os.path.basename(name) or name in (".", ".."):
            return None  # blocks path traversal such as ../../etc/passwd
        path = self.dir / name
        try:
            st = path.stat()
        except OSError:
            return None
        if not path.is_file():
            return None
        key = (st.st_size, st.st_mtime_ns)
        with self._lock:
            hit = self._cache.get(name)
            if hit and hit["key"] == key:
                return hit
        entry = {"key": key, "path": path, "size": st.st_size, "sha256": sha256_file(path)}
        with self._lock:
            self._cache[name] = entry
        return entry


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, sender):
        self.sender = sender
        super().__init__(addr, handler)

    def get_request(self):
        sock, addr = super().get_request()
        if self.sender.tls_ctx:
            # handshake happens lazily in the handler thread, not the accept loop
            sock = self.sender.tls_ctx.wrap_socket(
                sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        s = self.server.sender
        s._enter()
        try:
            self.connection.settimeout(30)
            while True:
                line = self.rfile.readline(4096)
                if not line:
                    return
                req = json.loads(line)
                op = req.get("op")
                if op == "PING":
                    self._send(P.STATUS_OK, 0, b"")
                elif op == "GET":
                    self._get(s, req)
                else:
                    return
        except (OSError, ValueError, EOFError):
            pass  # includes ssl.SSLError; a bad client must never crash the sender
        finally:
            s._leave()

    def _send(self, status, offset, payload, crc=0):
        self.connection.sendall(P.pack_header(status, offset, len(payload), crc) + payload)

    def _get(self, s, req):
        name, offset, length = req.get("file"), req.get("offset"), req.get("length")
        entry = s.index.lookup(name) if isinstance(name, str) else None
        if entry is None:
            return self._send(P.STATUS_NOT_FOUND, 0, b"")
        if (not isinstance(offset, int) or not isinstance(length, int) or offset < 0
                or length <= 0 or length > P.MAX_CHUNK_SIZE
                or offset + length > entry["size"]):
            return self._send(P.STATUS_BAD_RANGE, 0, b"")
        s._before_serve()
        with open(entry["path"], "rb") as fh:
            fh.seek(offset)
            data = fh.read(length)
        if len(data) != length:
            return self._send(P.STATUS_BAD_RANGE, 0, b"")
        crc = crc32(data)                 # CRC of the *correct* data...
        data = s._maybe_corrupt(data)     # ...so injected corruption is detectable
        self._send(P.STATUS_OK, offset, data, crc)
        s._throttle(len(data))


class Sender:
    def __init__(self, directory, tcp_port, discovery_port=P.DEFAULT_DISCOVERY_PORT,
                 secret=P.DEFAULT_SECRET, host="0.0.0.0", sender_id=None,
                 throttle_kbps=0, corrupt_rate=0.0, die_after=0,
                 tls_cert=None, tls_key=None, audit=None):
        self.index = FileIndex(directory)
        self.host, self.tcp_port, self.discovery_port = host, tcp_port, discovery_port
        self.secret = secret
        self.id = sender_id or f"sender-{tcp_port}"
        self.throttle_kbps, self.corrupt_rate, self.die_after = throttle_kbps, corrupt_rate, die_after
        self.audit = audit or AuditLog()
        self.tls_ctx = None
        if tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(tls_cert, tls_key)
            self.tls_ctx = ctx
        self._lock = threading.Lock()
        self._active = 0
        self._served = 0
        self._rng = random.Random()
        self._stop = threading.Event()
        self._tcp = None
        self._udp = None

    # -- bookkeeping used by the handler ------------------------------------
    def _enter(self):
        with self._lock:
            self._active += 1

    def _leave(self):
        with self._lock:
            self._active -= 1

    def _before_serve(self):
        with self._lock:
            if self.die_after and self._served >= self.die_after:
                self.audit.log("SENDER_CRASH_INJECTED", sender=self.id, served=self._served)
                os._exit(1)  # simulate a hard crash (fault injection for demos/tests)
            self._served += 1

    def _maybe_corrupt(self, data):
        if self.corrupt_rate and self._rng.random() < self.corrupt_rate:
            buf = bytearray(data)
            buf[self._rng.randrange(len(buf))] ^= 0xFF
            self.audit.log("CORRUPTION_INJECTED", sender=self.id)
            return bytes(buf)
        return data

    def _throttle(self, nbytes):
        if self.throttle_kbps:
            time.sleep(nbytes / (self.throttle_kbps * 1024))

    # -- lifecycle ------------------------------------------------------------
    def start(self):
        self._tcp = _Server((self.host, self.tcp_port), _Handler, self)
        self.tcp_port = self._tcp.server_address[1]
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((self.host, self.discovery_port))
        self._udp.settimeout(0.5)
        threading.Thread(target=self._tcp.serve_forever, daemon=True).start()
        threading.Thread(target=self._udp_loop, daemon=True).start()
        self.audit.log("SENDER_STARTED", sender=self.id, tcp_port=self.tcp_port,
                       discovery_port=self.discovery_port, tls=bool(self.tls_ctx))

    def stop(self):
        self._stop.set()
        if self._tcp:
            self._tcp.shutdown()
            self._tcp.server_close()
        if self._udp:
            self._udp.close()

    # -- discovery ----------------------------------------------------------
    def _udp_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._on_discover(json.loads(data), addr)
            except (ValueError, OSError, TypeError):
                continue

    def _on_discover(self, msg, addr):
        if not isinstance(msg, dict) or msg.get("type") != "DISCOVER":
            return
        if not P.verify(msg, self.secret):
            self.audit.log("DISCOVER_REJECTED", reason="bad mac", peer=addr[0])
            return
        if not P.is_fresh(msg):
            self.audit.log("DISCOVER_REJECTED", reason="stale timestamp", peer=addr[0])
            return
        name = msg.get("filename")
        entry = self.index.lookup(name) if isinstance(name, str) else None
        if entry is None:
            return
        with self._lock:
            load = self._active
        offer = P.sign({"type": "OFFER", "sender_id": self.id, "filename": name,
                        "size": entry["size"], "sha256": entry["sha256"],
                        "tcp_port": self.tcp_port, "load": load,
                        "tls": bool(self.tls_ctx), "nonce": msg.get("nonce"),
                        "ts": time.time()}, self.secret)
        self._udp.sendto(json.dumps(offer).encode(), addr)
        self.audit.log("OFFER_SENT", sender=self.id, file=name, peer=addr[0])


def main(argv=None):
    ap = argparse.ArgumentParser(description="DFT sender")
    ap.add_argument("--dir", required=True, help="directory of files to share")
    ap.add_argument("--port", type=int, required=True, help="TCP port for chunk transfer")
    ap.add_argument("--discovery-port", type=int, default=P.DEFAULT_DISCOVERY_PORT)
    ap.add_argument("--secret", default=os.environ.get("DFT_SECRET", P.DEFAULT_SECRET))
    ap.add_argument("--id", default=None, help="sender id (default sender-<port>)")
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    ap.add_argument("--audit-log", help="write JSON-lines audit log here")
    ap.add_argument("--throttle-kbps", type=int, default=0, help="[demo] limit speed")
    ap.add_argument("--corrupt-rate", type=float, default=0.0, help="[demo] corrupt this fraction of chunks")
    ap.add_argument("--die-after", type=int, default=0, help="[demo] crash after serving N chunks")
    a = ap.parse_args(argv)

    sender = Sender(a.dir, a.port, a.discovery_port, a.secret, sender_id=a.id,
                    throttle_kbps=a.throttle_kbps, corrupt_rate=a.corrupt_rate,
                    die_after=a.die_after, tls_cert=a.tls_cert, tls_key=a.tls_key,
                    audit=AuditLog(a.audit_log, echo=True))
    sender.start()
    print("READY", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sender.stop()


if __name__ == "__main__":
    main()
