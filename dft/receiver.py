"""Receiver: discovers senders, schedules chunks, verifies and assembles the file.

Run:  python -m dft.receiver file.bin --targets 127.0.0.1:5001,127.0.0.1:5002
      python -m dft.receiver file.bin            # LAN: UDP broadcast discovery
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import protocol as P
from .auditlog import AuditLog
from .integrity import crc32, sha256_file
from .scheduler import Scheduler
from .state import TransferState

EXIT_OK, EXIT_NO_SENDERS, EXIT_INCOMPLETE, EXIT_INTEGRITY, EXIT_CONFLICT = 0, 1, 2, 3, 4


@dataclass
class ReceiverConfig:
    filename: str
    out_dir: str = "downloads"
    targets: Optional[list] = None          # [(host, port)]; None = LAN broadcast
    discovery_port: int = P.DEFAULT_DISCOVERY_PORT
    secret: str = P.DEFAULT_SECRET
    discover_timeout: float = 1.5
    chunk_size: int = P.DEFAULT_CHUNK_SIZE
    max_retries: int = 3
    strike_limit: int = 3
    max_reconnects: int = 2
    io_timeout: float = 5.0
    tls_ca: Optional[str] = None
    save_every: int = 16
    progress: bool = False
    strategy: str = "smart"                 # "smart" or "baseline" (see dft/smart.py)


@dataclass
class TransferResult:
    success: bool
    exit_code: int
    message: str
    path: Optional[str] = None
    report: dict = field(default_factory=dict)


# ----------------------------------------------------------------- discovery
def discover(cfg: ReceiverConfig, audit: AuditLog) -> dict:
    nonce = uuid.uuid4().hex
    targets = cfg.targets or [("255.255.255.255", cfg.discovery_port)]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.1)

    def send():
        msg = P.sign({"type": "DISCOVER", "filename": cfg.filename,
                      "nonce": nonce, "ts": time.time()}, cfg.secret)
        for target in targets:
            try:
                sock.sendto(json.dumps(msg).encode(), target)
            except OSError as exc:
                audit.log("DISCOVER_SEND_ERROR", target=str(target), error=str(exc))

    start = time.time()
    send()
    audit.log("DISCOVER_SENT", file=cfg.filename, targets=len(targets))
    resent = False
    offers = {}
    while time.time() - start < cfg.discover_timeout:
        if not resent and time.time() - start > cfg.discover_timeout / 2:
            send()  # UDP is lossy: one retransmission
            resent = True
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        try:
            msg = json.loads(data)
            if msg.get("type") != "OFFER" or msg.get("nonce") != nonce:
                continue
            if not P.verify(msg, cfg.secret):
                audit.log("OFFER_REJECTED", reason="bad mac", peer=addr[0])
                continue
            if not P.is_fresh(msg):
                audit.log("OFFER_REJECTED", reason="stale", peer=addr[0])
                continue
            offer = {"sender_id": str(msg["sender_id"]), "host": addr[0],
                     "tcp_port": int(msg["tcp_port"]), "size": int(msg["size"]),
                     "sha256": str(msg["sha256"]), "load": int(msg.get("load", 0)),
                     "tls": bool(msg.get("tls"))}
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        offers[offer["sender_id"]] = offer
    sock.close()
    return offers


def select_quorum(offers: dict):
    """Group offers by (sha256, size); the largest group wins. A tie is ambiguous."""
    groups = defaultdict(list)
    for o in offers.values():
        groups[(o["sha256"], o["size"])].append(o)
    ranked = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    if len(ranked) > 1 and len(ranked[0][1]) == len(ranked[1][1]):
        return None, [o for g in groups.values() for o in g]
    best_key, best = ranked[0]
    rejected = [o for k, g in ranked[1:] for o in g]
    return (best_key, best), rejected


# ------------------------------------------------------------------ transfer
class _Transfer:
    def __init__(self, cfg, audit, sha, size, offers, part_path, state, verified):
        self.cfg, self.audit, self.sha, self.size = cfg, audit, sha, size
        self.offers, self.state = offers, state
        self.num_chunks = -(-size // cfg.chunk_size)
        self.sched = Scheduler(self.num_chunks, verified, cfg.max_retries,
                               cfg.strike_limit, audit=audit, strategy=cfg.strategy)
        self.part_path = part_path
        self.fh = open(part_path, "r+b")
        self.fh_lock = threading.Lock()
        self.save_lock = threading.Lock()
        self.since_save = 0
        self.ctx = None
        if cfg.tls_ca:
            self.ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cfg.tls_ca)
            self.ctx.check_hostname = False  # self-signed LAN cert; pinned by CA file
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    def _connect(self, offer):
        raw = socket.create_connection((offer["host"], offer["tcp_port"]),
                                       timeout=self.cfg.io_timeout)
        sock = raw
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.ctx:
                sock = self.ctx.wrap_socket(raw)
            sock.settimeout(self.cfg.io_timeout)
            sock.sendall(b'{"op":"PING"}\n')
            status, *_ = P.unpack_header(P.recv_exact(sock, P.HEADER.size))
            if status != P.STATUS_OK:
                raise P.ProtocolError("ping failed")
            return sock
        except BaseException:
            sock.close()
            raise

    def _fetch(self, sock, offset, length):
        req = {"op": "GET", "file": self.cfg.filename, "offset": offset, "length": length}
        sock.sendall(json.dumps(req).encode() + b"\n")
        status, hoff, hlen, hcrc = P.unpack_header(P.recv_exact(sock, P.HEADER.size))
        if status != P.STATUS_OK:
            raise P.ProtocolError(f"sender returned status {status}")
        if hoff != offset or hlen != length:
            raise P.ProtocolError("unexpected frame")
        data = P.recv_exact(sock, length)
        return data, crc32(data) == hcrc

    def _write(self, offset, data):
        with self.fh_lock:
            self.fh.seek(offset)
            self.fh.write(data)

    def _save_state(self, force=False):
        with self.save_lock:
            self.since_save += 1
            if force or self.since_save >= self.cfg.save_every:
                self.since_save = 0
                with self.fh_lock:
                    self.fh.flush()
                    os.fsync(self.fh.fileno())
                self.state.save(self.sha, self.size, self.cfg.chunk_size,
                                self.sched.snapshot_verified())

    def _worker(self, offer):
        sid, cs = offer["sender_id"], self.cfg.chunk_size
        sock, reconnects = None, 0
        try:
            while True:
                if sock is None:
                    try:
                        sock = self._connect(offer)
                        self.audit.log("SENDER_CONNECTED", sender=sid)
                    except (OSError, EOFError, P.ProtocolError) as exc:
                        self.sched.mark_dead(sid, f"connect failed: {exc}")
                        return
                idx = self.sched.next_chunk(sid)
                if idx is None:
                    return
                offset = idx * cs
                length = min(cs, self.size - offset)
                self.audit.log("CHUNK_ASSIGNED", chunk=idx, sender=sid)
                t0 = time.perf_counter()
                try:
                    data, crc_ok = self._fetch(sock, offset, length)
                except (OSError, EOFError, P.ProtocolError) as exc:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    sock = None
                    self.audit.log("SENDER_IO_ERROR", chunk=idx, sender=sid, error=str(exc))
                    self.sched.fail(idx, sid, f"io error: {exc}", crc=False, count=False)
                    reconnects += 1
                    if reconnects > self.cfg.max_reconnects:
                        self.sched.mark_dead(sid, "too many connection errors")
                        return
                    continue
                elapsed = time.perf_counter() - t0
                if not crc_ok:
                    self.audit.log("CRC_FAIL", chunk=idx, sender=sid)
                    self.sched.fail(idx, sid, "crc mismatch", crc=True, count=True)
                    continue
                self._write(offset, data)
                first = self.sched.complete(idx, sid, length, elapsed)
                self.audit.log("CHUNK_VERIFIED", chunk=idx, sender=sid, duplicate=not first)
                self._save_state()
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    def run(self):
        for o in self.offers:
            self.sched.register(o["sender_id"])
        threads = [threading.Thread(target=self._worker, args=(o,), daemon=True)
                   for o in self.offers]
        for t in threads:
            t.start()
        while any(t.is_alive() for t in threads):
            time.sleep(0.2)
            if self.cfg.progress:
                done, total = self.sched.progress()
                print(f"\r  progress: {done}/{total} chunks", end="", flush=True)
        if self.cfg.progress:
            print()
        with self.fh_lock:
            self.fh.flush()
            os.fsync(self.fh.fileno())
            self.fh.close()


def run_transfer(cfg: ReceiverConfig, audit: Optional[AuditLog] = None) -> TransferResult:
    out = Path(cfg.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    own_audit = audit is None
    audit = audit or AuditLog(out / f"{cfg.filename}.audit.jsonl")
    try:
        return _run(cfg, audit, out)
    finally:
        if own_audit:
            audit.close()


def _run(cfg, audit, out) -> TransferResult:
    t_start = time.time()
    offers = discover(cfg, audit)
    if not offers:
        audit.log("TRANSFER_FAILED", reason="no senders responded")
        return TransferResult(False, EXIT_NO_SENDERS, "no senders responded")

    quorum, rejected = select_quorum(offers)
    for o in rejected:
        audit.log("SENDER_REJECTED", sender=o["sender_id"], reason="content hash mismatch")
    if quorum is None:
        audit.log("TRANSFER_FAILED", reason="senders disagree and there is no majority")
        return TransferResult(False, EXIT_CONFLICT,
                              "senders disagree about the file and there is no majority")
    (sha, size), group = quorum

    eligible = []
    for o in group:
        if bool(cfg.tls_ca) != o["tls"]:
            audit.log("SENDER_REJECTED", sender=o["sender_id"], reason="TLS mismatch")
            continue
        audit.log("SENDER_JOINED", sender=o["sender_id"], host=o["host"],
                  port=o["tcp_port"], load=o["load"])
        eligible.append(o)
    if not eligible:
        return TransferResult(False, EXIT_NO_SENDERS, "no eligible senders (TLS mismatch?)")

    final_path = out / cfg.filename
    part_path = out / f"{cfg.filename}.part"
    state = TransferState(out / f"{cfg.filename}.state.json")

    if size == 0:
        final_path.write_bytes(b"")
        return TransferResult(True, EXIT_OK, "empty file created", str(final_path))

    verified = state.load(sha, size, cfg.chunk_size)
    if verified and part_path.exists() and part_path.stat().st_size == size:
        audit.log("TRANSFER_RESUMED", verified_chunks=len(verified))
    else:
        verified = set()
        with open(part_path, "wb") as fh:
            fh.truncate(size)
        audit.log("TRANSFER_STARTED", size=size, chunk_size=cfg.chunk_size)
    resumed = len(verified)

    tr = _Transfer(cfg, audit, sha, size, eligible, part_path, state, verified)
    tr.run()
    sched = tr.sched
    duration = time.time() - t_start
    report = _build_report(cfg, sha, size, tr.num_chunks, resumed, duration, sched)

    if not sched.done():
        state.save(sha, size, cfg.chunk_size, sched.snapshot_verified())
        reason = sched.aborted or "workers stopped early"
        audit.log("TRANSFER_PAUSED", reason=reason, verified=len(sched.verified))
        _write_report(out, cfg.filename, report)
        return TransferResult(False, EXIT_INCOMPLETE,
                              f"incomplete: {reason}; state saved, re-run to resume",
                              report=report)

    actual = sha256_file(part_path)
    if actual != sha:
        part_path.unlink(missing_ok=True)
        state.clear()
        audit.log("FILE_HASH_MISMATCH", expected=sha, actual=actual)
        return TransferResult(False, EXIT_INTEGRITY,
                              "final SHA-256 mismatch; partial file deleted", report=report)

    os.replace(part_path, final_path)
    state.clear()
    audit.log("FILE_VERIFIED", sha256=sha, bytes=size, duration_s=round(duration, 3))
    _write_report(out, cfg.filename, report)
    return TransferResult(True, EXIT_OK, "transfer complete, SHA-256 verified",
                          str(final_path), report)


def _build_report(cfg, sha, size, chunks, resumed, duration, sched):
    senders = {sid: {"chunks": st.chunks, "bytes": st.bytes,
                     "throughput_mbps": round(st.ewma_bps * 8 / 1e6, 2),
                     "mean_chunk_ms": round(st.speed.mean * 1000, 2),
                     "crc_failures": st.crc_failures, "io_errors": st.io_errors,
                     "quarantined": st.quarantined, "dead": st.dead, "reason": st.reason}
               for sid, st in sched.senders.items()}
    fetched = max(0, chunks - resumed)
    return {"file": cfg.filename, "strategy": cfg.strategy, "sha256": sha, "size": size,
            "chunks": chunks,
            "chunk_size": cfg.chunk_size, "resumed_chunks": resumed,
            "fetched_chunks": fetched, "duration_s": round(duration, 3),
            "avg_mbps": round(size * 8 / 1e6 / duration, 2) if duration > 0 else 0,
            "counters": dict(sched.counters), "senders": senders}


def _write_report(out, filename, report):
    (Path(out) / f"{filename}.report.json").write_text(json.dumps(report, indent=2))


def format_report(res: TransferResult) -> str:
    r = res.report
    lines = [("OK  " if res.success else "FAIL") + " " + res.message]
    if r:
        lines.append(f"    {r['size']} bytes in {r['chunks']} chunks, {r['duration_s']}s "
                     f"({r['avg_mbps']} Mbit/s), resumed chunks: {r['resumed_chunks']}")
        c = r["counters"]
        lines.append(f"    crc failures: {c['crc_failures']}, requeues: {c['requeues']}, "
                     f"endgame duplicates: {c['endgame_duplicates']}")
        for sid, s in r["senders"].items():
            flag = " [QUARANTINED]" if s["quarantined"] else " [DEAD]" if s["dead"] else ""
            lines.append(f"    {sid:<14} chunks={s['chunks']:<5} "
                         f"{s['throughput_mbps']:>8} Mbit/s  crc_fail={s['crc_failures']}{flag}")
    return "\n".join(lines)


def _parse_targets(text):
    out = []
    for item in text.split(","):
        host, _, port = item.strip().rpartition(":")
        out.append((host, int(port)))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="DFT receiver")
    ap.add_argument("filename", help="name of the file to fetch from the senders")
    ap.add_argument("--out", default="downloads")
    ap.add_argument("--targets", help="host:port,host:port (unicast discovery); default LAN broadcast")
    ap.add_argument("--discovery-port", type=int, default=P.DEFAULT_DISCOVERY_PORT)
    ap.add_argument("--secret", default=os.environ.get("DFT_SECRET", P.DEFAULT_SECRET))
    ap.add_argument("--chunk-size", type=int, default=P.DEFAULT_CHUNK_SIZE)
    ap.add_argument("--discover-timeout", type=float, default=1.5)
    ap.add_argument("--tls-ca", help="sender certificate to trust; enables TLS")
    ap.add_argument("--strategy", choices=["smart", "baseline"], default="smart",
                    help="smart = Thompson-sampling endgame + SPRT quarantine (default)")
    a = ap.parse_args(argv)
    cfg = ReceiverConfig(a.filename, a.out, _parse_targets(a.targets) if a.targets else None,
                         a.discovery_port, a.secret, a.discover_timeout, a.chunk_size,
                         tls_ca=a.tls_ca, progress=sys.stdout.isatty(), strategy=a.strategy)
    res = run_transfer(cfg)
    print(format_report(res))
    return res.exit_code


if __name__ == "__main__":
    sys.exit(main())
