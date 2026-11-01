"""Helpers for tests and demos: spawn senders as subprocesses, make test files."""
from __future__ import annotations

import random
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def free_tcp_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_file(path, size: int, seed: int = 1) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(random.Random(seed).randbytes(size))
    return path


class SenderProc:
    def __init__(self, proc, tcp_port, discovery_port):
        self.proc, self.tcp_port, self.discovery_port = proc, tcp_port, discovery_port

    @property
    def target(self):
        return ("127.0.0.1", self.discovery_port)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.proc.stdout:
            self.proc.stdout.close()


def spawn_sender(directory, secret, sender_id, throttle_kbps=0, corrupt_rate=0.0,
                 die_after=0, tls_cert=None, tls_key=None) -> SenderProc:
    tcp, udp = free_tcp_port(), free_udp_port()
    cmd = [sys.executable, "-m", "dft.sender", "--dir", str(directory), "--port", str(tcp),
           "--discovery-port", str(udp), "--secret", secret, "--id", sender_id]
    if throttle_kbps:
        cmd += ["--throttle-kbps", str(throttle_kbps)]
    if corrupt_rate:
        cmd += ["--corrupt-rate", str(corrupt_rate)]
    if die_after:
        cmd += ["--die-after", str(die_after)]
    if tls_cert:
        cmd += ["--tls-cert", str(tls_cert), "--tls-key", str(tls_key)]
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    if "READY" not in (proc.stdout.readline() or ""):
        proc.kill()
        raise RuntimeError(f"sender {sender_id} failed to start")
    return SenderProc(proc, tcp, udp)
