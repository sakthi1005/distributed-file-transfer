"""One-command demos on a single machine.

    python scripts/demo.py normal      # 3 senders, healthy
    python scripts/demo.py mixed       # one slow sender: it serves fewer chunks
    python scripts/demo.py corrupt     # one sender corrupts data -> quarantined
    python scripts/demo.py crash       # one sender crashes mid-transfer
    python scripts/demo.py rogue       # one sender holds a tampered file -> rejected
    python scripts/demo.py resume      # interrupt, then resume
    python scripts/demo.py tls         # TLS + HMAC end to end (needs openssl)
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dft.devtools import make_file, spawn_sender  # noqa: E402
from dft.receiver import ReceiverConfig, format_report, run_transfer  # noqa: E402

SECRET = "demo-secret"
NAME = "data.bin"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=["normal", "mixed", "corrupt", "crash", "rogue", "resume", "tls"])
    ap.add_argument("--size-mb", type=float, default=8)
    a = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="dft-demo-"))
    good, bad, out = work / "good", work / "rogue", work / "out"
    size = int(a.size_mb * 1024 * 1024)
    make_file(good / NAME, size, seed=1)
    make_file(bad / NAME, size, seed=2)          # same name and size, different bytes
    cert = key = None
    if a.scenario == "tls":
        subprocess.run([sys.executable, str(Path(__file__).parent / "gen_certs.py")], check=True)
        root = Path(__file__).resolve().parent.parent / "certs"
        cert, key = root / "cert.pem", root / "key.pem"

    specs = {
        "normal":  [dict(), dict(), dict()],
        "mixed":   [dict(), dict(throttle_kbps=4000), dict(throttle_kbps=1000)],
        "corrupt": [dict(), dict(), dict(corrupt_rate=1.0)],
        "crash":   [dict(), dict(), dict(die_after=8)],
        "rogue":   [dict(), dict(), dict(directory=bad)],
        "resume":  [dict(die_after=12)],
        "tls":     [dict(tls_cert=cert, tls_key=key)] * 3,
    }[a.scenario]

    procs = []
    try:
        def start(specs):
            ps = []
            for i, sp in enumerate(specs, 1):
                sp = dict(sp)
                d = sp.pop("directory", good)
                ps.append(spawn_sender(d, SECRET, f"sender-{i}", **sp))
            procs.extend(ps)
            return ps

        def receive(ps):
            cfg = ReceiverConfig(NAME, str(out), [p.target for p in ps], secret=SECRET,
                                 chunk_size=64 * 1024, discover_timeout=1.0, progress=True,
                                 tls_ca=str(cert) if cert else None)
            res = run_transfer(cfg)
            print(format_report(res))
            return res

        print(f"scenario: {a.scenario}   file: {a.size_mb} MB   work dir: {work}")
        ps = start(specs)
        res = receive(ps)
        if a.scenario == "resume":
            print("\n--- sender crashed; state saved. Starting a healthy sender and resuming ---\n")
            ps = start([dict()])
            res = receive(ps)
        ok = res.success and (out / NAME).read_bytes() == (good / NAME).read_bytes()
        print("\nbyte-for-byte identical to the original:", ok)
        print(f"audit log: {out / (NAME + '.audit.jsonl')}")
    finally:
        for p in procs:
            p.stop()


if __name__ == "__main__":
    main()
