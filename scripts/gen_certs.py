"""Generate a self-signed TLS certificate for the senders (needs the openssl CLI).

    python scripts/gen_certs.py            # writes certs/cert.pem and certs/key.pem
"""
import subprocess
from pathlib import Path

out = Path(__file__).resolve().parent.parent / "certs"
out.mkdir(exist_ok=True)
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(out / "key.pem"), "-out", str(out / "cert.pem"),
                "-days", "365", "-subj", "/CN=dft-sender"], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(f"wrote {out/'cert.pem'} and {out/'key.pem'}")
