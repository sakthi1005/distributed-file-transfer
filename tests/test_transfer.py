"""End-to-end tests: real senders (subprocesses) + in-process receiver over loopback."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from dft.devtools import ROOT, make_file, spawn_sender
from dft.receiver import (EXIT_CONFLICT, EXIT_INCOMPLETE, EXIT_NO_SENDERS, EXIT_OK,
                          ReceiverConfig, run_transfer)

SECRET, NAME, CHUNK, SIZE = "test-secret", "data.bin", 64 * 1024, 2 * 1024 * 1024


class Base(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="dft-test-"))
        self.good, self.bad, self.out = self.work / "good", self.work / "bad", self.work / "out"
        make_file(self.good / NAME, SIZE, seed=1)
        make_file(self.bad / NAME, SIZE, seed=2)
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            p.stop()
        shutil.rmtree(self.work, ignore_errors=True)

    def sender(self, sid, directory=None, **kw):
        p = spawn_sender(directory or self.good, SECRET, sid, **kw)
        self.procs.append(p)
        return p

    def receive(self, senders, secret=SECRET, **kw):
        cfg = ReceiverConfig(NAME, str(self.out), [p.target for p in senders], secret=secret,
                             chunk_size=CHUNK, discover_timeout=0.8, **kw)
        return run_transfer(cfg)

    def events(self):
        path = self.out / f"{NAME}.audit.jsonl"
        return [json.loads(l)["event"] for l in path.read_text().splitlines()]

    def assertIdentical(self):
        self.assertEqual((self.out / NAME).read_bytes(), (self.good / NAME).read_bytes())


class TransferTests(Base):
    def test_three_senders_share_the_work(self):
        ps = [self.sender(f"s{i}") for i in range(3)]
        res = self.receive(ps)
        self.assertEqual(res.exit_code, EXIT_OK, res.message)
        self.assertIdentical()
        self.assertEqual(sum(s["chunks"] for s in res.report["senders"].values()) >= 32, True)
        self.assertFalse((self.out / f"{NAME}.part").exists())

    def test_slow_sender_serves_fewer_chunks(self):
        fast, slow = self.sender("fast"), self.sender("slow", throttle_kbps=1500)
        res = self.receive([fast, slow])
        self.assertTrue(res.success, res.message)
        s = res.report["senders"]
        self.assertGreater(s["fast"]["chunks"], s["slow"]["chunks"])

    def test_corrupting_sender_is_quarantined_baseline(self):
        bad, ok = self.sender("bad", corrupt_rate=1.0), self.sender("ok", throttle_kbps=4000)
        res = self.receive([bad, ok], strategy="baseline")
        self.assertTrue(res.success, res.message)
        self.assertIdentical()
        self.assertTrue(res.report["senders"]["bad"]["quarantined"])
        self.assertEqual(res.report["counters"]["crc_failures"], 3)   # 3 strikes
        self.assertIn("SENDER_QUARANTINED", self.events())

    def test_corrupting_sender_is_quarantined_smart(self):
        bad, ok = self.sender("bad", corrupt_rate=1.0), self.sender("ok", throttle_kbps=4000)
        res = self.receive([bad, ok], strategy="smart")
        self.assertTrue(res.success, res.message)
        self.assertIdentical()
        self.assertTrue(res.report["senders"]["bad"]["quarantined"])
        self.assertLessEqual(res.report["counters"]["crc_failures"], 3)  # SPRT: never slower than 3 strikes
        self.assertIn("SENDER_QUARANTINED", self.events())

    def test_sender_crash_midway_fails_over(self):
        crashy, ok = self.sender("crashy", die_after=3), self.sender("ok", throttle_kbps=4000)
        res = self.receive([crashy, ok])
        self.assertTrue(res.success, res.message)
        self.assertIdentical()
        self.assertTrue(res.report["senders"]["crashy"]["dead"])
        self.assertIn("SENDER_DEAD", self.events())

    def test_rogue_sender_with_different_content_is_rejected(self):
        a, b = self.sender("a"), self.sender("b")
        rogue = self.sender("rogue", directory=self.bad)
        res = self.receive([a, b, rogue])
        self.assertTrue(res.success, res.message)
        self.assertIdentical()
        self.assertNotIn("rogue", res.report["senders"])
        self.assertIn("SENDER_REJECTED", self.events())

    def test_two_disagreeing_senders_is_ambiguous(self):
        res = self.receive([self.sender("a"), self.sender("r", directory=self.bad)])
        self.assertEqual(res.exit_code, EXIT_CONFLICT)
        self.assertFalse((self.out / NAME).exists())

    def test_wrong_secret_gets_no_offers(self):
        res = self.receive([self.sender("a")], secret="wrong")
        self.assertEqual(res.exit_code, EXIT_NO_SENDERS)

    def test_interrupted_transfer_resumes(self):
        res1 = self.receive([self.sender("crashy", die_after=10)])
        self.assertEqual(res1.exit_code, EXIT_INCOMPLETE, res1.message)
        self.assertTrue((self.out / f"{NAME}.state.json").exists())
        self.assertFalse((self.out / NAME).exists())
        res2 = self.receive([self.sender("healthy")])
        self.assertTrue(res2.success, res2.message)
        self.assertEqual(res2.report["resumed_chunks"], 10)
        self.assertEqual(res2.report["fetched_chunks"], SIZE // CHUNK - 10)
        self.assertIdentical()
        self.assertFalse((self.out / f"{NAME}.state.json").exists())
        self.assertIn("TRANSFER_RESUMED", self.events())

    def test_tls_end_to_end(self):
        cert, key = self.work / "cert.pem", self.work / "key.pem"
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=test"], check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("openssl not available")
        ps = [self.sender(f"t{i}", tls_cert=cert, tls_key=key) for i in range(2)]
        res = self.receive(ps, tls_ca=str(cert))
        self.assertTrue(res.success, res.message)
        self.assertIdentical()

    def test_receiver_requiring_tls_rejects_plaintext_sender(self):
        cert = self.work / "cert.pem"
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(self.work / "k.pem"), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=test"], check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("openssl not available")
        res = self.receive([self.sender("plain")], tls_ca=str(cert))
        self.assertEqual(res.exit_code, EXIT_NO_SENDERS)


if __name__ == "__main__":
    unittest.main()
