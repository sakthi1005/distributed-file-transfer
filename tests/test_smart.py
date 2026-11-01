import random
import unittest

from dft.scheduler import Scheduler
from dft.smart import CorruptionSPRT, SpeedModel


class SPRTTests(unittest.TestCase):
    def test_new_sender_quarantined_after_two_failures(self):
        s = CorruptionSPRT()
        s.observe(True)
        self.assertFalse(s.faulty)
        s.observe(True)
        self.assertTrue(s.faulty)

    def test_clean_history_tolerates_isolated_glitches(self):
        s = CorruptionSPRT()
        for _ in range(500):
            for _ in range(60):
                s.observe(False)
            s.observe(True)               # one glitch per 60 chunks (~1.6%)
            self.assertFalse(s.faulty)

    def test_always_corrupt_sender_is_flagged_fast(self):
        s = CorruptionSPRT()
        n = 0
        while not s.faulty:
            s.observe(True)
            n += 1
        self.assertLessEqual(n, 2)


class SpeedModelTests(unittest.TestCase):
    def test_mean_and_sampling(self):
        m = SpeedModel()
        for x in (0.1, 0.1, 0.1, 0.1):
            m.update(x)
        self.assertAlmostEqual(m.mean, 0.1)
        self.assertAlmostEqual(m.sample(random.Random(1), 9.9), 0.1, places=3)

    def test_unknown_sender_uses_prior(self):
        self.assertEqual(SpeedModel().sample(random.Random(1), 0.05), 0.05)


class SmartSchedulerTests(unittest.TestCase):
    def test_glitchy_but_mostly_good_sender_is_not_quarantined(self):
        s = Scheduler(2000, strategy="smart", seed=1)
        s.register("A")
        s.register("B")
        for i in range(300):
            idx = s.next_chunk("A")
            if i % 40 == 39:
                s.fail(idx, "A", "crc", crc=True)
            else:
                s.complete(idx, "A", 10, 0.01)
        self.assertFalse(s.senders["A"].quarantined)

    def test_baseline_quarantines_the_same_glitchy_sender(self):
        s = Scheduler(2000, strategy="baseline", strike_limit=3)
        s.register("A")
        s.register("B")
        for i in range(300):
            idx = s.next_chunk("A")
            if i % 40 == 39:
                s.fail(idx, "A", "crc", crc=True)
            else:
                s.complete(idx, "A", 10, 0.01)
        self.assertTrue(s.senders["A"].quarantined)

    def _two_senders(self, now):
        s = Scheduler(1, strategy="smart", seed=1, clock=lambda: now[0])
        s.register("fast")
        s.register("slow")
        for _ in range(5):
            s.senders["fast"].speed.update(0.01)
            s.senders["slow"].speed.update(0.5)
        return s

    def test_smart_endgame_skips_pointless_duplicate(self):
        now = [0.0]
        s = self._two_senders(now)
        self.assertEqual(s.next_chunk("fast"), 0)        # fast holds the last chunk
        with s.cv:
            self.assertIsNone(s._endgame_pick("slow"))   # slow would only waste a copy

    def test_smart_endgame_rescues_chunk_stuck_on_slow_sender(self):
        now = [0.0]
        s = self._two_senders(now)
        with s.cv:                                       # slow holds the last chunk, 1 s in
            s.pending.popleft()
            s._assign(0, "slow")
            now[0] = 1.0
            self.assertEqual(s._endgame_pick("fast"), 0)  # fast duplicates it

    def test_tail_gate_keeps_last_chunk_from_slow_sender(self):
        now = [0.0]
        s = self._two_senders(now)
        with s.cv:
            self.assertTrue(s._tail_gated("slow"))
            self.assertFalse(s._tail_gated("fast"))
            now[0] = 5.0                                 # gate always lapses: no stalls
            self.assertFalse(s._tail_gated("slow"))


if __name__ == "__main__":
    unittest.main()
