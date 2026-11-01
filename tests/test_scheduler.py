import unittest

from dft.scheduler import Scheduler


class SchedulerTests(unittest.TestCase):
    def make(self, n=6, **kw):
        s = Scheduler(n, **kw)
        s.register("A")
        s.register("B")
        return s

    def test_each_chunk_assigned_once(self):
        s = self.make(4)
        got = [s.next_chunk("A") for _ in range(4)]
        self.assertEqual(sorted(got), [0, 1, 2, 3])

    def test_failed_chunk_goes_to_other_sender(self):
        s = self.make(3)
        idx = s.next_chunk("A")
        s.fail(idx, "A", "crc", crc=True)
        self.assertNotEqual(s.next_chunk("A"), idx)   # A skips the chunk it failed
        self.assertIn(idx, [s.next_chunk("B"), s.next_chunk("B")])  # B picks it up

    def test_quarantine_after_strikes(self):
        s = self.make(10, strike_limit=3)
        for _ in range(3):
            idx = s.next_chunk("A")
            s.fail(idx, "A", "crc", crc=True)
        self.assertTrue(s.senders["A"].quarantined)
        self.assertIsNone(s.next_chunk("A"))

    def test_dead_sender_chunk_is_requeued(self):
        s = self.make(2)
        idx = s.next_chunk("A")
        s.fail(idx, "A", "io", crc=False, count=False)
        s.mark_dead("A", "gone")
        self.assertEqual(s.next_chunk("B"), idx)

    def test_abort_when_all_senders_lost(self):
        s = self.make(2)
        s.mark_dead("A", "x")
        s.mark_dead("B", "x")
        self.assertEqual(s.aborted, "no healthy senders remaining")

    def test_retry_limit_aborts(self):
        s = Scheduler(1, max_retries=1)
        s.register("A")
        for _ in range(2):
            idx = s.next_chunk("A")
            s.fail(idx, "A", "crc", crc=False, count=True)
        self.assertIn("failed 2 times", s.aborted)

    def test_endgame_duplicates_last_chunk(self):
        s = self.make(1)
        self.assertEqual(s.next_chunk("A"), 0)
        self.assertEqual(s.next_chunk("B", wait=0.01), 0)   # B duplicates A's chunk
        self.assertTrue(s.complete(0, "B", 10, 0.1))
        self.assertFalse(s.complete(0, "A", 10, 0.5))        # second copy ignored


if __name__ == "__main__":
    unittest.main()
