"""Learned components used by the 'smart' scheduling strategy (standard library only).

These are classical online-statistics methods, not deep learning:

SpeedModel       Welford online mean/variance of seconds-per-chunk for one sender.
                 ``sample()`` draws from the posterior of the mean (Thompson sampling),
                 so uncertain senders are explored instead of being trusted blindly.

CorruptionSPRT   Wald's Sequential Probability Ratio Test on "was this chunk corrupt?".
                 H0: sender corrupts with probability p0 (healthy, ~1%)
                 H1: sender corrupts with probability p1 (faulty, ~25%)
                 Every good chunk lowers the evidence, every bad chunk raises it. A sender
                 with a long clean record tolerates a rare glitch; a sender that corrupts
                 repeatedly is quarantined after ~2 failures.
"""
from __future__ import annotations

import math


class SpeedModel:
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self._m2 = 0.0

    def update(self, seconds: float) -> None:
        self.n += 1
        d = seconds - self.mean
        self.mean += d / self.n
        self._m2 += d * (seconds - self.mean)

    def sample(self, rng, prior_mean: float) -> float:
        """Thompson sample of this sender's seconds-per-chunk."""
        if self.n == 0:
            return prior_mean
        var = self._m2 / (self.n - 1) if self.n > 1 else (0.5 * self.mean) ** 2
        sd = math.sqrt(max(var, 0.0) / self.n)
        return max(1e-6, rng.gauss(self.mean, sd))


class CorruptionSPRT:
    def __init__(self, p_healthy=0.01, p_faulty=0.25, alpha=0.01, beta=0.10):
        self.on_bad = math.log(p_faulty / p_healthy)
        self.on_good = math.log((1 - p_faulty) / (1 - p_healthy))   # negative
        self.upper = math.log((1 - beta) / alpha)                    # accept H1 (faulty)
        self.lower = math.log(beta / (1 - alpha))                    # accept H0, floor
        self.llr = 0.0

    def observe(self, corrupt: bool) -> None:
        self.llr += self.on_bad if corrupt else self.on_good
        self.llr = max(self.lower, self.llr)   # clean history earns bounded credit only

    @property
    def faulty(self) -> bool:
        return self.llr >= self.upper
