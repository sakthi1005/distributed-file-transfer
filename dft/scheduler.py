"""Pull-based chunk scheduler with failover, sender quarantine and endgame mode.

Each sender has one worker thread that calls ``next_chunk`` whenever it is idle,
so faster senders naturally receive more chunks (dynamic load balancing).

Chunk life cycle:   PENDING -> IN_FLIGHT -> VERIFIED
                       ^____________|   (failure: re-queued, preferably to a
                                         *different* sender)
"""
from __future__ import annotations

import random
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .smart import CorruptionSPRT, SpeedModel


@dataclass
class SenderStats:
    chunks: int = 0
    bytes: int = 0
    ewma_bps: float = 0.0
    strikes: int = 0
    crc_failures: int = 0
    io_errors: int = 0
    quarantined: bool = False
    dead: bool = False
    reason: str = ""
    speed: SpeedModel = field(default_factory=SpeedModel)
    sprt: CorruptionSPRT = field(default_factory=CorruptionSPRT)

    @property
    def healthy(self) -> bool:
        return not (self.quarantined or self.dead)


class Scheduler:
    EWMA_ALPHA = 0.3
    TAIL_SLOW_FACTOR = 3.0     # smart: a sender this many times slower than the best is gated in the tail
    MAX_GATE_S = 2.0           # smart: gating always lapses so it can never stall a transfer

    def __init__(self, num_chunks, verified=(), max_retries=3, strike_limit=3,
                 endgame_threshold=4, audit=None, strategy="baseline", seed=None,
                 clock=time.monotonic):
        if strategy not in ("baseline", "smart"):
            raise ValueError("strategy must be 'baseline' or 'smart'")
        self.strategy = strategy
        self.rng = random.Random(seed)
        self.clock = clock
        self.started: dict = {}
        self._gate_since: dict = {}
        self.cv = threading.Condition()
        self.num_chunks = num_chunks
        self.verified = set(verified)
        self.pending = deque(i for i in range(num_chunks) if i not in self.verified)
        self.in_flight: dict[int, set] = {}
        self.failures: dict[int, int] = defaultdict(int)
        self.failed_on: dict[int, set] = defaultdict(set)
        self.senders: dict[str, SenderStats] = {}
        self.max_retries = max_retries
        self.strike_limit = strike_limit
        self.endgame_threshold = endgame_threshold
        self.audit = audit
        self.aborted = None
        self.counters = {"crc_failures": 0, "requeues": 0, "endgame_duplicates": 0}

    # ------------------------------------------------------------------ helpers
    def _log(self, event, **kw):
        if self.audit:
            self.audit.log(event, **kw)

    def _healthy_ids(self):
        return {sid for sid, st in self.senders.items() if st.healthy}

    def _can_serve(self, idx, sid):
        """Avoid re-trying a chunk on a sender that already failed it, unless
        every healthy sender has failed it (then retrying is the only option)."""
        eligible = self._healthy_ids() - self.failed_on[idx]
        return sid in eligible or not eligible

    def _check_exhausted(self):
        if not self.done() and not self._healthy_ids() and not self.aborted:
            self.aborted = "no healthy senders remaining"
            self._log("TRANSFER_ABORTED", reason=self.aborted)

    # --------------------------------------------------------------- public API
    def register(self, sid):
        with self.cv:
            self.senders[sid] = SenderStats()

    def done(self):
        return len(self.verified) >= self.num_chunks

    def snapshot_verified(self):
        with self.cv:
            return set(self.verified)

    def progress(self):
        with self.cv:
            return len(self.verified), self.num_chunks

    def next_chunk(self, sid, wait=0.25):
        """Block until there is work for ``sid``; None means the worker should stop."""
        with self.cv:
            while True:
                if self.aborted or self.done():
                    return None
                if not self.senders[sid].healthy:
                    return None
                if not self._tail_gated(sid):
                    for _ in range(len(self.pending)):
                        idx = self.pending.popleft()
                        if self._can_serve(idx, sid):
                            self._assign(idx, sid)
                            return idx
                        self.pending.append(idx)
                idx = self._endgame_pick(sid)
                if idx is not None:
                    return idx
                self.cv.wait(wait)

    def _assign(self, idx, sid):
        self.in_flight.setdefault(idx, set()).add(sid)
        self.started[(idx, sid)] = self.clock()
        self._gate_since.pop(sid, None)

    def _fleet_mean(self):
        means = [s.speed.mean for s in self.senders.values() if s.speed.n and s.healthy]
        return sum(means) / len(means) if means else 0.05

    def _tail_gated(self, sid):
        """smart: in the tail, do not hand a chunk to a sender far slower than the best one."""
        if self.strategy != "smart":
            return False
        healthy = self._healthy_ids()
        if len(self.pending) > len(healthy):
            return False
        me = self.senders[sid].speed
        if me.n < 2:
            return False
        known = [self.senders[s].speed.mean for s in healthy if self.senders[s].speed.n >= 2]
        if not known or me.mean <= self.TAIL_SLOW_FACTOR * min(known):
            self._gate_since.pop(sid, None)
            return False
        since = self._gate_since.setdefault(sid, self.clock())
        return self.clock() - since <= self.MAX_GATE_S

    def _expected_remaining(self, idx, holder):
        m = self.senders[holder].speed.mean or self._fleet_mean()
        started = self.started.get((idx, holder))
        elapsed = 0.0 if started is None else self.clock() - started
        return m - elapsed if elapsed <= m else elapsed   # already late: expect about as long again

    def _endgame_pick(self, sid):
        """Tail latency fix: when few chunks remain, an idle sender duplicates a chunk
        that another (possibly slow) sender is still fetching.

        baseline: duplicate any in-flight chunk.
        smart:    duplicate the chunk with the longest expected remaining time, and only if
                  this sender's Thompson-sampled chunk time beats it (avoids wasted copies).
        """
        remaining = self.num_chunks - len(self.verified)
        if remaining > self.endgame_threshold:
            return None
        if self.strategy == "smart":
            best, best_rem = None, 0.0
            for idx, holders in self.in_flight.items():
                if (not holders or sid in holders or sid in self.failed_on[idx]
                        or idx in self.verified):
                    continue
                rem = min(self._expected_remaining(idx, h) for h in holders)
                if rem > best_rem:
                    best, best_rem = idx, rem
            if best is None:
                return None
            mine = self.senders[sid].speed.sample(self.rng, self._fleet_mean())
            if mine >= best_rem:
                return None
            chosen = best
        else:
            if self.pending:
                return None
            chosen = None
            for idx, holders in self.in_flight.items():
                if (sid not in holders and sid not in self.failed_on[idx]
                        and idx not in self.verified):
                    chosen = idx
                    break
            if chosen is None:
                return None
        self._assign(chosen, sid)
        self.counters["endgame_duplicates"] += 1
        self._log("ENDGAME_DUPLICATE", chunk=chosen, sender=sid)
        return chosen

    def complete(self, idx, sid, nbytes, elapsed):
        """Record a verified chunk. Returns True if this was the first copy."""
        with self.cv:
            st = self.senders[sid]
            st.chunks += 1
            st.bytes += nbytes
            bps = nbytes / max(elapsed, 1e-6)
            st.ewma_bps = bps if st.ewma_bps == 0 else (
                self.EWMA_ALPHA * bps + (1 - self.EWMA_ALPHA) * st.ewma_bps)
            st.speed.update(elapsed)
            st.sprt.observe(False)
            first = idx not in self.verified
            self.verified.add(idx)
            for h in self.in_flight.pop(idx, set()):
                self.started.pop((idx, h), None)
            self.cv.notify_all()
            return first

    def fail(self, idx, sid, reason, crc=False, count=True):
        """A fetch failed. Re-queue the chunk and update the sender's record.

        crc=True   -> corruption: counts as a strike against the sender.
        count=True -> counts toward the per-chunk retry limit (network faults
                      do not, because they are the sender's fault, not the chunk's).
        """
        with self.cv:
            st = self.senders[sid]
            holders = self.in_flight.get(idx)
            if holders:
                holders.discard(sid)
            self.started.pop((idx, sid), None)
            if idx in self.verified:
                if holders is not None and not holders:
                    self.in_flight.pop(idx, None)
                return
            self.failed_on[idx].add(sid)
            if crc:
                st.crc_failures += 1
                st.strikes += 1
                st.sprt.observe(True)
                self.counters["crc_failures"] += 1
            else:
                st.io_errors += 1
            if count:
                self.failures[idx] += 1
                if self.failures[idx] > self.max_retries and not self.aborted:
                    self.aborted = f"chunk {idx} failed {self.failures[idx]} times"
                    self._log("TRANSFER_ABORTED", reason=self.aborted)
            if not holders:
                self.in_flight.pop(idx, None)
                self.pending.appendleft(idx)
                self.counters["requeues"] += 1
                self._log("CHUNK_REQUEUED", chunk=idx, failed_sender=sid, reason=reason)
            smart_flag = self.strategy == "smart" and st.sprt.faulty
            if crc and (smart_flag or (self.strategy == "baseline"
                                       and st.strikes >= self.strike_limit)) \
                    and not st.quarantined:
                st.quarantined = True
                st.reason = (f"{st.strikes} corrupted chunks"
                             + (" (SPRT: statistically faulty)" if smart_flag else ""))
                self._log("SENDER_QUARANTINED", sender=sid, reason=st.reason)
                self._check_exhausted()
            self.cv.notify_all()

    def mark_dead(self, sid, reason):
        with self.cv:
            st = self.senders[sid]
            if not st.dead:
                st.dead = True
                st.reason = reason
                self._log("SENDER_DEAD", sender=sid, reason=reason)
            self._check_exhausted()
            self.cv.notify_all()
