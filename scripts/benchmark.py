"""Compare scheduling strategies on simulated senders.

    python scripts/benchmark.py            # ~2 minutes, writes results/benchmark.{md,json,png}
    python scripts/benchmark.py --quick    # fewer trials

Strategies
  static    original design: chunks pre-split across senders, retry on the same sender, no failover
  baseline  pull-based scheduler, 3-strike quarantine, duplicate any chunk in the endgame
  smart     pull-based + Thompson-sampling endgame/tail gating + SPRT quarantine

This drives the real ``Scheduler`` class with threads that sleep instead of using the
network, so the numbers isolate *scheduling* behaviour. They are not network benchmarks.
"""
import argparse
import json
import random
import statistics
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dft.scheduler import Scheduler  # noqa: E402

CHUNKS = 150


@dataclass
class Spec:
    name: str
    ms: float                    # mean seconds-per-chunk in ms
    corrupt_p: float = 0.0
    die_after: int = None        # crash after serving this many chunks
    slow_after: int = None       # becomes 10x slower after this many chunks

    def chunk_time(self, served, rng):
        t = self.ms / 1000 * rng.uniform(0.8, 1.2)
        if self.slow_after is not None and served >= self.slow_after:
            t *= 10
        return t


SCENARIOS = {
    "uniform":      [Spec("a", 10), Spec("b", 10), Spec("c", 10), Spec("d", 10)],
    "heterogeneous": [Spec("a", 5), Spec("b", 10), Spec("c", 20), Spec("d", 60)],
    "straggler":    [Spec("a", 8), Spec("b", 8), Spec("c", 8), Spec("d", 250)],
    "degrading":    [Spec("a", 8), Spec("b", 8), Spec("c", 8), Spec("d", 8, slow_after=15)],
    "always-corrupt": [Spec("a", 10), Spec("b", 10), Spec("c", 10), Spec("bad", 10, corrupt_p=1.0)],
    "glitchy-fast": [Spec("a", 12), Spec("b", 12), Spec("c", 12), Spec("glitchy", 4, corrupt_p=0.03)],
    "crash":        [Spec("a", 10), Spec("b", 10), Spec("c", 10), Spec("d", 10, die_after=12)],
}


def run_pull(strategy, specs, seed):
    sched = Scheduler(CHUNKS, strategy=strategy, seed=seed)
    for s in specs:
        sched.register(s.name)

    def worker(spec, wseed):
        rng, served = random.Random(wseed), 0
        while True:
            idx = sched.next_chunk(spec.name)
            if idx is None:
                return
            if spec.die_after is not None and served >= spec.die_after:
                sched.fail(idx, spec.name, "crash", crc=False, count=False)
                sched.mark_dead(spec.name, "crash")
                return
            t = spec.chunk_time(served, rng)
            time.sleep(t)
            if rng.random() < spec.corrupt_p:
                sched.fail(idx, spec.name, "crc", crc=True)
            else:
                sched.complete(idx, spec.name, 1, t)
                served += 1

    t0 = time.perf_counter()
    threads = [threading.Thread(target=worker, args=(s, seed * 100 + i), daemon=True)
               for i, s in enumerate(specs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return {"time": time.perf_counter() - t0, "ok": sched.done(),
            "crc_failures": sched.counters["crc_failures"],
            "duplicates": sched.counters["endgame_duplicates"],
            "quarantined": sorted(n for n, s in sched.senders.items() if s.quarantined)}


def run_static(specs, seed):
    """Original-design behaviour computed analytically: sender i owns chunks i, i+n, ...; a corrupt chunk is
    retried on the same sender up to 3 times; a crash or exhausted retries fails the transfer."""
    rng, n = random.Random(seed), len(specs)
    finish, ok, crc = 0.0, True, 0
    for i, spec in enumerate(specs):
        t_total, served = 0.0, 0
        for _ in range(len(range(i, CHUNKS, n))):
            if spec.die_after is not None and served >= spec.die_after:
                ok = False
                break
            for attempt in range(4):
                t_total += spec.chunk_time(served, rng)
                if rng.random() >= spec.corrupt_p:
                    served += 1
                    break
                crc += 1
            else:
                ok = False
                break
        finish = max(finish, t_total)
    return {"time": finish, "ok": ok, "crc_failures": crc, "duplicates": 0, "quarantined": []}


def draw(results, out):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib not installed: skipping chart)")
        return
    fig, ax = plt.subplots(figsize=(11, 4.8))
    scens, w = list(results), 0.27
    for k, (strat, color) in enumerate((("static", "#9aa5b1"), ("baseline", "#4a7fb5"), ("smart", "#e07b39"))):
        vals = [results[s][strat]["median_time_s"] or 0.0 for s in scens]
        ax.bar([i + (k - 1) * w for i in range(len(scens))], vals, w, label=strat, color=color)
        for i, s in enumerate(scens):
            if results[s][strat]["median_time_s"] is None:
                ax.text(i + (k - 1) * w, 0.3, "FAILED", ha="center", rotation=90, fontsize=8, color="red")
    ax.set_yscale("log")
    ax.set_xticks(range(len(scens)))
    ax.set_xticklabels(scens, rotation=20)
    ax.set_ylabel("median completion time (s, log scale)")
    ax.set_title("Completion time by scheduling strategy (lower is better)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "benchmark.png", dpi=140)
    print("chart:", out / "benchmark.png")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--chart-only", action="store_true", help="redraw the chart from results/benchmark.json")
    a = ap.parse_args()
    if a.chart_only:
        out = Path(__file__).resolve().parent.parent / "results"
        draw(json.loads((out / "benchmark.json").read_text()), out)
        return
    trials = 3 if a.quick else 7
    results = {}
    for scen, specs in SCENARIOS.items():
        results[scen] = {}
        for strat in ("static", "baseline", "smart"):
            runs = [run_static(specs, s) if strat == "static" else run_pull(strat, specs, s)
                    for s in range(1, trials + 1)]
            ok = [r for r in runs if r["ok"]]
            results[scen][strat] = {
                "success_rate": len(ok) / len(runs),
                "median_time_s": round(statistics.median(r["time"] for r in ok), 3) if ok else None,
                "crc_failures": round(statistics.mean(r["crc_failures"] for r in runs), 1),
                "duplicates": round(statistics.mean(r["duplicates"] for r in runs), 1),
                "quarantined": sorted({q for r in runs for q in r["quarantined"]}),
            }
        print(f"done: {scen}", flush=True)

    out = Path(__file__).resolve().parent.parent / "results"
    out.mkdir(exist_ok=True)
    (out / "benchmark.json").write_text(json.dumps(results, indent=2))

    lines = [f"# Scheduling benchmark ({CHUNKS} chunks, {trials} trials per cell, median)\n",
             "Simulated senders driving the real `Scheduler`; times are scheduling effects only.\n",
             "| Scenario | Strategy | Success | Median time (s) | CRC failures | Wasted duplicates | Quarantined |",
             "|---|---|---|---|---|---|---|"]
    for scen, row in results.items():
        for strat, r in row.items():
            t = "FAILED" if r["median_time_s"] is None else r["median_time_s"]
            lines.append(f"| {scen} | {strat} | {int(r['success_rate']*100)}% | {t} | "
                         f"{r['crc_failures']} | {r['duplicates']} | {', '.join(r['quarantined']) or '-'} |")
    (out / "benchmark.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))

    draw(results, out)


if __name__ == "__main__":
    main()
