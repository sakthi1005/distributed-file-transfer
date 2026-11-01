# Distributed File Transfer System

A fault-tolerant, multi-source file transfer system for a LAN. One **receiver** discovers several
**senders** over UDP, pulls different chunks of the same file from all of them in parallel over TCP
(optionally TLS), recovers from corrupt data and dead senders, and verifies the final file with SHA-256.

Pure Python standard library (3.9+). No installation needed.

## What this adds over the original design

| Area | Original design | This implementation |
|---|---|---|
| Discovery | UDP broadcast, anyone can answer | HMAC-signed DISCOVER/OFFER with nonce and timestamp; offers carry size, SHA-256 and load |
| Wrong versions | not handled | Senders grouped by file hash; the **majority** wins, others are rejected |
| Chunk assignment | static | **Pull-based work queue**: fast senders automatically serve more chunks |
| Corrupt chunk | abort whole transfer | **Re-queue to a different sender**, retry limit, sender **quarantined** after 3 strikes |
| Sender dies | transfer fails | Detected by timeout/disconnect; its chunks are re-queued (**failover**) |
| Slow tail | one slow sender delays the end | **Endgame mode**: last chunks are duplicated on idle senders |
| Integrity | CRC-32 only | CRC-32 per chunk **and** SHA-256 for the whole file |
| Interruption | start over | **Resume** from a state file of verified chunks |
| Transport | plain TCP | Optional **TLS**; a TLS-requiring receiver refuses plaintext senders |
| Logging | simple | Structured **JSON-lines audit log** and a JSON transfer report |

## Architecture

```
                        UDP: DISCOVER (signed) ───────────────►  Sender 1 ─┐
 ┌──────────────── RECEIVER ───────────────┐  ◄─────── OFFER ────  Sender 2 ─┤ each sender:
 │ discover → quorum (hash majority)       │                       Sender 3 ─┘  Discovery responder
 │ Scheduler (work queue, strikes, endgame)│                                    File index (SHA-256)
 │ Worker threads, one per sender ─────────┼── TCP/TLS: GET chunk ─►            Chunk server
 │ Verifier (CRC-32 / SHA-256)  Assembler  │  ◄─ header + payload ──
 │ State store (resume)   Audit logger     │
 └─────────────────────────────────────────┘
```

Source layout:

```
dft/protocol.py    wire format, HMAC signing, exact-length socket reads
dft/sender.py      discovery responder + threaded TCP/TLS chunk server + fault injection flags
dft/receiver.py    discovery, quorum, workers, assembly, final verification, CLI
dft/scheduler.py   chunk state machine, failover, quarantine, endgame mode
dft/state.py       resume state (verified chunk ranges, atomic writes)
dft/integrity.py   CRC-32 and SHA-256
dft/auditlog.py    JSON-lines audit log
dft/devtools.py    helpers for tests/demos
scripts/demo.py    one-command demos      scripts/gen_certs.py   TLS certificate
dft/smart.py       learned components: Thompson-sampling speed model, SPRT corruption detector
scripts/benchmark.py  strategy comparison -> results/benchmark.{md,json,png}
tests/             28 tests (unit + end-to-end over loopback)
```

## Protocol

**Discovery (UDP, JSON).** `DISCOVER {filename, nonce, ts, mac}` is broadcast. A sender with the file
replies `OFFER {sender_id, size, sha256, tcp_port, load, tls, nonce, ts, mac}`. `mac` is
HMAC-SHA256 over the canonical JSON using the shared secret. Messages with a bad MAC or a timestamp
older than 30 s are ignored, and the receiver only accepts offers echoing its own nonce. The DISCOVER
is sent twice because UDP is lossy.

**Transfer (TCP, optionally TLS).** Request is one JSON line (`PING` or `GET file offset length`).
The response is a 21-byte header followed by the payload:

```
| magic "DFTP" 4B | status 1B | offset 8B | length 4B | crc32 4B | payload ... |
```

TCP is a byte stream, so the receiver reads exactly `length` bytes (`recv_exact`) and checks the
offset/length echo before trusting the frame.

## Scheduling and fault tolerance

- A chunk is `PENDING → IN_FLIGHT → VERIFIED`. Each sender has a worker that pulls the next pending
  chunk when idle, so throughput decides who does the work; per-sender throughput is tracked as an EWMA.
- **CRC mismatch**: chunk is discarded and re-queued, and avoided on that sender while other healthy
  senders exist. Quarantine rule depends on the strategy (`--strategy smart|baseline`, default `smart`):
  baseline = 3 strikes; smart = SPRT statistical test (see "Learned components"). A chunk may fail at most
  `max_retries` (3) times before the transfer pauses.
- **Network failure**: the worker reconnects up to twice, then the sender is marked dead and its chunk
  goes back to the queue. Network faults are not counted against the chunk's retry budget.
- **No healthy senders left**: the receiver saves its state and exits with code 2 (resumable).
- **Endgame**: when ≤ 4 chunks remain and none are pending, idle senders duplicate in-flight chunks;
  the first verified copy wins.

## Integrity and security layers

| Layer | Mechanism | Protects against |
|---|---|---|
| Chunk | CRC-32 | accidental corruption in transit |
| File | SHA-256 vs. the majority-agreed hash | wrong/mixed versions, assembly bugs |
| Transport | TLS 1.2+ (optional) | eavesdropping, tampering |
| Discovery | HMAC + nonce + timestamp | rogue or replayed discovery messages |

CRC-32 is **not** a security feature; it only detects accidents. Tampering is covered by SHA-256
and TLS.

## Quick start (one machine)

```bash
python scripts/demo.py normal     # 3 healthy senders
python scripts/demo.py mixed      # slow senders serve fewer chunks
python scripts/demo.py corrupt    # corrupting sender gets quarantined
python scripts/demo.py crash      # sender dies mid-transfer, others finish
python scripts/demo.py rogue      # tampered copy is rejected by hash quorum
python scripts/demo.py resume     # crash, then resume with only the missing chunks
python scripts/demo.py tls        # TLS end to end (needs the openssl command)
python -m unittest discover -s tests -t .
python scripts/benchmark.py       # ~2 min: static vs baseline vs smart, writes results/
```

## Learned components (`--strategy smart`, the default)

These are classical online-statistics methods implemented with the standard library, not deep learning.
Integrity checks (CRC-32, SHA-256) are never replaced by a model.

1. **Speed model + Thompson sampling.** Each sender's seconds-per-chunk is tracked online (Welford mean
   and variance). When only a few chunks remain, an idle sender duplicates an in-flight chunk **only if**
   its sampled chunk time beats the holder's expected remaining time. Senders much slower than the best
   (>3x) are not handed tail chunks (this gate always lapses after 2 s, so it cannot stall a transfer).
2. **SPRT corruption detector** (Wald's sequential probability ratio test). H0: sender corrupts ~1% of
   chunks; H1: ~25%. Clean chunks lower the evidence (bounded credit), corrupt chunks raise it. A new
   sender that corrupts twice is quarantined; a sender with a long clean record survives rare glitches,
   which a fixed "3 strikes" counter would wrongly ban.

### Benchmark results (`results/benchmark.md`, `results/benchmark.png`)

150 chunks, 7 trials per cell, 4 simulated senders driving the real `Scheduler` with sleeps instead of a network.

| Finding | Evidence |
|---|---|
| **Pull-based scheduling is the big win over a static split** | straggler: 9.27 s static vs 0.47 s; heterogeneous: 2.22 s vs 0.45 s |
| Static (original design) cannot survive faults | 0% success when a sender corrupts every chunk or crashes; baseline/smart 100% |
| **Smart wastes far less work than baseline** | duplicated chunks per run: uniform 3.0 -> 0.4, straggler 3.1 -> 1.1, crash 2.0 -> 0.1 |
| Smart quarantines a bad sender sooner | always-corrupt: 2 corrupt chunks fetched vs 3 |
| Smart does not ban a mostly-good sender | glitchy-fast (3% corruption): baseline quarantined it; smart kept it |
| **Smart is NOT faster than baseline** | completion times are within noise in every scenario (glitchy-fast: 0.334 s baseline vs 0.342 s smart) |

Be honest about this in your viva: the learned parts reduce wasted bandwidth and false bans; they do not
shorten completion time on these workloads. The simulation measures scheduling only, not real network speed.

## Real LAN use

On each sender machine (put the file in `shared/`):

```bash
python -m dft.sender --dir shared --port 6001 --secret MY_SECRET
```

On the receiver (same LAN subnet, default discovery port 50000, UDP broadcast):

```bash
python -m dft.receiver bigfile.iso --secret MY_SECRET --out downloads
```

With TLS: run `python scripts/gen_certs.py`, copy `certs/` to every machine, start senders with
`--tls-cert certs/cert.pem --tls-key certs/key.pem` and the receiver with `--tls-ca certs/cert.pem`.

Without broadcast (e.g. same host or routed networks) pass explicit targets:
`--targets 10.0.0.5:50000,10.0.0.6:50000`. On one machine give each sender its own `--discovery-port`.

Exit codes: `0` ok, `1` no senders, `2` incomplete (resumable), `3` final hash mismatch, `4` senders disagree with no majority.

## Outputs

In the output directory: the file, `<file>.audit.jsonl`, `<file>.report.json`, and while in progress
`<file>.part` and `<file>.state.json`. Audit events include `DISCOVER_SENT`, `SENDER_JOINED`,
`SENDER_REJECTED`, `CHUNK_ASSIGNED`, `CHUNK_VERIFIED`, `CRC_FAIL`, `CHUNK_REQUEUED`,
`SENDER_QUARANTINED`, `SENDER_DEAD`, `ENDGAME_DUPLICATE`, `TRANSFER_PAUSED`, `TRANSFER_RESUMED`,
`FILE_VERIFIED`.

## Demo/fault-injection flags (sender)

`--throttle-kbps N`, `--corrupt-rate P`, `--die-after N` simulate slow links, corruption and crashes.
They exist for demonstrations and tests only.

## Known limitations (be upfront in your viva)

- Failure detection is timeout/disconnect based; there is no periodic heartbeat.
- The shared secret is a single pre-shared key: it authenticates discovery, not individual senders.
  TLS here uses one self-signed certificate that the receiver pins.
- Quorum needs at least 3 senders to out-vote a bad one; with 2 disagreeing senders the receiver refuses (exit 4).
- The file is pre-allocated (`.part`), so a huge file needs its full size free on disk.
- Chunk size is fixed per transfer (no adaptive sizing). The smart strategy needs a few chunks of history before its speed estimates mean anything. UDP broadcast works only inside one subnet.

## Possible viva questions

1. Why UDP for discovery and TCP for data? (no connection needed to ask "who has it", vs. reliability/ordering for bulk data)
2. Why is CRC-32 not enough? (not cryptographic; can't detect a different but self-consistent file)
3. What happens if a sender dies halfway? If two senders disagree? If the receiver crashes?
4. Why pull-based instead of assigning chunks up front? (heterogeneous speeds, automatic load balancing)
5. What is the endgame problem and how is it solved?
6. How do you stop a rogue host on the LAN from injecting data? (HMAC discovery, hash quorum, TLS, final SHA-256)
