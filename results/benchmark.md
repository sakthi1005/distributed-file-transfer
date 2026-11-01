# Scheduling benchmark (150 chunks, 7 trials per cell, median)

Simulated senders driving the real `Scheduler`; times are scheduling effects only.

| Scenario | Strategy | Success | Median time (s) | CRC failures | Wasted duplicates | Quarantined |
|---|---|---|---|---|---|---|
| uniform | static | 100% | 0.383 | 0 | 0 | - |
| uniform | baseline | 100% | 0.392 | 0 | 3 | - |
| uniform | smart | 100% | 0.386 | 0 | 0.4 | - |
| heterogeneous | static | 100% | 2.224 | 0 | 0 | - |
| heterogeneous | baseline | 100% | 0.446 | 0 | 3.4 | - |
| heterogeneous | smart | 100% | 0.44 | 0 | 1.7 | - |
| straggler | static | 100% | 9.267 | 0 | 0 | - |
| straggler | baseline | 100% | 0.47 | 0 | 3.1 | - |
| straggler | smart | 100% | 0.47 | 0 | 1.1 | - |
| degrading | static | 100% | 1.912 | 0 | 0 | - |
| degrading | baseline | 100% | 0.381 | 0 | 3 | - |
| degrading | smart | 100% | 0.378 | 0 | 0.9 | - |
| always-corrupt | static | 0% | FAILED | 4 | 0 | - |
| always-corrupt | baseline | 100% | 0.522 | 3 | 2.4 | bad |
| always-corrupt | smart | 100% | 0.514 | 2 | 0.3 | bad |
| glitchy-fast | static | 100% | 0.457 | 1.6 | 0 | - |
| glitchy-fast | baseline | 100% | 0.334 | 2.1 | 2.7 | glitchy |
| glitchy-fast | smart | 100% | 0.342 | 2.6 | 0.9 | - |
| crash | static | 0% | FAILED | 0 | 0 | - |
| crash | baseline | 100% | 0.477 | 0 | 2 | - |
| crash | smart | 100% | 0.474 | 0 | 0.1 | - |
