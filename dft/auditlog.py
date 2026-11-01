"""Thread-safe JSON-lines audit log."""
from __future__ import annotations

import json
import sys
import threading
from collections import Counter
from datetime import datetime, timezone


class AuditLog:
    def __init__(self, path=None, echo: bool = False):
        self._fh = open(path, "a", encoding="utf-8") if path else None
        self._echo = echo
        self._lock = threading.Lock()
        self.counts: Counter = Counter()

    def log(self, event: str, **fields) -> None:
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
               "event": event, **fields}
        line = json.dumps(rec, separators=(",", ":"), default=str)
        with self._lock:
            self.counts[event] += 1
            if self._fh:
                self._fh.write(line + "\n")
                self._fh.flush()
            if self._echo:
                print(line, file=sys.stderr, flush=True)

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None
