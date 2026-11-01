"""Persistent resume state: which chunks are already verified."""
from __future__ import annotations

import json
import os
from pathlib import Path


def _to_ranges(indices):
    out, start, prev = [], None, None
    for i in sorted(indices):
        if start is None:
            start = prev = i
        elif i == prev + 1:
            prev = i
        else:
            out.append([start, prev])
            start = prev = i
    if start is not None:
        out.append([start, prev])
    return out


class TransferState:
    def __init__(self, path):
        self.path = Path(path)

    def load(self, sha256: str, size: int, chunk_size: int) -> set:
        """Return verified chunk indices, or an empty set if state is absent/mismatched."""
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return set()
        if (data.get("sha256"), data.get("size"), data.get("chunk_size")) != (sha256, size, chunk_size):
            return set()
        verified = set()
        for a, b in data.get("verified_ranges", []):
            verified.update(range(a, b + 1))
        return verified

    def save(self, sha256: str, size: int, chunk_size: int, verified) -> None:
        payload = {"sha256": sha256, "size": size, "chunk_size": chunk_size,
                   "verified_ranges": _to_ranges(verified)}
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload))
        os.replace(tmp, self.path)

    def clear(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass
