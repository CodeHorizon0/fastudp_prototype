from __future__ import annotations
import time
from dataclasses import dataclass

@dataclass(slots=True)
class SessionControl:
    created: float
    last_activity: float
    closed: bool = False

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def close(self) -> None:
        self.closed = True
