from __future__ import annotations
import time

class UDPCongestionController:
    def __init__(self, initial_window: int = 32, max_window: int = 4096) -> None:
        self.cwnd = float(initial_window)
        self.max_window = float(max_window)
        self.in_flight = 0
        self.rtt = 0.1
        self.sent = {}

    def can_send(self) -> bool:
        return self.in_flight < self.cwnd

    def on_send(self, seq: int) -> None:
        self.in_flight += 1
        self.sent[seq] = time.monotonic()

    def on_ack(self, seq: int) -> None:
        start = self.sent.pop(seq, None)
        if start is not None:
            sample = time.monotonic() - start
            self.rtt = self.rtt * 0.875 + sample * 0.125
        self.in_flight = max(0, self.in_flight - 1)
        self.cwnd = min(self.max_window, self.cwnd + 1.0 / max(self.cwnd, 1))

    def on_loss(self) -> None:
        self.cwnd = max(2.0, self.cwnd / 2)
