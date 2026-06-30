from __future__ import annotations

import hashlib
import hmac
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .constants import MAX_CLOCK_SKEW, REPLAY_WINDOW


class TokenBucket:
    def __init__(self, rate: float, burst: float) -> None:
        self.rate = float(rate)
        self.burst = float(burst)
        self.tokens = float(burst)
        self.updated = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        current = time.monotonic()
        elapsed = current - self.updated
        self.updated = current
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class ReplayWindow:
    __slots__ = ("highest", "bitmap")

    def __init__(self) -> None:
        self.highest = -1
        self.bitmap = 0

    def accept(self, seq: int) -> bool:
        if seq < 0:
            return False
        if self.highest == -1:
            self.highest = seq
            self.bitmap = 1
            return True
        if seq > self.highest:
            shift = seq - self.highest
            if shift >= REPLAY_WINDOW:
                self.bitmap = 1
            else:
                self.bitmap = (self.bitmap << shift) | 1
                self.bitmap &= (1 << REPLAY_WINDOW) - 1
            self.highest = seq
            return True
        delta = self.highest - seq
        if delta >= REPLAY_WINDOW:
            return False
        bit = 1 << delta
        if self.bitmap & bit:
            return False
        self.bitmap |= bit
        return True


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def mac(key: bytes, *parts: object) -> bytes:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    first = True
    for part in parts:
        if not first:
            digest.update(b"|")
        first = False
        if isinstance(part, bytes):
            digest.update(part)
        else:
            digest.update(str(part).encode("utf-8"))
    return digest.digest()


def now_ts() -> int:
    return int(time.time())


def ts_ok(ts: int, skew: int = MAX_CLOCK_SKEW) -> bool:
    return abs(int(time.time()) - int(ts)) <= skew


def ticket_key(psk: bytes) -> bytes:
    return hkdf_expand(hkdf_extract(b"fastudp-ticket-salt", psk), b"fastudp-ticket-key", 32)


def seal_ticket(psk: bytes, payload: bytes) -> bytes:
    key = ticket_key(psk)
    nonce = hashlib.sha256(b"fastudp-ticket-nonce" + payload + psk).digest()[:12]
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, payload, b"fastudp-ticket-aad")


def open_ticket(psk: bytes, ticket: bytes) -> bytes:
    if len(ticket) < 12 + 16:
        raise ValueError("ticket too small")
    key = ticket_key(psk)
    nonce = ticket[:12]
    cipher = ticket[12:]
    return ChaCha20Poly1305(key).decrypt(nonce, cipher, b"fastudp-ticket-aad")


def derive_session_key(psk: bytes, client_id: str, cnonce: bytes, snonce: bytes) -> bytes:
    prk = hkdf_extract(snonce + cnonce, psk)
    info = b"fastudp-session|" + client_id.encode("utf-8") + b"|" + cnonce + b"|" + snonce
    return hkdf_expand(prk, info, 32)
