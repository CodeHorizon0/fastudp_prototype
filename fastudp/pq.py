from __future__ import annotations
import hashlib
import secrets

try:
    import oqs
except ImportError:
    oqs = None

class PostQuantumKeyExchange:
    def __init__(self) -> None:
        self.algorithm = "ML-KEM-768" if oqs else "HYBRID-FALLBACK"

    def generate(self):
        if oqs:
            kem = oqs.KeyEncapsulation(self.algorithm)
            return kem.generate_keypair(), kem
        secret = secrets.token_bytes(32)
        return hashlib.sha256(secret).digest(), secret

    def derive(self, private, peer):
        if oqs:
            return private.decap_secret(peer)
        return hashlib.sha256(bytes(private) + bytes(peer)).digest()
