"""FastPassword cryptography.

Envelope encryption for a server-side-unlock vault:

* Each **vault** has a random 256-bit **Vault Key (VK)**. Item secret fields are
  encrypted at rest with the VK using AES-256-GCM.
* The VK is stored **sealed** to the deployment **recovery public key**
  (anonymous X25519 + HKDF + AES-GCM, libsodium-sealed-box style). The matching
  recovery *private* key lives only in the environment
  (``FASTPASSWORD_RECOVERY_KEY``), so the running server can unseal a VK after a
  user authenticates — this is the "SSO auto-unlock" model. Whoever holds the
  recovery key can decrypt every vault; guard it like a root secret and never
  commit it.
* Password health (weak / reused / old) is computed from a strength score and a
  keyed HMAC **fingerprint** stored per item — never from stored plaintext.

Losing ``FASTPASSWORD_RECOVERY_KEY`` makes every vault permanently
undecryptable. Back it up.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_SEAL_INFO = b"fastpassword-seal-v1"


# ── base64 (url-safe, unpadded) ──────────────────────────────────────────────
def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


# ── symmetric (AES-256-GCM) ──────────────────────────────────────────────────
def random_key() -> bytes:
    return os.urandom(32)


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> str:
    """Return ``nonce.ciphertext`` (both url-safe base64)."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    return f"{b64e(nonce)}.{b64e(ct)}"


def aes_decrypt(key: bytes, blob: str, aad: bytes = b"") -> bytes:
    nonce_b64, ct_b64 = blob.split(".", 1)
    return AESGCM(key).decrypt(b64d(nonce_b64), b64d(ct_b64), aad or None)


# ── asymmetric keypair + anonymous sealed box ────────────────────────────────
def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(private_raw, public_raw)`` (32 bytes each)."""
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def public_from_private(priv_raw: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv_raw).public_key().public_bytes_raw()


def _seal_key(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=_SEAL_INFO + eph_pub + recipient_pub).derive(shared)


def seal(recipient_pub: bytes, plaintext: bytes) -> str:
    """Anonymous seal to ``recipient_pub`` → ``eph_pub.nonce.ciphertext``."""
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
    key = _seal_key(shared, eph_pub, recipient_pub)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return f"{b64e(eph_pub)}.{b64e(nonce)}.{b64e(ct)}"


def unseal(recipient_priv: bytes, blob: str) -> bytes:
    eph_b64, nonce_b64, ct_b64 = blob.split(".", 2)
    eph_pub = b64d(eph_b64)
    recipient_pub = public_from_private(recipient_priv)
    shared = X25519PrivateKey.from_private_bytes(recipient_priv).exchange(
        X25519PublicKey.from_public_bytes(eph_pub))
    key = _seal_key(shared, eph_pub, recipient_pub)
    return AESGCM(key).decrypt(b64d(nonce_b64), b64d(ct_b64), None)


# ── deployment recovery key (from env) ───────────────────────────────────────
class RecoveryKeyMissing(RuntimeError):
    pass


def recovery_private() -> bytes:
    raw = os.getenv("FASTPASSWORD_RECOVERY_KEY", "").strip()
    if not raw:
        raise RecoveryKeyMissing(
            "FASTPASSWORD_RECOVERY_KEY is not set — the vault cannot be unlocked. "
            "Generate one with `python -m fastpassword.crypto genkey`.")
    key = b64d(raw)
    if len(key) != 32:
        raise RecoveryKeyMissing("FASTPASSWORD_RECOVERY_KEY must be a 32-byte url-safe base64 X25519 key.")
    return key


def recovery_public() -> bytes:
    return public_from_private(recovery_private())


def recovery_enabled() -> bool:
    try:
        recovery_private()
        return True
    except RecoveryKeyMissing:
        return False


# ── optional passphrase KDF (scrypt, stdlib) ─────────────────────────────────
def derive_kek(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


# ── password fingerprint + strength (health, no plaintext at rest) ───────────
def _pepper() -> bytes:
    return (os.getenv("FASTPASSWORD_SECRET") or "fastpassword-dev-pepper").encode()


def fingerprint(password: str) -> str:
    """Keyed HMAC of a password — lets us flag reuse without storing plaintext."""
    return hmac.new(_pepper(), password.encode(), hashlib.sha256).hexdigest()


_COMMON = {"password", "123456", "qwerty", "letmein", "admin", "welcome",
           "iloveyou", "password1", "12345678", "abc123"}


def strength(password: str) -> int:
    """A 0–100 strength estimate from length, character variety and penalties."""
    if not password:
        return 0
    if password.lower() in _COMMON:
        return 5
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32
    pool = pool or 1
    entropy = len(password) * math.log2(pool)
    score = min(100, int(entropy / 80 * 100))          # ~80 bits ≈ full marks
    if re.fullmatch(r"(.)\1*", password):              # all one character
        score = min(score, 10)
    if len(set(password)) <= 2:
        score = min(score, 20)
    return max(0, score)


def strength_label(score: int) -> str:
    if score >= 80:
        return "Strong"
    if score >= 60:
        return "Good"
    if score >= 40:
        return "Fair"
    if score >= 20:
        return "Weak"
    return "Very weak"


if __name__ == "__main__":  # `python -m fastpassword.crypto genkey`
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "genkey":
        priv, _ = generate_keypair()
        print("FASTPASSWORD_RECOVERY_KEY=" + b64e(priv))
    else:
        print("usage: python -m fastpassword.crypto genkey")
