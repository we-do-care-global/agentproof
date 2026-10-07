"""
agentproof — zero-overhead cryptographic Proof-of-Execution (PoE) engine.

Standalone, tamper-evident audit logging for autonomous AI systems in the
We Do Care Global governance ecosystem.

Core invariants:
  * Deterministic (canonical) JSON serialization — sorted keys, no whitespace.
  * Merkle tree chaining — every ExecutionBlock hashes to an immutable root.
  * Ed25519 signing — each block is signed with the notary's private key.
  * Independent verification — a verifier needs no secret keys, only the public key.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

try:
    import blake3
except ImportError:  # pragma: no cover - blake3 is optional
    blake3 = None


# --------------------------------------------------------------------------- #
#  Canonical hashing
# --------------------------------------------------------------------------- #
def canonical_json(obj: Any) -> bytes:
    """Canonical deterministic UTF-8 byte stream for signatures.

    Explicitly sorts keys and strips whitespace so the same logical object
    always produces the same digest across every environment.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    """SHA-256 hex digest of arbitrary bytes."""
    return hashlib.sha256(data).hexdigest()


def blake3_digest(data: bytes) -> str:
    """BLAKE3 hex digest — falls back to SHA-256 when blake3 is unavailable."""
    if blake3 is not None:
        return blake3.blake3(data).hexdigest()
    return sha256_digest(data)


def hash_bytes(data: bytes) -> str:
    return sha256_digest(data)


def hash_hex(s: str) -> str:
    return sha256_digest(s.encode("utf-8"))
