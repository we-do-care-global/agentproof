"""
Merkle tree calculation, inclusion proofs, and Ed25519 key helpers.

Produces a tamper-evident chain where each block's ``merkle_root`` is the
hash of its canonical payload, and the whole chain is anchored by an Ed25519
signature over the root.
"""

import hashlib
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .hasher import canonical_json, sha256_digest, blake3_digest

DEFAULT_PREV_HASH = "0" * 64


class MerkleTree:
    """Minimal in-memory Merkle tree over execution blocks."""

    def __init__(self):
        self.leaves: List[str] = []
        self.root: str = "0" * 64

    @staticmethod
    def _hash_leaf(data: bytes) -> str:
        return blake3_digest(data)

    @staticmethod
    def _hash_pair(a: str, b: str) -> str:
        """Hash two hex-prefixed siblings into a parent node."""
        pair = a + b
        return blake3_digest(pair.encode("ascii"))

    def push(self, leaf: str) -> str:
        """Append a leaf (hex digest) and return the new root."""
        self.leaves.append(leaf)
        self.root = self._recompute_root()
        return self.root

    def _recompute_root(self) -> str:
        leaves = self.leaves
        if not leaves:
            return "0" * 64
        level = leaves[:]
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level) - 1, 2):
                next_level.append(self._hash_pair(level[i], level[i + 1]))
            if len(level) % 2 == 1:
                next_level.append(self._hash_pair(level[-1], level[-1]))
            level = next_level
        return level[0]

    def proof_of_inclusion(self, index: int) -> Dict[str, Any]:
        """Generate a Merkle proof of inclusion for a leaf at *index*."""
        if index < 0 or index >= len(self.leaves):
            raise IndexError("leaf index out of range")
        path: List[Dict[str, Any]] = []
        left = index == 0
        for i in range(len(self.leaves).bit_length() - 1):
            sibling = index ^ (1 << i)
            if sibling < len(self.leaves):
                sibling_hash = self.leaves[sibling]
                path.append({
                    "index": i,
                    "is_left": left,
                    "sibling": sibling_hash,
                })
            left = not left
            index >>= 1
        return {"leaf_index": self.leaves.index(self.leaves[index]), "proof": path}

    def verify_proof(self, leaf: str, proof: Dict[str, Any], root: str) -> bool:
        """Verify a Merkle proof against a claimed root."""
        target = leaf
        for step in proof["proof"]:
            sibling = step["sibling"]
            if step["is_left"]:
                target = self._hash_pair(sibling, target)
            else:
                target = self._hash_pair(target, sibling)
        return target == root


class KeyPair:
    """Ed25519 key pair for notary signing. Public key is trust-on-first-use."""

    def __init__(self, private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey):
        self._private = private_key
        self._public = public_key

    @staticmethod
    def generate() -> KeyPair:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair(private_key, public_key)

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._private

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public

    def sign(self, data: bytes) -> str:
        return self._private.sign(data).hex()

    def verify(self, signature: str, data: bytes) -> bool:
        try:
            self._public.verify(bytes.fromhex(signature), data)
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def public_bytes(public_key: Ed25519PublicKey) -> bytes:
        return public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

    def to_dict(self) -> Dict[str, str]:
        return {
            "public_key_hex": self._public.public_bytes(
                encoding=ED25519, format=ED25519
            ).hex(),
        }
