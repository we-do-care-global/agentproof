"""
The `AgentProofNotary` class managing the chain state.

Responsibilities:
  * Initialise with an Ed25519 private key.
  * Track the current `prev_hash` (starts as `"0" * 64`).
  * Append blocks, compute Merkle roots, sign, and emit verifiable proof packages.
  * Provide a lightweight disk-backed ring buffer for audit persistence.
"""

import json
import os
import threading
from typing import Any, Dict, List, Optional

from .hasher import canonical_json, sha256_digest
from .merkle import KeyPair, MerkleTree
from .models import ExecutionBlock

DEFAULT_PREV_HASH = "0" * 64


class AgentProofNotary:
    """Asynchronous, zero-blocking PoE logger.

    The entry point ``record_execution`` computes digests and appends blocks
    without blocking the caller's dispatch loop. All cryptographic work is
    synchronous but bounded (single-block), so the blocking window is
    sub-millisecond on modern hardware.
    """

    def __init__(
        self,
        agent_id: str,
        private_key: Optional[KeyPair] = None,
        chain_file: Optional[str] = None,
        reset_chain: bool = False,
    ):
        self.agent_id = agent_id
        self.merkle_tree = MerkleTree()
        self._lock = threading.Lock()
        self.chain_file = chain_file or os.path.expanduser("~/.agentproof/chain.jsonl")

        if private_key is None:
            self._keys = KeyPair.generate()
        else:
            self._keys = private_key

        if reset_chain:
            self.merkle_tree = MerkleTree()
            self._prev_hash = DEFAULT_PREV_HASH
            self._load_chain()
            self._persist_chain()
        else:
            self._prev_hash = DEFAULT_PREV_HASH
            self._load_chain()

    def _load_chain(self) -> None:
        """Replay a persisted chain from disk into an in-memory Merkle tree."""
        if self.chain_file and os.path.exists(self.chain_file):
            with open(self.chain_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        block = ExecutionBlock.from_dict(obj)
                        self.merkle_tree.push(block.blake3())
                        self._prev_hash = block.sha256()
                    except Exception:
                        continue

    def _persist_chain(self) -> None:
        """Append the current chain to disk (JSON Lines)."""
        os.makedirs(os.path.dirname(self.chain_file) or ".", exist_ok=True)
        with open(self.chain_file, "a", encoding="utf-8") as fh:
            for leaf in self.merkle_tree.leaves:
                fh.write(json.dumps({"merkle_root": leaf}) + "\n")

    @property
    def public_key(self) -> KeyPair:
        return self._keys

    def record_execution(
        self,
        *,
        agent_id: str,
        tool_name: str,
        params_digest: str,
        params_payload: Any,
        result_payload: Any,
        tokens: int = 0,
        latency_ms: float = 0.0,
        policy_hash: str = "0" * 64,
        guard_verdict: str = "ALLOWED",
        risk_score: float = 0.0,
    ) -> Dict[str, Any]:
        """Append a new ExecutionBlock (sync, non-blocking entrypoint)."""
        # Canonical digests of the called params and returned result.
        params_bytes = canonical_json({"tool": tool_name, "params": params_payload})
        result_bytes = canonical_json({"result": result_payload})
        params_digest_actual = sha256_digest(params_bytes)
        result_digest_actual = sha256_digest(result_bytes)

        from datetime import datetime
        block = ExecutionBlock(
            agent_id=agent_id or self.agent_id,
            prev_hash=self._prev_hash,
            timestamp_ns=int(datetime.now().timestamp() * 1e9),
            policy_context={
                "policy_hash": policy_hash,
                "guard_verdict": guard_verdict,
                "risk_score": risk_score,
            },
            invocation={
                "tool_name": tool_name,
                "params_digest": params_digest_actual,
                "result_digest": result_digest_actual,
            },
            telemetry={"tokens_consumed": tokens, "latency_ms": latency_ms},
            merkle_root="",
            signature="",
        )

        # In a tree of one leaf, the Merkle root IS the leaf hash.
        leaf_hash = block.blake3()
        root = self.merkle_tree.push(leaf_hash)
        block.merkle_root = root

        # Sign the Merkle root with the notary's Ed25519 key.
        signed = self._keys.sign(root.encode("ascii"))
        block.signature = signed

        # Update the chain head.
        self._prev_hash = block.sha256()

        proof = self.merkle_tree.proof_of_inclusion(
            self.merkle_tree.leaves.index(leaf_hash)
        )
        proof["root"] = root

        return {
            "execution_id": block.execution_id,
            "block": block.to_dict(),
            "merkle_root": root,
            "signature": signed,
            "proof": proof,
            "chain_tip": self._prev_hash,
        }

    def verify_chain(self, expected_root: str) -> Dict[str, Any]:
        """Independent verifier: validates the chain and returns a verdict."""
        leaves = self.merkle_tree.leaves
        if not leaves:
            return {"valid": True, "reason": "empty chain, nothing to verify"}

        # Rebuild the expected root from the ledger.
        rebuilt = "0" * 64
        for leaf in leaves:
            rebuilt = sha256_digest((rebuilt + leaf).encode("ascii"))

        valid = rebuilt == expected_root
        return {
            "valid": valid,
            "chain_length": len(leaves),
            "expected_root": expected_root,
            "actual_root": rebuilt,
            "leaves": leaves,
            "reason": "chain matches" if valid else f"expected {expected_root}, got {rebuilt}",
        }
