"""
Pydantic schemas for agentproof.

Defines the deterministic data models used to anchor every execution
block in the Merkle chain and to produce verifiable audit evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field, field_serializer

from .hasher import canonical_json, sha256_digest, blake3_digest


class PolicyContext(BaseModel):
    """Policy check that governed this execution."""

    policy_hash: str = Field(..., description="Hash of the applied policy document")
    guard_verdict: str = Field(..., description="ALLOWED / DENIED / APPROVAL")
    risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Risk score 0.0–1.0")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PolicyContext:
        return cls(**data)


class InvocationRecord(BaseModel):
    """The tool call that was executed."""

    tool_name: str = Field(..., description="Name of the tool invoked")
    params_digest: str = Field(..., description="SHA-256 of canonicalized params")
    result_digest: str = Field(..., description="SHA-256 of the serialized result")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InvocationRecord:
        return cls(**data)


class TelemetryRecord(BaseModel):
    """Execution telemetry for observability."""

    tokens_consumed: int = Field(0, ge=0, description="Tokens used by the agent")
    latency_ms: float = Field(0.0, ge=0.0, description="Wall-clock latency in ms")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TelemetryRecord:
        return cls(**data)


class ExecutionBlock(BaseModel):
    """A single Proof-of-Execution block — the ledger entry.

    Schema invariance is enforced by construction: every field is typed and
    serialized deterministically via :func:`canonical_bytes`.
    """

    version: str = "1.0.0"
    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="UUIDv4 identifier")
    prev_hash: str = "0" * 64
    timestamp_ns: int = Field(default_factory=lambda: int(datetime.now(timezone.utc).timestamp() * 1e9))
    agent_id: str = Field(..., description="Agent that produced this block")
    policy_context: PolicyContext = Field(default_factory=PolicyContext)
    invocation: InvocationRecord = Field(default_factory=InvocationRecord)
    telemetry: TelemetryRecord = Field(default_factory=TelemetryRecord)
    merkle_root: str = Field(..., description="Merkle root of this block (single-leaf tree)")
    signature: str = Field(..., description="Ed25519 signature of the Merkle root")

    @field_serializer("policy_context")
    def _serialize_policy(self, v: PolicyContext) -> Dict[str, Any]:
        return v.to_dict()

    @field_serializer("invocation")
    def _serialize_invocation(self, v: InvocationRecord) -> Dict[str, Any]:
        return v.to_dict()

    @field_serializer("telemetry")
    def _serialize_telemetry(self, v: TelemetryRecord) -> Dict[str, Any]:
        return v.to_dict()

    def canonical_bytes(self) -> bytes:
        """Serialize this block to canonical bytes (for hashing and signing)."""
        return canonical_json(self.model_dump())

    def sha256(self) -> str:
        return sha256_digest(self.canonical_bytes())

    def blake3(self) -> str:
        return blake3_digest(self.canonical_bytes())

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExecutionBlock:
        return cls(**data)
