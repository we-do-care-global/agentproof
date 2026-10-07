"""agentproof — cryptographic Proof-of-Execution (PoE) engine."""

__version__ = "1.0.0"
__author__ = "Emir Perla"
__email__ = "emirperla96@gmail.com"

from .hasher import (
    canonical_json,
    sha256_digest,
    blake3_digest,
    hash_bytes,
    hash_hex,
)
from .models import (
    PolicyContext,
    InvocationRecord,
    TelemetryRecord,
    ExecutionBlock,
)
from .merkle import MerkleTree, KeyPair
from .notary import AgentProofNotary

__all__ = [
    "canonical_json",
    "sha256_digest",
    "blake3_digest",
    "hash_bytes",
    "hash_hex",
    "PolicyContext",
    "InvocationRecord",
    "TelemetryRecord",
    "ExecutionBlock",
    "MerkleTree",
    "KeyPair",
    "AgentProofNotary",
    "__version__",
]
