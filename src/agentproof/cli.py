"""
agentproof CLI.

Usage:
    agentproof keygen --out-dir ./keys
    agentproof verify --proof-file proof.json --pubkey public.pem
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .hasher import canonical_json, sha256_digest
from .merkle import KeyPair, MerkleTree, DEFAULT_PREV_HASH
from .models import ExecutionBlock
from .notary import AgentProofNotary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentproof",
        description=(
            "agentproof — cryptographic Proof-of-Execution (PoE) engine for "
            "autonomous AI systems. Tamper-evident audit logging with "
            "Ed25519 signing and Merkle chain verification."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True, help="Subcommand")

    # keygen
    kg = sub.add_parser("keygen", help="Generate an Ed25519 key pair")
    kg.add_argument("--out-dir", default="./keys", help="Directory for the keypair files")
    kg.set_defaults(func=cmd_keygen)

    # register
    reg = sub.add_parser("register", help="Register a new agent (one-shot)")
    reg.add_argument("--agent-id", required=True, help="Agent identifier")
    reg.add_argument("--tool", default="echo", help="Tool name")
    reg.add_argument("--params", default="{}", help="JSON params payload")
    reg.add_argument("--result", default="{}", help="JSON result payload")
    reg.add_argument("--policy-hash", default="0" * 64, help="Policy hash")
    reg.add_argument("--guard-verdict", default="ALLOWED", help="Guard verdict")
    reg.add_argument("--risk-score", type=float, default=0.0, help="Risk score 0–1")
    reg.add_argument(
        "--chain-file", default=None, help="Persist chain to this JSONL file"
    )
    reg.set_defaults(func=cmd_register)

    # verify
    ver = sub.add_parser("verify", help="Verify a proof and the chain")
    ver.add_argument("--proof-file", required=True, help="Proof JSON file from `register`")
    ver.add_argument("--pubkey", required=True, help="Public key PEM/hex file")
    ver.add_argument(
        "--chain-file", default=None, help="Persist chain to this JSONL file"
    )
    ver.set_defaults(func=cmd_verify)

    # inspect
    ins = sub.add_parser("inspect", help="Inspect chain state")
    ins.add_argument("--agent-id", default="default", help="Agent identifier")
    ins.add_argument("--chain-file", default=None, help="Persist chain to this JSONL file")
    ins.set_defaults(func=cmd_inspect)

    # export-cert
    exp = sub.add_parser("export-cert", help="Export a verifiable audit certificate")
    exp.add_argument("--agent-id", required=True, help="Agent identifier")
    exp.add_argument("--pubkey", required=True, help="Public key PEM/hex file")
    exp.add_argument("--chain-file", default=None, help="Persist chain to this JSONL file")
    exp.set_defaults(func=cmd_export_cert)

    return parser


def cmd_keygen(args: argparse.Namespace) -> int:
    kp = KeyPair.generate()
    os.makedirs(args.out_dir, exist_ok=True)
    priv_path = os.path.join(args.out_dir, "private.pem")
    pub_path = os.path.join(args.out_dir, "public.pem")

    # Ed25519 public key (Raw bytes -> hex printable form)
    pub_hex = kp.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    with open(pub_path, "w", encoding="utf-8") as fh:
        fh.write(pub_hex + "\n")

    # Private key: never print in production; store raw hex for programmatic use
    priv_hex = kp.private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    ).hex()
    with open(priv_path, "w", encoding="utf-8") as fh:
        fh.write(priv_hex + "\n")

    print(f"Key pair generated.")
    print(f"  public.pem: {pub_path}")
    print(f"  private.pem: {priv_path}")
    print(f"  public key hex: {pub_hex}")
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    chain_file = args.chain_file or os.path.expanduser("~/.agentproof/chain.jsonl")
    notary = AgentProofNotary(
        agent_id=args.agent_id,
        chain_file=chain_file,
        reset_chain=False,
    )
    params = json.loads(args.params or "{}")
    result = json.loads(args.result or "{}")

    proof = notary.record_execution(
        agent_id=args.agent_id,
        tool_name=args.tool,
        params_digest=sha256_digest(canonical_json(params)),
        params_payload=params,
        result_payload=result,
        tokens=0,
        latency_ms=0.0,
        policy_hash=args.policy_hash,
        guard_verdict=args.guard_verdict,
        risk_score=args.risk_score,
    )

    out = {
        "execution_id": proof["execution_id"],
        "agent_id": args.agent_id,
        "tool": args.tool,
        "merkle_root": proof["merkle_root"],
        "signature": proof["signature"],
        "proof": proof["proof"],
        "chain_tip": proof["chain_tip"],
    }
    print(json.dumps(out, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    # Load proof
    with open(args.proof_file, "r", encoding="utf-8") as fh:
        proof = json.load(fh)

    # Load public key
    with open(args.pubkey, "r", encoding="utf-8") as fh:
        pub_hex = fh.read().strip()
    pub_bytes = bytes.fromhex(pub_hex)
    public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

    # Verify signature
    merkle_root = proof["merkle_root"].encode("ascii")
    signature = proof["signature"]
    signature_valid = public_key.verify(bytes.fromhex(signature), merkle_root)

    # Verify proof of inclusion
    merkle_tree = MerkleTree()
    merkle_tree.leaves = [proof["merkle_root"]]
    root = merkle_tree.push(proof["merkle_root"])
    proof_valid = merkle_tree.verify_proof(
        proof["merkle_root"], proof["proof"], root
    )

    # Verify chain continuity
    chain = []
    if args.chain_file and os.path.exists(args.chain_file):
        with open(args.chain_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    chain.append(json.loads(line))
    chain_valid = True
    prev_hash = DEFAULT_PREV_HASH
    for entry in chain:
        block = ExecutionBlock.from_dict(entry)
        if block.prev_hash != prev_hash:
            chain_valid = False
        prev_hash = block.sha256()

    all_valid = signature_valid and proof_valid and chain_valid
    verdict = "VERIFIED" if all_valid else "TAMPERED"
    print(json.dumps({
        "verdict": verdict,
        "signature_valid": signature_valid,
        "proof_valid": proof_valid,
        "chain_valid": chain_valid,
    }, indent=2))
    return 0 if all_valid else 1


def cmd_inspect(args: argparse.Namespace) -> int:
    chain_file = args.chain_file or os.path.expanduser("~/.agentproof/chain.jsonl")
    notary = AgentProofNotary(
        agent_id=args.agent_id,
        chain_file=chain_file,
        reset_chain=False,
    )
    print(json.dumps({
        "agent_id": notary.agent_id,
        "chain_length": len(notary.merkle_tree.leaves),
        "root": notary.merkle_tree.root,
        "prev_hash": notary._prev_hash,
    }, indent=2))
    return 0


def cmd_export_cert(args: argparse.Namespace) -> int:
    chain_file = args.chain_file or os.path.expanduser("~/.agentproof/chain.jsonl")
    notary = AgentProofNotary(
        agent_id=args.agent_id,
        chain_file=chain_file,
        reset_chain=False,
    )
    cert = {
        "version": "1.0.0",
        "agent_id": notary.agent_id,
        "chain_length": len(notary.merkle_tree.leaves),
        "merkle_root": notary.merkle_tree.root,
        "public_key_hex": notary.public_key.public_key.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        ).hex(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    out_path = os.path.join(args.out_dir or ".", "audit_certificate.json")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(cert, fh, indent=2)
    print(f"Certificate exported to {out_path}")
    print(json.dumps(cert, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
