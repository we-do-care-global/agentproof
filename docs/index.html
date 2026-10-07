# agentproof

Zero-overhead cryptographic **Proof-of-Execution (PoE)** engine for autonomous AI systems within the
We Do Care Global governance ecosystem.

Every execution block is anchored in an immutable Merkle chain and signed with Ed25519 — tamper-evident audit
logging for AgentGuard, Enterprise Hybrid-RAG, and the full WDCG governance stack.

## Key invariants

- **Deterministic serialization** — `json.dumps(obj, sort_keys=True, separators=(",", ":"))`
- **Schema invariance** — every `ExecutionBlock` carries: `version`, `execution_id`, `prev_hash`, `timestamp_ns`,
  `agent_id`, `policy_context`, `invocation`, `telemetry`, `merkle_root`, `signature`
- **Zero-latency ingestion** — `record_execution` computes digests without blocking agent dispatch loops
- **Independent verifier** — verifies the cryptographic chain and Merkle proofs without raw secrets or full payload

## Install

```bash
pip install -e .
```

## Quickstart

```bash
# 1. Generate a key pair
agentproof keygen --out-dir ./keys

# 2. Register an execution (agentguard / mix)
agentproof register \
  --agent-id agentguard \
  --tool "mix" \
  --params '{"track":"dolores-v2","sample_rate":44100}' \
  --result '{"mixdown":"dolores-v2-mono.wav","bitrate":320}' \
  --chain-file chain.jsonl

# 3. Inspect the chain
agentproof inspect --agent-id agentguard --chain-file chain.jsonl
```

## CLI

| Command | Description |
|---|---|
| `keygen --out-dir ./keys` | Generate an Ed25519 keypair |
| `register` | Run one execution record and append it to the chain |
| `verify --proof-file proof.json --pubkey public.pem` | Independently verify a proof + chain |
| `inspect --agent-id <id> --chain-file <file>` | Show chain state |
| `export-cert --agent-id <id> --out-dir <dir>` | Export a verifiable audit certificate |

## Architecture

```
src/agentproof/
├── hasher.py        Canonical JSON + SHA-256/BLAKE3 digests
├── models.py        Pydantic schemas (PolicyContext, InvocationRecord, TelemetryRecord, ExecutionBlock)
├── merkle.py        MerkleTree + Ed25519 KeyPair
├── notary.py        AgentProofNotary chain state
└── cli.py           Click/Typer CLI (keygen, register, verify, inspect, export-cert)
```

## Compliance mapping

- **EU AI Act Article 12** — automatic logging of events throughout the AI system's lifecycle
- **FDA 21 CFR Part 11** — cryptographic audit trail with tamper-evident signatures
- **NIST AI RMF** — govern, map, measure, manage evidence chain

## License

Apache-2.0
