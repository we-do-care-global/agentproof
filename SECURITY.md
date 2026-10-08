# Security Policy — AgentProof

## Supported Versions
| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability
Open a GitHub Security Advisory on `we-do-care-global/agentproof` or email `emirperla96@gmail.com`.
Please include: affected version, PoC (no live secrets), impact on chain verification.

We aim to acknowledge within 72h and patch within 14 days.

## Scope
- `src/agentproof/hasher.py` (canonical JSON, digests)
- `src/agentproof/merkle.py` (MerkleTree, Ed25519 KeyPair)
- `src/agentproof/notary.py` (chain state)
- `src/agentproof/cli.py` (keygen, register, verify, inspect, export-cert)

Out of scope: GitHub Pages docs, example keys in `keys/` (test-only, rotate before production).
