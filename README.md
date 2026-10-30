# Decision Black Box

Private research repo. A tamper-evident audit layer for human-in-the-loop decisions. It's a hash-chained, Ed25519-signed, append-only log with RFC 6962 Merkle inclusion proofs, signed checkpoints, a replay tool, and OPA policy checks before any action.

Written in **Go**: standard library only (crypto/ed25519, sha256, net/http), with no third-party packages. It builds a single static binary that can be carried onto an air-gapped network.

Full write-up: [`docs/project-page.md`](docs/project-page.md)

## What's here

| Path | Purpose |
|---|---|
| `blackbox/entry.go` | Entry format, canonical hashing, Ed25519 signing and verification |
| `blackbox/log.go` | Append-only JSONL log (fsync on every write), chain verification, signed checkpoints |
| `blackbox/merkle.go` | RFC 6962 Merkle tree with audit paths and inclusion verification |
| `blackbox/policy.go` | OPA client that **fails closed**: if the policy engine is unreachable, the action is denied |
| `policy/blackbox.rego`, `policy/data.json` | Role permissions, two-person rule for high-impact actions, confidence threshold, stale-data rule |
| `cmd/blackbox` | CLI: `keygen`, `append`, `verify`, `prove`, `replay`, `checkpoint` |

## Quickstart

```bash
make test      # go vet + race-enabled tests
make demo      # keygen -> append -> verify -> replay -> inclusion proof
opa run --server --addr :8181 policy/    # policy engine
```

## Next steps
- [ ] Keep the signing key in a YubiKey or TPM instead of a file (PKCS#11)
- [ ] Ship checkpoints every N minutes to a second machine. Hash chains prove edits, but only checkpoints prove nothing was cut off the end
- [ ] Replay mode that re-runs the OPA policy recorded in `Policy.Bundle` against the stored inputs
- [ ] HTTP API so `counter-drone-sensor-fusion` and the COP dashboard log every operator decision
- [ ] RFC 3161 timestamping (or Sigstore Rekor on a private instance) for independent time evidence
