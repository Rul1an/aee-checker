# aee-checker

An independent validity-gate checker for the **Adversarial Execution Evidence (AEE)** in-toto predicate (v0.6, [in-toto/attestation#570](https://github.com/in-toto/attestation/pull/570)), implemented **from the specification text alone**: the four byte-pure stage-one validity steps (statement well-formedness, coverage validity, the result recompute, digest integrity) plus the trust-relative evidence tier, run against the [astrogilda/aee-conformance](https://github.com/astrogilda/aee-conformance) vector corpus.

**Result: 125/125 parity** (34/34 accepts including result tokens, 91/91 rejects) on the first full corpus run, with no vector-driven fixes. [PARITY-REPORT.md](PARITY-REPORT.md) carries the score, the eleven interpretation decisions the spec text forced, and the from-spec discipline attestation listing exactly what was and was not read. [NOTES.md](NOTES.md) compares the vendored spec against the branch-head spec (byte-identical).

No dependency on the reference implementation: this crate carries its own strict I-JSON parser, RFC 8785 canonicalization with ECMAScript number formatting, RFC 6962 domain-separated Merkle root over DSSE PAE bytes, run-binding derivation, and Ed25519 tier verification against the suite's seed-derived test key.

## Running

```
git clone https://github.com/astrogilda/aee-conformance
cargo run --release -- aee-conformance/vectors --json report.json
```

Exit code 0 on full parity, 1 on any mismatch. Reject reasons are free-form and this implementation's own; the suite's informative condition codes were never read. `--role <name>` overrides the pinned test-key role, and `--discover-role <vector.json>` re-runs the role probe against a vector's signatures.

## What this is not

The checker verifies validity and recomputes `result` from the carried bytes. It does not evaluate consumer policy beyond the corpus's pinned test key, and parity with the reference corpus is a claim about the specification's determinacy, not about the security of any assessed artifact.

License: Apache-2.0.
