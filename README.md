# aee-checker

An independent validity-gate checker for the **Adversarial Execution Evidence (AEE)** in-toto predicate (v0.6, [in-toto/attestation#570](https://github.com/in-toto/attestation/pull/570)), implemented **from the specification text alone**: the four byte-pure stage-one validity steps (statement well-formedness, coverage validity, the result recompute, digest integrity) plus the trust-relative evidence tier, run against the [astrogilda/aee-conformance](https://github.com/astrogilda/aee-conformance) vector corpus.

**suiteRevision 1: 125/125 parity** (34/34 accepts including result tokens, 91/91 rejects) on the first full corpus run, blind, with no vector-driven fixes.

**suiteRevision 2: 138/138** (35/35 accepts, 103/103 rejects) after a spec-diff-led update. Run against the new corpus unchanged first, the same build scored 132/138; the six vectors separating the two runs, and what each contract change was, are in the report. That second pass is deliberately **not** described as blind: the changelog and vector names were read before the spec passages were, so the honest claim is *independent checker, spec-diff-led update, conformance verified*.

**suiteRevision 3: 140/140** (35/35, 105/105) on the first run with the checker unchanged. The revision adds two forcing vectors for the reason-map side of the coverage-partition rule; this checker's rule for it came from the spec text and predates them, so the two met rather than one driving the other.

[PARITY-REPORT.md](PARITY-REPORT.md) carries the scores, the interpretation decisions the spec text forced, the four formerly-open corners and how each was closed, and the from-spec discipline attestation listing exactly what was and was not read for each revision. [NOTES.md](NOTES.md) compares the vendored spec against the branch-head spec.

No dependency on the reference implementation: this crate carries its own strict I-JSON parser, RFC 8785 canonicalization with ECMAScript number formatting, RFC 6962 domain-separated Merkle root over DSSE PAE bytes, run-binding derivation, and Ed25519 tier verification against the suite's seed-derived test key.

## Running

```
git clone https://github.com/astrogilda/aee-conformance
git -C aee-conformance checkout cf0d5402327ae5a451efebc914852d1c687753ca
cargo run --locked --release -- aee-conformance/vectors --json fresh.json
python3 scripts/compare-report.py fresh.json reports/suite-revision-3.json
```

The checkout is pinned deliberately. `main` moves, and a later revision would run
a different corpus against the 140/140 claim on this page, which is the one thing
a reproduction recipe must not do quietly. Earlier revisions are reproducible the
same way by taking their suite pin and checker commit from
[`reports/INDEX.json`](reports/INDEX.json).

Exit code 0 on full parity, 1 on any mismatch. Reject reasons are free-form and this implementation's own; the suite's informative condition codes were never read. `--role <name>` overrides the pinned test-key role, and `--discover-role <vector.json>` re-runs the role probe against a vector's signatures.

## What this is not

The checker verifies validity and recomputes `result` from the carried bytes. It does not evaluate consumer policy beyond the corpus's pinned test key, and parity with the reference corpus is a claim about the specification's determinacy, not about the security of any assessed artifact.

License: Apache-2.0.
