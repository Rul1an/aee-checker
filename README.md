# aee-checker

An independent validity-gate checker for the **Adversarial Execution Evidence (AEE)** in-toto predicate (v0.6, [in-toto/attestation#570](https://github.com/in-toto/attestation/pull/570)), implemented **from the specification text alone**: the four byte-pure stage-one validity steps (statement well-formedness, coverage validity, the result recompute, digest integrity) plus the trust-relative evidence tier, run against the [astrogilda/aee-conformance](https://github.com/astrogilda/aee-conformance) vector corpus.

**suiteRevision 1: 125/125 parity** (34/34 accepts including result tokens, 91/91 rejects) on the first full corpus run, blind, with no vector-driven fixes.

**suiteRevision 2: 138/138** (35/35 accepts, 103/103 rejects) after a spec-diff-led update. Run against the new corpus unchanged first, the same build scored 132/138; the six vectors separating the two runs, and what each contract change was, are in the report. That second pass is deliberately **not** described as blind: the changelog and vector names were read before the spec passages were, so the honest claim is *independent checker, spec-diff-led update, conformance verified*.

**suiteRevision 3: 140/140** (35/35, 105/105) on the first run with the checker unchanged. The revision adds two forcing vectors for the reason-map side of the coverage-partition rule; this checker's rule for it came from the spec text and predates them, so the two met rather than one driving the other.

**suiteRevision 5: 149/149** (35/35, 114/114) after a parser fix. The unchanged revision-3 build scored **148/149** against it, and the single miss is worth stating plainly because the causation runs the other way this time: the revision pins a nesting bound the earlier text did not state, this checker had picked 256, and the new `bad-741` vector found it. Not blind, and not a case of the two meeting. The bound was only the visible half. The revision also states the counting rule, and this parser had been incrementing per parsed value rather than per open container, which read exactly one level deeper than the spec rule on **every document in the corpus** — all 149 statements and every record payload inside them, measured on the raw bytes so the deliberately ill-formed vectors are covered too — because every deepest path in the corpus ends in a scalar. Changing only the constant scores 149/149 as well, and still rejects a statement at depth 128 that the spec calls valid. What keeps the corpus from telling the two fixes apart is not its maximum depth, since `bad-741`'s payload sits at 130, but that nothing in it sits at 128, the one depth where the two readings disagree: a scalar leaf inside 128 open containers reads as 129 to a per-value counter and 128 to a per-container one, and at 129 both reject. That boundary is pinned in this parser's own tests instead. The revision's other half, the encoding rules, needed no change here: this checker rejected ill-formed UTF-8, CESU-8, overlong forms and unpaired surrogate escapes from the first build.

**suiteRevision 6: 153/153** (36/36, 117/117) after implementing the noncharacter exclusion. The unchanged revision-5 build scored **151/153**. Two of the four new vectors are the depth-boundary pair, `ok-036` and `bad-742`, and the container-branch counter already handled both; the other two, `bad-743` and `bad-744`, carry Unicode noncharacters in a vocabulary label and a payload value, which this checker admitted. It admitted them because the earlier text scoped its MUST to well-formed sequences of Unicode scalar values, and a noncharacter is one; the revision widens the rule to the RFC 7493 section 2.1 exclusion the strict-I-JSON label had always implied. **This one is directed, and more so than revision 2 was:** the rule was written and the vectors named before this checker ran, so what it demonstrates is that the corrected rule is implementable from the text, not that an independent reader found it.

[PARITY-REPORT.md](PARITY-REPORT.md) carries the scores, the interpretation decisions the spec text forced, the four formerly-open corners and how each was closed, and the from-spec discipline attestation listing exactly what was and was not read for each revision. [NOTES.md](NOTES.md) compares the vendored spec against the branch-head spec.

No dependency on the reference implementation: this crate carries its own strict I-JSON parser, RFC 8785 canonicalization with ECMAScript number formatting, RFC 6962 domain-separated Merkle root over DSSE PAE bytes, run-binding derivation, and Ed25519 tier verification against the suite's seed-derived test key.

## Running

```
git clone https://github.com/astrogilda/aee-conformance
git -C aee-conformance checkout 7098f4e6b7d04c8394969ed81b4025d4d9038324
cargo run --locked --release -- aee-conformance/vectors --json fresh.json
python3 scripts/compare-report.py fresh.json reports/suite-revision-6.json
```

The checkout is pinned deliberately. `main` moves, and a later revision would run
a different corpus against the 153/153 claim on this page, which is the one thing
a reproduction recipe must not do quietly. Earlier revisions are reproducible the
same way by taking their suite pin and checker commit from
[`reports/INDEX.json`](reports/INDEX.json).

Exit code 0 on full parity, 1 on any mismatch. Reject reasons are free-form and this implementation's own; the suite's informative condition codes were never read. `--role <name>` overrides the pinned test-key role, and `--discover-role <vector.json>` re-runs the role probe against a vector's signatures.

## What this is not

The checker verifies validity and recomputes `result` from the carried bytes. It does not evaluate consumer policy beyond the corpus's pinned test key, and parity with the reference corpus is a claim about the specification's determinacy, not about the security of any assessed artifact.

License: Apache-2.0.
