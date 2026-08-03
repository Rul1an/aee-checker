# The v0.7 run, pinned before it starts

Written 2026-08-03, after the precondition in `PROTOCOL-v0.7.md` was satisfied and before any v0.7
code exists in this repository. Both facts are checkable from what is recorded below, which is the
only reason this file is worth writing.

## The precondition is now met

`PROTOCOL-v0.7.md` said the pass does not begin until the v0.7 predicate text is resolvable from a
public ref, and recorded that it was not: the commit named by the suite's `spec/VENDOR-PIN.json`
answered 422 from `in-toto/attestation` and from the fork, and the only public v0.7 text was the
copy vendored inside the conformance suite.

That has changed, and both halves of the pin now hold:

- `23bee586d651c79ba6a1dd55d4b29b7c2ef2cff2` resolves from `in-toto/attestation`. It is the head of
  pull request 570 (`compare` reports `identical`, 0 ahead, 0 behind).
- The spec fetched from that public ref is 2140 lines and hashes to
  `sha256:94de8da54af6a2fe4c897f606ca22bfd054f4238b3c85db031ddc703516331b5`, which is exactly the
  `specDigest` the suite's `VENDOR-PIN.json` names.

So the bytes are both what the pin says they are and reachable by a third party. The integrity half
held all along; the provenance half is what was missing, and it is what is now satisfied.

## What is pinned, before the work

| | |
|---|---|
| Predicate text | `in-toto/attestation` @ `23bee586d651c79ba6a1dd55d4b29b7c2ef2cff2`, `spec/predicates/adversarial-execution-evidence.md` |
| Predicate spec digest | `sha256:94de8da54af6a2fe4c897f606ca22bfd054f4238b3c85db031ddc703516331b5` |
| Conformance suite | `astrogilda/aee-conformance` @ `84ba227155f55b653deed5051027f9aecdd2159f` (2026-08-03T02:34:15Z) |
| Checker source digest at declaration | `sha256:1c3e2e7843fc021e20c33d3bdc726fbb704ad0438654a0444fa7a06d6613aaba` |
| Checker commit at declaration | `524cc7d9f6a2fdbc8cf741b69f7d0a98ab74ee16` |

The checker source digest is byte-identical to the one `PROTOCOL-v0.7.md` froze on 2026-08-01,
recomputed here by `scripts/checker_digest.py`. That is the evidence that the build which declared
the protocol is the build that starts the pass: it has not moved in between.

## What this build has read, and what it has not

Read: the predicate specification at the pinned commit, and nothing else from it.

Not read, and not to be read before the first run reports its number:

- the reference implementation in the suite (`aee/`, `cmd/`, `witnessattestor/`),
- any `expected.json` or per-vector verdict in `vectors/`,
- the suite's condition vocabulary, dispositions, or crosswalks,
- any prose describing what a rule is supposed to do, beyond the spec itself.

The suite is pinned by commit so the corpus cannot move under the run. It is fetched at execution
time to produce the number, not before, and only the statement inputs are read.

## The rules this run follows

Unchanged from `PROTOCOL-v0.7.md`: one pass at the revision pinned above, implemented from the text
alone, the number published whatever it turns out to be, interpretation decisions recorded with
their spec quotes, anything after the first run labelled directed, and the record bound to a source
digest and a suite commit in `reports/INDEX.json`.

One thing worth restating because this version makes it costly. v0.7 is breaking on the wire, with
no alias and no dual-accept window, so the build frozen above rejects every v0.7 statement at the
type check. The delta is not an increment: `attribution` becomes a required row member over a closed
two-value vocabulary, `expectedPayloads` enters the corpus manifest and therefore the run binding
input, `aeePayloadCommitment` becomes required on every interception record, a `sealed` record
becomes unconditionally required on any statement carrying a `basis: substrate` row and carries both
`aeeObservedSet` and `aeeObservedAttacks`, `aeeAssessedAttacks` becomes required on the arming
record, five coverage validity requirements are added, and two record kinds are registered that
cover nothing. A bad number is a live possibility and publishing it is the point.

## What the run cannot establish

Unchanged: whether the predicate is the right shape for the framework. That judgement belongs to the
in-toto maintainers, has been declined here on the record more than once, and is not what a
mechanical row-by-row gate can attest.
