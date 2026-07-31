# Protocol for the v0.7 pass, fixed before the spec was readable

Written 2026-08-01, while the v0.7 predicate text is **not** reachable from any public ref. That
timing is the entire point of this file. A conformance number means different things depending on
what existed first, and the only moment a pass can be committed to as blind is before its author
could have read the thing being implemented.

This repository already distinguishes those cases in `NOTES.md` and in the suite's own independence
section. The 125/125 at revision 1 was blind. The 140/140 was a first run by an unchanged build
whose rule predated the two vectors it met. Everything after followed a spec diff already read, and
was reported as directed. The distinction has been made after the fact each time. This one is made
in advance.

## Preconditions, and why the work has not started

The pass does not begin until the v0.7 predicate text is **resolvable from a public ref**. Today it
is not:

- `spec/VENDOR-PIN.json` in the suite names `in-toto/attestation`, PR 570, ref
  `predicate/adversarial-execution-evidence`, commit `23bee586d651c79ba6a1dd55d4b29b7c2ef2cff2`.
  That commit answers 422 from `in-toto/attestation` and from the fork.
- The named ref's head carries v0.6. No branch of the fork carries v0.7.
- The only public v0.7 text is the vendored copy inside the conformance suite itself.

Implementing from that copy would bind the result to a spec version no third party can fetch. If the
eventual PR text differs, the pass is not weaker, it is void, and nobody could show which bytes were
read. So the precondition is not fussiness about provenance; it is the difference between a result
that survives scrutiny and one that evaporates under it.

Either resolution satisfies it: the pinned commit becomes reachable, or the v0.7 spec lands as its
own PR.

## What is frozen now

- Checker source digest at the time of writing: `sha256:1c3e2e7843fc021e20c33d3bdc726fbb704ad0438654a0444fa7a06d6613aaba`
  (`scripts/checker_digest.py`, repository at `db9ab2a`).
- That build implements v0.6. It has read no v0.7 text of any kind, including the vendored copy, and
  no description of v0.7 beyond the summary its author posted in the thread.

## The rules the pass will follow

1. **One pass.** A single revision, pinned before the run and named in the record. Not a rolling
   re-run against a corpus that moves daily. Chasing a moving corpus manufactures directed scores,
   which is the one thing this record cannot afford.
2. **From the text alone.** The predicate spec, and nothing else. No reference implementation, no
   condition codes, no vector-driven fixes, no reading of the corpus to discover a rule.
3. **The number is published whatever it is.** Including a bad one. A protocol that only survives a
   good result is not a protocol.
4. **Interpretation decisions are recorded with their spec quotes**, as in `PARITY-REPORT.md`, so a
   reader can check the reading rather than trust the score.
5. **Anything after the first run is labelled directed**, in the existing convention, and reported
   as evidence that a rule is implementable from the text rather than that a second reader found it.
6. **The record binds to a source digest and a suite commit**, per `reports/INDEX.json`, so the claim
   names the build that produced it.

## What this pass cannot establish, stated up front

Whether the predicate is the right shape for the framework. That judgement belongs to the in-toto
maintainers and has been declined on the record, in the thread, more than once. A mechanical gate
checked row by row is what an implementer can attest, and it is all this will claim.
