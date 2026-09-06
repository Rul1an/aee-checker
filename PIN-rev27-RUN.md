# The rev-27 run, pinned before it starts

Written 2026-09-06, on the same terms as `PIN-v0.7-RUN.md` and for the same reason: a number is
worth what a third party can re-run, and the terms have to be fixed before the number exists or
fixing them is worthless.

This pass is **not blind, and not for the usual reason**. It is declared below rather than
discovered later.

## The disclosure that has to come first

An exploratory pass was run on 2026-09-06 before this file existed. It was not pre-registered, it
produced numbers, and those numbers are known to the author of this file. Publishing them as a
protocol run would be the exact quiet standard-lowering `PIN-v0.7-RUN.md` exists to prevent, so
they are not published that way. What is recorded here instead:

- The exploratory pass read the predicate text at the current pull-request head, and read
  astrogilda's 2026-09-04 comment on in-toto/attestation#570 describing what she changed and why,
  **before** anything was run. Neither can be un-read.
- It ran the checker unchanged against two pinned corpora and recorded verdict parity on both.
- It changed no checker source. The build under test predates every vector in this corpus and every
  word of the spec delta below, so no vector-driven fix is possible in either direction. That is
  the one property this pass still has, and it is the only one it claims.

So the honest label is **directed**, in the existing convention of rule 5, and the claim is narrower
than a blind number: *this build, frozen before the corpus moved, still agrees with the corpus after
it moved.* Not *the specification was determinate from a cold start*. The blind figure that bears on
determinacy is still the 179/232 in `reports/v0.7-blind-run.json` and this run does not touch it.

## What is pinned, before the work

| | |
|---|---|
| Predicate text (authoritative) | `in-toto/attestation` @ `25ac8581fbc9398a3add2577c65e2d09163e3db3`, `spec/predicates/adversarial-execution-evidence.md` |
| Predicate spec digest at that head | `sha256:2b7f3bc08123cbe1981d287cf20193858ae5ea6d55ca067e06363a1e71a573d7` (152102 bytes) |
| Predicate text the corpus was authored against | `astrogilda/attestation` @ `0dbe10bcc959b63dc42370a5db09812c9476f59a` |
| Spec digest the corpus names | `sha256:759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0` (147709 bytes) |
| Conformance suite | `astrogilda/aee-conformance` @ `94c163c` (2026-09-04T10:05:01-04:00), 272 vectors |
| Checker source digest at declaration | `sha256:5fbe879e9d6a7355d5af8c4ea6f7c055f9289753c69b9336b5ce0a213371b596` |
| Checker commit at declaration | `61b5e28b84ede1dec26ae8d1e33f9e65f84cb013` |
| Revision number | 27, assigned by **this** repository's sequence, not the suite's. The suite carries no `suiteRevision`; its authoritative identifier is the commit, and `git describe` calls this head `v0.9.0-21-g94c163c`. |

**Two spec digests appear above and that is the finding, not an error.** The corpus is pinned to
`0dbe10bc`, the pull request head is `25ac8581`, and they are 4393 bytes and 69 changed lines apart.
The run therefore cannot test the head; it can only test the corpus, and the corpus was authored
against superseded text. Anything this run reports binds to `759d2383`, and any sentence that
attaches it to the head would be false.

## How the provenance was settled, and the method correction that came with it

`PIN-v0.7-RUN.md` declared its commit resolvable because GitHub's `compare` reported `identical`,
and a correction dated 2026-09-01 recorded that the API cannot settle that question, because forks
share an object store and the API answers for a commit only a fork holds.

**That correction is itself incomplete, and this run found the missing half.** `git fetch --depth 1
origin <sha>` against upstream does not settle it either: it is served from the same shared object
store. Run as a negative control against `23bee586`, the commit the 2026-09-01 record establishes as
fork-only, the fetch **succeeds** from `in-toto/attestation`. A probe that cannot fail on a known
negative is not a probe.

What settles it is a plain clone plus a reachability test, with lazy fetch disabled:

```bash
git clone https://github.com/in-toto/attestation.git
GIT_NO_LAZY_FETCH=1 git cat-file -e <sha>^{commit}     # ABSENT for both shas
git for-each-ref  # 11 refs; neither sha is an ancestor of any
git fetch origin refs/pull/570/head                    # = 25ac8581..., exactly
```

Result, and it **refines** the 2026-09-01 record rather than confirming it: `25ac8581` is on no
upstream branch or tag, but upstream *does* publish it at `refs/pull/570/head`. "Resolves only from
the fork" is too strong for this head.

**What that ref is good for, and what it is not.** It is a discovery path: it lets a third party
reach the commit from upstream without trusting the fork, which a fork branch deletion would
otherwise take away. It is **not** an immutable pin. GitHub defines `refs/pull/<n>/head` as the
latest commit on the pull-request head branch, so it moves whenever the author force-pushes, which
this author has now done twice. The pin is therefore the **full commit SHA**, and the ref is the way
to fetch it; a reproduction should require the fetched ref to resolve to that SHA and treat a
mismatch as the branch having moved, not as a failed fetch.

## What this build has read, and what it has not

Read: the predicate specification at both commits above, the byte diff between them, and
astrogilda's 2026-09-04 comment on #570. All three before running. Disclosed rather than denied.

Not read, and not to be read before this run reports its numbers:

- the reference implementation in the suite (`aee/`, `cmd/`, `witnessattestor/`),
- any `expected.json` or per-vector verdict in `vectors/`,
- the suite's condition vocabulary, dispositions, or crosswalks beyond what earlier revisions
  already disclosed reading.

## The two numbers this run publishes, whatever they are

1. **Regression.** The checker at the digest above, against suite `50199317` (revision 26), compared
   to `reports/v0.7-rev26-directed-run.json` by `scripts/compare-report.py`. Expected to reproduce
   exactly; published if it does not.
2. **Advance.** The same unchanged checker against suite `94c163c` (revision 27), 272 vectors, 282
   commits later. Published whatever it is.

Reason parity is reported alongside and is **not** a verdict-parity figure and **not** an
independence claim, for the reason `README.md` already gives: the condition codes are not
independent of the suite's.

One counting note, recorded because the exploratory pass got it wrong first. Between revisions 26
and 27 the suite renamed every vector from descriptive names (`ok-001-caught-intercepted-fail`) to
content-addressed ids (`vcf20eae7df4f1f1b`). A set difference between the two record files therefore
reports 272 new and 250 removed, which is an artifact of the rename and not a corpus delta. The
honest statement of the change is the net count: 250 to 272, accepts 55 to 61, rejects 193 to 209,
indeterminate 2 to 2.

## What this run cannot establish

Everything `PIN-v0.7-RUN.md` already excludes, and one thing specific to this revision.

The spec delta at the head adds a refusal-set rule: the set a refusal names MUST be the set the
implementation evaluated, the listed shapes are explicitly non-exhaustive, and where evaluation
short-circuits at the first false conjunct **a verifier MUST NOT name a conjunct it did not reach**
and SHOULD name the conjunct that decided the refusal.

**No vector in this corpus exercises that rule**, because the corpus is pinned to the text that
predates it. So this run says nothing about whether this checker complies with it. That question is
open, it is answerable only from the text, and it is not answered here. Recording it as open is the
point: a run that quietly let a full parity number stand in for compliance with a clause the corpus
cannot reach would be claiming coverage it does not have — which is the failure this repository
exists to argue about.
