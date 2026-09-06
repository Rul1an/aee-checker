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

## The pin did not hold, and this is the re-pin

Added 2026-09-01. Everything above is left as written on 2026-08-03, because a pre-registration that
gets edited when the world moves is not one. What follows records that the world moved.

### The provenance half stopped holding, and the method above could not have seen it

The section above declares `23bee586d651c79ba6a1dd55d4b29b7c2ef2cff2` resolvable from
`in-toto/attestation`, and names its own method in passing: `compare` reports `identical`. That is
the GitHub API, and the API cannot settle this question. Forks share an object store, so the API
answers 200 for a commit that only a fork holds. Verified both ways today:

```
gh api repos/in-toto/attestation/commits/0dbe10bc     -> 200, same SHA
gh api repos/astrogilda/attestation/commits/0dbe10bc  -> 200, same SHA
git clone https://github.com/in-toto/attestation.git
git cat-file -e 0dbe10bc...^{commit}                  -> exit 128
```

Only a clone settles it, and the two disagree. Applied to the commit this file pins:
`23bee586` exits 0 in a plain clone of `astrogilda/attestation` and 128 in a plain clone of
`in-toto/attestation`. So the sentence above is false as written today, and was established by a
method that could not have distinguished the two cases when it was written.

The upstream account is astrogilda's, on PR 570 on 2026-08-28: history was rewritten after the
revision was published, which is also why the suite commit that sat on no ref now carries an
annotated tag, `cited/5019931`.

### What moved

The suite's `spec/VENDOR-PIN.json` no longer names `23bee586`, and the way it stopped is the part
worth recording. The pinned commit has been rewritten **13 times** across that file's history. Three
of those moves came after the one this document names: `f347c82 fix(spec): vendor the head that
states the rule the corpus enforces` took it off `23bee586` to `c0c4da67`, then `237f83b9`, then the
current `0dbe10bc`. A pin that moves is not a defect on his side; it is a corpus under active
development, and it is exactly why a run has to name the revision it ran against rather than name
the file that holds it.

A later commit, `be67a74 fix(vendor): pin the repository the vendored commit is fetchable from`,
added `commitRepo`, so the repository holding the commit is now named rather than guessed. Verified:
that commit's diff adds the line `"commitRepo": "astrogilda/attestation"`. The natural guesses fail.

| | pinned 2026-08-03 | pinned today |
|---|---|---|
| Repository | `in-toto/attestation` (implicit) | `astrogilda/attestation` (explicit, `commitRepo`) |
| Commit | `23bee586d651c79ba6a1dd55d4b29b7c2ef2cff2` | `0dbe10bcc959b63dc42370a5db09812c9476f59a` |
| Spec size | 2140 lines | 2322 lines, 147709 bytes |
| Spec digest | `sha256:94de8da5...` | `sha256:759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0` |
| Suite | `84ba2271` (2026-08-03) | `0c4e27ec4f28b03d9688885bb5a00c6e96334d1e` (2026-08-31) |

Verified today by clone, not by API: the commit resolves in `astrogilda/attestation`, sits on
`origin/predicate/adversarial-execution-evidence`, and its
`spec/predicates/adversarial-execution-evidence.md` is 147709 bytes hashing to the `specDigest` the
pin names, byte for byte.

The suite is **251 commits** past the revision pinned above.

### What follows for the run

The run described above has not started, and it cannot start against the pin above: that pin names
spec text two commits behind the branch head and a suite 251 commits behind. Starting it would
produce a number against superseded text, which is the failure this file was written to prevent, so
the pin is not quietly updated in the table above. A run begins from a fresh pre-registration naming
the row on the right, written before any v0.7 code exists, on the same terms.

One further thing is true of the current head and is recorded here so a later reader does not have to
rediscover it. The refusal-set clause, `b1513f62` on the fork's PR branch, is **not** an ancestor of
the pinned commit. It lands after it, together with `a4cb887`. Anything said about that clause binds
to the branch head and not to the digest this file names.

### Two things in the section above went stale, appended 2026-09-06

Same rule as before: appended and dated, not folded into the text it corrects.

**The method is right and its evidence was not the whole test.** "Only a clone settles it" holds.
But the intermediate probe a later reader would most naturally reach for — `git fetch --depth 1
origin <sha>` against upstream — does **not** settle it either, for the same reason the API does
not: it is served from the shared fork-network object store. Run as a negative control against
`23bee586`, the very commit this section establishes as fork-only, that fetch **succeeds** from
`in-toto/attestation`. A probe that cannot fail on a known negative is not a probe.

What settles it is a plain clone with lazy fetch disabled, plus a reachability test against the refs
upstream actually publishes:

```
git clone https://github.com/in-toto/attestation.git
GIT_NO_LAZY_FETCH=1 git cat-file -e <sha>^{commit}   # absent for 23bee586 and for 25ac8581
git for-each-ref                                     # 11 refs; neither sha is an ancestor of any
git fetch origin refs/pull/570/head                  # = 25ac8581..., exactly
```

That last line **refines** the finding above rather than contradicting it. The current head is on no
upstream branch or tag, but upstream *does* publish it at `refs/pull/570/head`. So "resolves only
from the fork" is too strong for the head, and the PR ref is the sounder pin target of the two,
because a fork branch can be rewritten by its owner — which is exactly what this section documents
happening — and a PR ref cannot.

**The `b1513f62` reference is now orphaned, and the claim it supported still stands.** That SHA is
today an ancestor of neither the corpus pin `0dbe10bc` nor the head `25ac8581`: the branch was
rewritten again, most recently on 2026-09-04. The claim itself was re-verified by text rather than
by ancestry, which is the durable way to state it — the refusal-set rule and its short-circuiting
clause (*a verifier MUST NOT name a conjunct it did not reach*) appear exactly once in the head and
not at all in the corpus pin, 4393 bytes and 69 changed lines apart.

One caveat on how that was checked, because the obvious probe lies. The clause is line-wrapped in
the source, so `grep` for the sentence returns **zero in both files** and reads as absent from the
head as well. Whitespace has to be normalised before matching, or the answer is a false negative on
the one question this paragraph exists to settle.

The fresh pre-registration this section called for is `PIN-rev27-RUN.md`, written on those terms;
one phrase there does not survive contact, since it asked for a run "before any v0.7 code exists"
and v0.7 code has existed since revision 22. What was preserved instead is the substance: a run
begins from terms fixed in advance, naming the revision it ran against.
