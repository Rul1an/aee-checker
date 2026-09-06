# Notes: spec versions and corpus observations

## Suite revisions and pins

| Revision | Suite commit | Spec digest (sha256 of the vendored predicate spec) | Vectors | Parity |
|---|---|---|---|---|
| 1 | `1bc6a5a2362260514d35fe3757f35dcc8723f6b6` | — (byte-identical to branch head `4a36b197`, see below) | 125 | 125/125 |
| 2 | `55ee73321cd40edd2b4a814948506a60074543a2` | `d3872a02875b2da8de0263e93fb92ca6f5ab0fd75f07ed3762a1b18b0c1712a3` | 138 | 138/138 |
| 3 | `cf0d5402327ae5a451efebc914852d1c687753ca` | `d3872a02875b2da8de0263e93fb92ca6f5ab0fd75f07ed3762a1b18b0c1712a3` (unchanged) | 140 | 140/140 |
| 4 | `b886c0a` | — | — | not run here |
| 5 | `ea25a1e218e94843e018dffc0eae4f3fcab1749e` | `39233b27b7f27b94ed727a3852030c69c7a64e5706b73519848a2b02f244e661` | 149 | 149/149 (148/149 unchanged) |
| 6 | `8959bd3293600c10516894e731ed1ef280a21b5c` | `606215de629d5f5eda9e62826cf511733b1ec0b9ca8ed07662a5c8bfe181d0b9` | 153 | 153/153 (151/153 unchanged) |

Revision 4 vendored the new encoding and nesting rules into the spec and this
checker was never run against it, so there is no record for it and the table
says so rather than leaving the gap to be read as a skipped number. Revision 5
adds the byte-level vector tier that exercises them.

The revision-1 run was blind. The revision-2 run was not, though the order
matters: the six differing behaviours came out of the baseline run, which named
them, and `vectors/CHANGES.md` and the spec passages were read afterwards to
determine what each should become. No Go or Python rail source was
opened for either revision, and neither were the manifest's expected condition
codes.

Against revision 2, the revision-1 build scored 132/138 unchanged. The before and
the after of *that* boundary are `reports/suite-revision-2-baseline.json` and
`reports/suite-revision-2.json`, both against suite `55ee7332`;
`reports/suite-revision-1.json` is the earlier corpus and is not the before-record
here. `reports/INDEX.json` names the checker and suite behind each of the five records.

The revision-5 run was not blind either, and in the opposite direction from
revision 2: the maintainer reported the miss before it was run, naming both the
vector and the constant. What that report did not contain, and what the run and
the source did, is that the constant was the smaller half. This parser counted
depth per parsed value where the revision states per open container, so it sat
one level away from the spec rule on every document in the corpus: measured on
the raw bytes, which needs no parser and so covers the deliberately ill-formed
vectors too, the offset is one on all 149 statements and every record payload
inside them, because every deepest path in the corpus ends in a scalar. Setting
the constant alone reaches 149/149 and is still wrong at depth 128. What makes
the corpus unable to separate the two is not its maximum depth — `bad-741`'s
payload sits at 130 — but that no document in it sits at 128, which is the one
depth where the two readings disagree. A scalar leaf inside 128 open containers
reads as 129 to a per-value counter and 128 to a per-container one; at 129 both
reject, and at 128 with an empty-container leaf both accept. The boundary
therefore lives in `src/json.rs`'s own tests.

All six are inspectable and reproducible by hand from those pins; the
revision-6 run at 153/153 is the one re-verified continuously by CI, which
follows the current suite pin. Each earlier record was continuously verified
until the next replaced it, and each remains reproducible from its own pins:
the fixed build still reproduces the revision-5 record exactly.

## Vendored spec vs branch head

**Re-measured 2026-09-06, and it no longer says what it said.** This section
previously recorded the vendored spec as byte-identical to the branch head, for
v0.6, against `astrogilda/attestation@4a36b197`. All three of those have moved,
and a reader who trusted the old text would conclude there is no version skew
when there is 4393 bytes of it.

Measured by clone rather than by API, at `spec/predicates/adversarial-execution-evidence.md`:

| | commit | bytes | sha256 |
|---|---|---|---|
| Corpus `VENDOR-PIN` | `0dbe10bc` | 147709 | `759d2383…` |
| Pull-request head | `25ac8581` | 152102 | `2b7f3bc0…` |
| The 2026-08-03 pin | `23bee586` | 135178 | `94de8da5…` |

The corpus pin hashes to its own declared `specDigest` byte for byte, so the
suite is internally consistent; the skew is between the corpus and the head, not
inside the corpus. The 69 changed lines add the refusal-set rule: the set a
refusal names MUST be the set the implementation evaluated, the listed shapes are
explicitly non-exhaustive, and where evaluation short-circuits at the first false
conjunct a verifier MUST NOT name a conjunct it did not reach and SHOULD name the
conjunct that decided the refusal.

**No vector in revision 27 exercises that rule**, because the corpus predates it.
Whether this checker complies is therefore open and answerable only from the
text.

### Where the head actually lives, and how that was settled

Not by the GitHub API, and not by `git fetch --depth 1 origin <sha>` either.
Both are served from the shared fork-network object store, so both answer for a
commit only a fork holds; run as a negative control against `23bee586`, which the
2026-09-01 record establishes as fork-only, the bare-sha fetch **succeeds** from
`in-toto/attestation`. A probe that cannot fail on a known negative is not a
probe, and this one had already been trusted once.

A plain clone with `GIT_NO_LAZY_FETCH=1` plus a ref-reachability test settles it:
`25ac8581` is absent from a plain clone and is an ancestor of none of upstream's
11 branches and tags, but upstream **does** publish it at `refs/pull/570/head`.
So "resolves only from the fork" is too strong for this head. That ref is a
discovery path rather than a pin: it reaches the commit from upstream even if the
fork branch is deleted, but GitHub defines `refs/pull/<n>/head` as the latest
commit on the pull-request head branch, so it moves on every force-push. Pin the
full SHA and require the fetched ref to resolve to it.


## Corpus observations

These were recorded against **suiteRevision 1** and are kept as the observations of
that revision rather than updated in place; the revision table at the top of this
file carries the current counts.

- `vectors/MANIFEST.json` enumerated 125 vectors (34 accept, 91 reject);
  the `accept/` and `reject/` directories contain exactly those 125 JSON
  files (plus generator scripts and INDEX files, which were not read).
- `vectors/CHANGES.md` declared suiteRevision 1, tracking PR #570 at commit
  `4a36b19`, consistent with the byte-identical spec diff above. It now also
  declares suiteRevision 2 (the round-7 chain-scope redesign) and suiteRevision 3
  (round-8 reason-map membership, no normative spec change), both pinned by digest
  in the table at the top of this file.
- Only `ok-024-mixed-basis-rows` carries explicit per-row tier expectations
  in the manifest (`tierWithPinnedKey` / `tierWithoutKey`); the other
  tier-relevant accepts (`ok-019`, `ok-020`, `ok-023`) pin tier behavior
  through their construction rather than through manifest columns.
- Three distinct `keyid` values appear across the corpus: the substrate
  observation key's id (sha256 of its raw public key, 191 occurrences),
  `deadbeef...` (the wrong-keyid accept `ok-019`), and one other id in
  `ok-024` (the row whose covering record does not verify under the pinned
  key).
- `bad-303-binding-version-2` carries no `aeeBindingVersion` member in its
  arming payload; the v2 construction is observable only as a run-binding
  digest that does not re-derive under the v1 construction, which is the
  fail-closed rejection path the spec mandates.
