# AEE validity-gate checker: parity report

Second independent implementation of the stage-one validity gate, `result`
recompute, and evidence-tier derivation for the **Adversarial Execution
Evidence** in-toto predicate v0.6 (in-toto/attestation PR #570, commit
`4a36b197`), built in Rust from the specification text alone and run against
the `astrogilda/aee-conformance` vector corpus (suiteRevision 1, git commit
`1bc6a5a2362260514d35fe3757f35dcc8723f6b6`, 125 vectors).

## Parity score

| Class | Parity |
|---|---|
| Accept vectors (verdict + result token) | **34/34** |
| Reject vectors (verdict) | **91/91** |
| Per-row tier columns (`ok-024`, both key policies) | **match** |
| **Total** | **125/125** |

Every accept vector verifies valid with the expected `result` token; every
reject vector is invalid with a free-form reason phrased from the spec (this
implementation's reasons are its own words; the corpus's condition-code
vocabulary was never read, see below). The evidence tier was exercised under
the corpus's own seed-derived test keys: `ok-024-mixed-basis-rows` reproduces
`["attested","unattested","declared"]` with the pinned key and
`["unattested","unattested","declared"]` without it, and the
signature-sensitive accepts behave as their names require (`ok-019` attested
despite a wrong `keyid` hint, `ok-020` unattested because the signature is
not over the DSSE PAE, `ok-023` attested under the out-of-band pinned key
with the embedded key never consulted).

The full machine-readable run records are kept per run rather than overwritten,
so each outcome stays inspectable (one row per vector: verdict, result, reason,
tier columns, parity flag). Which checker produced each record matters as much as
which suite it ran against, so both are named:

Provenance lives in [`reports/INDEX.json`](reports/INDEX.json) as well as in this
table. A conformance result is a statement about an implementation under test, and
the record files do not carry that: the two revision-2 records have the same
`suite` field, no checker field, and differ only in the outcome they report. So a
record taken on its own does **not** tell you which implementation produced it,
and `INDEX.json` has to travel with it.

The index is bound to the records rather than merely describing them. Each entry
carries the record's `sha256` and a `checkerSourceDigest`, a deterministic hash of
`Cargo.toml`, `Cargo.lock` and `src/**` computed by
[`scripts/checker_digest.py`](scripts/checker_digest.py). A source digest is used
rather than a commit SHA because a commit cannot name itself from inside the file
it carries. [`scripts/validate-index.py`](scripts/validate-index.py) checks the
record set, the digests, the counts and the parity strings on every push, so a
swapped report, an unindexed one, or a source change without a regenerated report
fails instead of passing quietly.

| Record | Checker | Suite | Result |
|---|---|---|---|
| [`reports/suite-revision-1.json`](reports/suite-revision-1.json) | `a7d891b` | revision 1, `1bc6a5a2` | 125 vectors, 34/34 and 91/91 |
| [`reports/suite-revision-2-baseline.json`](reports/suite-revision-2-baseline.json) | `a7d891b`, unchanged | revision 2, `55ee7332` | 138 vectors, 34/35 and 98/103 |
| [`reports/suite-revision-2.json`](reports/suite-revision-2.json) | `47dbaf17` | revision 2, `55ee7332` | 138 vectors, 35/35 and 103/103 |
| [`reports/suite-revision-3.json`](reports/suite-revision-3.json) | `47dbaf17`, unchanged | revision 3, `cf0d5402` | 140 vectors, 35/35 and 105/105 |

The middle row is the one worth keeping. It is the revision boundary itself: the
same build that scored 125/125 on revision 1, run unchanged against revision 2,
with the six diverging vectors named in the record rather than only summarised
here.

Three claims, and they are not the same claim. All three records are
**inspectable**: a reader can open one and see what happened. All three are
**reproducible by hand**, because the checker commit and the suite commit are
pinned for each, which is what reproducing needs. Only the last is
**continuously re-verified**: CI pins the suite, checks the spec digest, and
compares a fresh run against the stored report on every push, so drift shows up
without anyone looking. The other two are not re-verified by anything, which is a
deliberate choice rather than an omission, since a workflow that rebuilds an
older checker on every push buys little.

## suiteRevision 2

The corpus moved to suiteRevision 2 (git commit
`55ee73321cd40edd2b4a814948506a60074543a2`, 138 vectors: 35 accept, 103
reject), against spec
`spec/predicates/adversarial-execution-evidence.md` at sha256
`d3872a02875b2da8de0263e93fb92ca6f5ab0fd75f07ed3762a1b18b0c1712a3`.

The revision was run twice: once with the checker unchanged, to record where
the new contract bites, and once after updating it. Both numbers are reported,
because the interesting artifact is the boundary rather than the final
scoreboard.

| Run | Accepts | Rejects | Total |
|---|---|---|---|
| Unchanged checker (the suiteRevision 1 build) vs suiteRevision 2 | 34/35 | 98/103 | **132/138** |
| After the spec-diff-led update | 35/35 | 103/103 | **138/138** |

Six vectors separated the two runs, each on new or tightened behaviour:

| Vector | Unchanged checker | suiteRevision 2 contract |
|---|---|---|
| `ok-034-arming-chain-genesis` | invalid | valid |
| `bad-721-chain-scope-not-array` | valid | invalid |
| `bad-724-artifact-ref-out-of-range` | valid | invalid |
| `bad-728-artifact-two-subjects` | valid | invalid |
| `bad-729-duplicate-attackid-rows` | valid | invalid |
| `bad-730-coverage-class-overlap` | valid | invalid |

That 132/138 does not weaken the suiteRevision 1 result. The earlier 125/125
was measured against the corpus as it stood; six of these vectors did not exist
or did not carry this reading then.

### What each change was

The six fall into three classes, and the distinction matters: a schema change, a
defect, and a resolved open boundary are different kinds of thing to have found.

**A deliberate schema change (`ok-034`, `bad-721`).** `aeeChainScope` went from a
free-form string in revision 1 to a duplicate-free array of tokens from the closed
vocabulary `subject`, `corpus`, `networkPosture`, sorted by UTF-16 code unit, with
no alias for the old form. The checker read the member through `as_str()`, which
is a faithful implementation of the revision 1 contract; against revision 2 an
array yields `None` and a bare string still passes. Both vectors fall out of that
one line, and neither is a defect against the spec the code was written to.

**Two defects in this checker.**

- *Subject cardinality was scoped to substrate-carrying statements.* Exactly one
  subject is required on a statement of any basis; only the six binding-digest
  inputs stay substrate-scoped. An artifact-only two-subject statement was
  accepted.
- *Duplicate `attackId` rows collapsed under the set comparison.* Uniqueness is a
  well-formedness invariant and has to be checked before the coverage comparison,
  because a set comparison absorbs the duplicate silently.

**Two formerly open boundaries, now pinned.**

- *Out-of-range `observationRefs` on any row.* The range check ran only while
  walking substrate rows, so an artifact row's dangling index was never resolved.
  Revision 2 places it on any row regardless of basis, fail-closed and independent
  of any gate.
- *Coverage as a disjoint partition.* This was an explicit editorial divergence,
  recorded as an open corner on both sides: these rails rejected overlap, this
  checker accepted it, and no vector exercised it. Revision 2 states it outright,
  a class appears in exactly one of `assessedClasses`, `outOfScope`,
  `routedElsewhere`, and *a class both assessed and disclosed as a gap is
  contradictory*. The reject reading is accepted rather than contested: one label
  says the class was covered and the other says it was not, so carrying both
  asserts two statuses rather than a nuance. Worth noting separately that the
  local check also read `n == 0` under a comment that said "exactly one", so the
  code and its own comment had drifted apart independently of which reading won.

The claim ceiling is unchanged and the revised spec now states it too: a
correct disjoint partition shows the carried classification is honest about
itself. It does not show that a producer withheld no runs and no classes.

### Discipline for this revision

Different from the first run, and the claim is narrowed accordingly. The
suiteRevision 1 result was a blind first run with no vector-driven fixes. This one
is not, though the order matters: the six divergences came out of the baseline run
itself. The unchanged build was run against revision 2 first and it named them;
`vectors/CHANGES.md` and the spec passages were read afterwards, to work out what
each should become.

What was read: `spec/predicates/adversarial-execution-evidence.md` (the
cardinality, coverage, `attackId`, `observationRefs` and chain-scope passages)
and `vectors/CHANGES.md`. What was not: any Go or Python rail source, and the
manifest's expected condition codes. Directory listings of `aee/` and `cmd/`
were seen; no file in them was opened.

The honest description of this revision is therefore **independent checker,
spec-diff-led update, conformance verified** — not a second blind run.

## suiteRevision 3

The corpus moved to suiteRevision 3 (git commit
`cf0d5402327ae5a451efebc914852d1c687753ca`, 140 vectors: 35 accept, 105 reject).
No normative spec change and the spec digest is unchanged; the revision adds two
forcing vectors, `bad-731-outofscope-unknown-class` and
`bad-732-routedelsewhere-unknown-class`.

**140/140 on the first run, with the checker unchanged.**

The claim worth making here is narrow and worth stating precisely, because a
looser one is available and would be wrong. This was not a second blind
from-scratch run: the checker is the same build that had already read revision 2's
changelog. What it was is this: the unchanged revision-2 checker, whose reason-map
membership rule was derived from the partition sentence in the spec and predates
both new vectors by about an hour and three quarters, passed revision 3 at 140/140
on its first run, refusing each new vector with the map-specific reason.

That is the useful shape of the evidence. The rule came out of the specification
text on one side and out of independently written vectors on the other, and the
two met. It says nothing about the rest of the corpus that a prior run had not
already said.

## Mismatches

None. There are no rows for the mismatch table, no divergences to
classify, and no unresolved vector-level questions for the author.
Because there were no mismatches, the manifest's informative `codes`
arrays were not read even after the run: no divergence analysis needed
them.

## Interpretation decisions made from the spec text

These are the readings this implementation committed to where the spec
required interpretation. All are exercised by the corpus and none produced a
mismatch, but they are the load-bearing choices a reviewer should check:

1. **Referenced-record validity vs covers-nothing.** The coverage-validity
   bullet ("every referenced payload parses as a canonical `+json` object
   ..., carries the reserved members, and its `aeeRunBinding` equals ...")
   is enforced as a hard validity requirement for every record a substrate
   row references, while kind-constraint violations (a non-UTC or late
   `armedAt`, a posture mismatch, `aeeMethod` wrong for the kind, sealed
   conditions, run-chaining member syntax) make the record cover nothing,
   invalidating the attestation only when the row is left without its
   required class cover. Both altitudes are in the spec ("the following
   MUST hold or the attestation is invalid" vs "a record violating any
   constraint of its declared `aeeKind` ... covers nothing").
2. **Method cap over covering records.** "The row's `method` is no stronger
   than the weakest `aeeMethod` across its covering records" is computed
   over the referenced records that pass their kind constraints, with
   unknown-`aeeKind` and non-covering records excluded ("a record whose
   `aeeKind` the consumer does not recognize covers nothing and is
   otherwise ignored"). This reading makes `bad-304` (an examination record
   dragging an intercepted row down) invalid while keeping `ok-013` (an
   unknown-kind extra record) and `ok-030` (a reconstructed row over a
   mixed record set) valid.
3. **Duplicate records by leaf hash.** "Two byte-identical entries ... make
   the attestation invalid: a record's canonical identity is its leaf hash"
   is implemented as duplicate detection on the RFC 6962 leaf hash over the
   DSSE PAE bytes (payloadType + payload), the spec's own identity notion,
   rather than on the enclosing JSON objects.
4. **Fail-closed vs malformed row members.** Members the recompute reads
   (`containmentObserved`, `basis`, `method`) are fail-closed on *absence*
   or unknown token; a present member of the wrong JSON type is a
   decode-layer fault and the statement is malformed (the altitude
   `bad-506` pins for `actualLayer`). On substrate rows, fail-closed label
   or method makes the attestation invalid per "a `basis: substrate` row
   whose `containmentObserved`, `basis`, or `method` is fail-closed ...
   cannot satisfy the class-match requirement and is therefore invalid."
5. **Clean-row `actualLayer: none` on every basis.** "On a row whose
   `containmentObserved` label is from the carried labels but not in the
   caught set ..., the producer MUST emit the literal string `none`" is
   enforced for artifact rows as well as substrate rows; the spec's clean-row
   definition does not scope it to a basis.
6. **Coverage completeness at class granularity.** Every manifest class must
   appear in **exactly one** of `assessedClasses` / `outOfScope` /
   `routedElsewhere`, and every class named in any of the three must exist in
   the manifest. A partition is made of subsets of the thing it partitions, so
   the membership rule runs both ways.
   Under suiteRevision 1 the first half was read as "at least one" from "empty
   objects when complete" plus the disclosed-gap rule; suiteRevision 2 states
   the disjoint partition outright and `bad-730-coverage-class-overlap` forces
   it. The second half is **not forced by revision 2**:
   `bad-819-assessed-class-not-in-manifest` covers `assessedClasses` only, and
   no vector puts an unknown key in either reason map. This checker enforced
   only the assessed side until an unknown key in `outOfScope` or
   `routedElsewhere` was shown to pass at full parity, with the result
   recompute unable to catch it because it ignores non-manifest classes
   entirely. Two upstream vectors would close it, one per reason map; the
   local guard is `tests/test_coverage_partition.py`.
   Attack-granularity integrity is exact set equality between row attackIds
   and the manifest's attacks for the assessed classes.
7. **Binding version 2 is detected as a binding mismatch.** `bad-303`'s
   arming payload carries no explicit version member; a construction this
   verifier does not implement is only visible as `aeeRunBinding` failing to
   equal the v1 derivation, which is exactly the fail-closed behavior the
   spec requires ("reject ... rather than attempt more than one
   construction"). An explicit payload `aeeBindingVersion` other than `"1"`
   is additionally rejected fail-closed.
8. **`armedAt` must be RFC 3339 with a zero offset** ("RFC 3339 UTC"),
   compared against `issuedAt` as instants; `issuedAt` itself only needs to
   be a valid RFC 3339 timestamp.
9. **Strict, canonical base64** for record payloads: decode with the
   standard alphabet and require the re-encoding to reproduce the carried
   text, treating anything else as an undecodable record.
10. **Tier per row over its covering records**, a record verifying when any
    of its signatures verifies (DSSE semantics) against the single pinned
    substrate observation key; `keyid` is never consulted ("an
    unauthenticated lookup hint and never the check itself").
11. **The whole statement is parsed as strict I-JSON** (duplicate members
    rejected anywhere, not only inside record payloads). Under suiteRevision 1
    only the payload-level duplicate had a corpus vector and this was flagged
    as a reading a lenient reader could differ on. suiteRevision 2 pins it:
    `bad-725-statement-duplicate-member` carries raw statement bytes with a
    repeated top-level member, and the reading is now forced rather than
    inferred.

All four open points recorded here under suiteRevision 1 are closed. Each was a
corner the corpus did not then exercise and this checker accepted; each is now
forced by a vector and refused:

| Former open point | suiteRevision 2 |
|---|---|
| duplicate `attackId` rows | malformed, `bad-729-duplicate-attackid-rows` |
| `assessedClasses` overlapping the gap maps | malformed, `bad-730-coverage-class-overlap` |
| artifact-only statement with two subjects | malformed, `bad-728-artifact-two-subjects` |
| out-of-range `observationRefs` on artifact rows | malformed, `bad-724-artifact-ref-out-of-range` |

Only one of the four was a genuine open call. Coverage overlap was a live
divergence with no vector either way, and the changelog names it the editorial
decision, reversible at vetting. The other three were existing requirements that
no implementation enforced correctly: the changelog calls the artifact-only
two-subject statement "wrongly accepted" and one row per executed attack "a
well-formedness invariant", and out-of-range references were always a structural
fault. Recording all four as open corners was itself part of the problem, since it
let a defect and a design question sit in the same list.

## How this was built (from-spec discipline)

The from-spec claim covers stages one through four plus the tier; the
implementation was written against the specification text and the public
standards it pins, then run against the vector corpus. Files read, in full:

- The spec:
  `https://raw.githubusercontent.com/astrogilda/attestation/4a36b197/spec/predicates/adversarial-execution-evidence.md`
  (worked from a local copy verified byte-identical to that URL).
- From `astrogilda/aee-conformance`: `vectors/MANIFEST.json` (viewed only
  through a filter selecting id/kind/file/expected verdict/result/tier
  fields; no `codes` value was ever displayed, before or after the run),
  `vectors/CHANGES.md`, `vectors/keys/README.md`, the vector JSON files
  themselves (`vectors/accept/*.json`, `vectors/reject/*.json`), and the
  vendored `spec/predicates/adversarial-execution-evidence.md` only as a
  byte-diff against the branch-head spec (identical).
- From the top-level `README.md`: the key-derivation sentences (lines
  ~100-111). Locating them with a case-insensitive grep for "key" also
  displayed a handful of single stray lines elsewhere in the README
  (component one-liners and a paraphrase of the spec's tier rule at lines
  40/79-81/124-133); they are disclosed here for completeness and carried
  no implementation detail.
- Public standards: RFC 8785 (JCS), RFC 7493 (I-JSON), RFC 6962 (Merkle
  hashing), the DSSE spec (PAE), RFC 3339, RFC 8032 (via ed25519-dalek).

Never opened: `aee/`, `aeetest/`, `cmd/`, `witnessattestor/`, `scripts/`,
`packaging/`, `docs/`, `BUILD-NOTES.md`, `TODO.md`, `vectors/gen_manifest.py`,
`vectors/accept/gen_valid_vectors.py`, `vectors/reject/gen_invalid_vectors.py`,
the `INDEX.md` files inside the vector directories, and no `.go`, `.ts`, or
`.py` file anywhere in that repository. No web search for other AEE
implementations or discussions was performed. Directory listings exposed the
names of these paths, never their contents.

**Test-key discovery.** The suite's published recipe
(`seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`) names no roles.
The substrate observation role was discovered by deriving candidate role
strings under the recipe and probing them against a real vector signature:
the role is `substrate-observation-test`, and the corpus's `keyid`
convention is the SHA-256 of the raw 32-byte Ed25519 public key. The
checker pins that one derived key as consumer policy, exactly as the spec's
consumer-policy example pins a key out of band.

**Chronology.** The gate was implemented in full against the spec before the
first corpus run; the first full run scored 125/125, so no vector-driven
fixes were made and no fault was ever debugged by reading anything beyond
the spec and the vector bytes.

## Reproducing

```
cargo run --release -- <aee-conformance>/vectors --json report.json
```

Exit code 0 on full parity, 1 on any mismatch. `--role <name>` overrides the
pinned test-key role; `--discover-role <vector.json>` re-runs the role probe
against a vector's signatures.
