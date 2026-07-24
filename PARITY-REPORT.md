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

The full machine-readable run record is `report.json` (one row per vector:
verdict, result, reason, tier columns, parity flag).

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
   appear in at least one of `assessedClasses` / `outOfScope` /
   `routedElsewhere` (from "empty objects when complete" plus the
   disclosed-gap rule), and every assessed class must exist in the manifest.
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
    rejected anywhere, not only inside record payloads). Only the
    payload-level duplicate has a corpus vector; statement-level strictness
    is this implementation's reading of the framework's parsing rules and is
    flagged here because a lenient reader could differ on a vector that does
    not currently exist.

Open points the corpus does not exercise (recorded for the author, not
divergences): duplicate `attackId` rows (this checker's union semantics
accept them), overlap between `assessedClasses` and the gap maps (accepted),
an artifact-only statement with two subjects (accepted, since the
malformedness sentence is scoped to substrate-row-carrying statements), and
out-of-range `observationRefs` on artifact rows (accepted, nothing normative
reads them).

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
