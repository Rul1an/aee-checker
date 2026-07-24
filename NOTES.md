# Notes: spec versions and corpus observations

## Vendored spec vs branch head

The conformance suite vendors the predicate spec at
`spec/predicates/adversarial-execution-evidence.md`. Compared (byte diff)
against the authoritative branch head at
`https://raw.githubusercontent.com/astrogilda/attestation/4a36b197/spec/predicates/adversarial-execution-evidence.md`:

**Byte-identical.** There are no normative (or editorial) differences
between the vendored spec and the branch-head spec, so no vector could be
affected by a version skew. Both carry:

- Type URI `https://in-toto.io/attestation/adversarial-execution-evidence/v0.6`,
  version 0.6.0;
- the BMP-only string profile on signed canonical surfaces;
- the optional `aeeRunSeq` / `aeePrevRunBinding` / `aeeChainScope`
  arming-payload run-chaining members;
- the numbered four-step byte-pure validity stage and the trust-relative
  tier stage.

The local working copy at `/tmp/aee-spec.md` was also byte-identical to the
branch head.

## Corpus observations

- `vectors/MANIFEST.json` enumerates 125 vectors (34 accept, 91 reject);
  the `accept/` and `reject/` directories contain exactly those 125 JSON
  files (plus generator scripts and INDEX files, which were not read).
- `vectors/CHANGES.md` declares suiteRevision 1, tracking PR #570 at commit
  `4a36b19` — consistent with the byte-identical spec diff above.
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
