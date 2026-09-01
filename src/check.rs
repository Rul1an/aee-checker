//! Stage-one validity gate, `result` recompute, and evidence-tier
//! derivation for the Adversarial Execution Evidence predicate v0.6,
//! implemented from the specification text alone.
//!
//! Stage one is byte-pure and ordered per the spec's numbered steps:
//! (1) statement well-formedness (vocabulary rules, run-binding
//! derivability for substrate-carrying statements), (2) coverage validity,
//! (3) the `result` recompute, (4) manifest/vocabulary digest and
//! batch-root integrity. The evidence tier (stage two) is trust-relative
//! and never alters the verdict.

use crate::json::{self, Value};
use crate::keys;
use crate::merkle;
use crate::time;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str =
    "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7";

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Valid {
        result: String,
        /// Per-row tier with the consumer's pinned substrate key.
        tiers_with_key: Vec<String>,
        /// Per-row tier with no pinned substrate root.
        tiers_without_key: Vec<String>,
    },
    Invalid {
        reason: String,
        /// The condition this refusal forces, from the corpus's vocabulary.
        code: &'static str,
    },
}

/// One failure: the condition it forces, and the human-readable reason.
///
/// The code is the load-bearing half. Verdict parity is the weaker measure, since
/// a reject naming the wrong condition scores as agreement under it, and prose
/// cannot be compared against a condition vocabulary without inventing a map.
/// Carrying the code at the site of the refusal makes reason parity a comparison
/// instead of a construction.
struct Fail {
    code: &'static str,
    msg: String,
}

impl Fail {
    fn new(code: &'static str, msg: String) -> Self {
        Fail { code, msg }
    }
}

/// Transitional: a bare `Fail(msg)` still compiles and reports the catch-all
/// condition, so an uncoded site shows up in the measurement rather than
/// silently scoring as whatever the corpus expected.
#[allow(non_snake_case)]
fn Fail(msg: String) -> Fail {
    Fail::new("statement-malformed", msg)
}

type R<T> = Result<T, Fail>;

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn jcs_sha256_hex(v: &Value) -> R<String> {
    let bytes = json::to_canonical_bytes(v)
        .map_err(|e| Fail(format!("cannot canonicalize: {e}")))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn req<'a>(obj: &'a Value, key: &str, what: &str) -> R<&'a Value> {
    obj.get(key)
        .ok_or_else(|| Fail::new("required-member-absent", format!("{what} is missing required member \"{key}\"")))
}

fn req_str<'a>(obj: &'a Value, key: &str, what: &str) -> R<&'a str> {
    req(obj, key, what)?
        .as_str()
        .ok_or_else(|| Fail(format!("{what}.{key} is not a JSON string")))
}

fn req_obj<'a>(obj: &'a Value, key: &str, what: &str) -> R<&'a Value> {
    let v = req(obj, key, what)?;
    if v.as_object().is_none() {
        return Err(Fail(format!("{what}.{key} is not a JSON object")));
    }
    Ok(v)
}

fn req_arr<'a>(obj: &'a Value, key: &str, what: &str) -> R<&'a [Value]> {
    req(obj, key, what)?
        .as_array()
        .ok_or_else(|| Fail(format!("{what}.{key} is not a JSON array")))
}

/// digest.sha256 string of an observationEnvironment member.
fn digest_sha256<'a>(obj: &'a Value, what: &str) -> R<&'a str> {
    let digest = req_obj(obj, "digest", what)?;
    req_str(digest, "sha256", &format!("{what}.digest"))
}

// ---------------------------------------------------------------------------
// Observation records
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum Method {
    Intercepted,
    Reconstructed,
}

fn parse_method(tok: &str) -> Option<Method> {
    match tok {
        "intercepted" => Some(Method::Intercepted),
        "reconstructed" => Some(Method::Reconstructed),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RecordKind {
    Interception,
    Arming,
    Sealed,
    Examination,
    /// Registered by 0.7 and covering nothing by registration. Distinct from
    /// `Unknown` so a citation of a kind that covers nothing can be reported
    /// under a condition naming the kind, which the spec asks for as a
    /// diagnostic obligation rather than a validity rule.
    CoversNothing,
    Unknown,
}

fn parse_kind(tok: &str) -> RecordKind {
    match tok {
        "interception" => RecordKind::Interception,
        "arming" => RecordKind::Arming,
        "sealed" => RecordKind::Sealed,
        "examination" => RecordKind::Examination,
        "moat-drop" | "uncommitted-observation" => RecordKind::CoversNothing,
        _ => RecordKind::Unknown,
    }
}

/// A duplicate-free array of lowercase 64-hex strings, sorted strictly
/// ascending by UTF-16 code unit. Three 0.7 members carry this shape
/// (`aeePayloadCommitment`) or its attack-identifier sibling; the sortedness
/// rule is the one the vocabulary arrays already carry (RFC 8785 3.2.3).
fn read_sorted_unique_strings(
    payload: &Value,
    member: &str,
    what: &str,
    require_hex64: bool,
) -> Result<Vec<String>, String> {
    let v = payload
        .get(member)
        .ok_or_else(|| format!("{what} payload is missing {member}"))?;
    let arr = v
        .as_array()
        .ok_or_else(|| format!("{what} {member} is not a JSON array"))?;
    let mut out: Vec<String> = Vec::new();
    let mut prev: Option<Vec<u16>> = None;
    for (i, e) in arr.iter().enumerate() {
        let s = e
            .as_str()
            .ok_or_else(|| format!("{what} {member}[{i}] is not a JSON string"))?;
        if require_hex64 && !is_lower_hex64(s) {
            return Err(format!("{what} {member}[{i}] is not lowercase 64-hex"));
        }
        let units = json::utf16_units(s);
        if let Some(p) = &prev {
            if *p >= units {
                return Err(format!(
                    "{what} {member} is not strictly ascending by UTF-16 code unit at index {i}"
                ));
            }
        }
        prev = Some(units);
        out.push(s.to_string());
    }
    Ok(out)
}

struct RecordEval {
    pae: Vec<u8>,
    leaf: [u8; 32],
    /// base64-decoded signature bytes (one per envelope signature)
    sig_bytes: Vec<Vec<u8>>,
    /// media type ends in +json
    json_media_type: bool,
    /// canonical, I-JSON-valid, BMP-member-name object payload
    payload: Option<Value>,
    /// error explaining why `payload` is None or non-canonical
    payload_err: Option<String>,
}

/// Recursively enforce the I-JSON safe-integer profile and BMP-only member
/// names on a signed canonical payload.
fn payload_profile_ok(v: &Value) -> Result<(), String> {
    match v {
        Value::Number { raw, value } => {
            let integral = !raw.contains(['.', 'e', 'E']);
            if integral && json::parse_safe_integer(raw).is_none() {
                return Err(format!("integer {raw} is outside the I-JSON safe range"));
            }
            // Non-integral numbers must still be finite doubles (parser enforced).
            let _ = value;
            Ok(())
        }
        Value::Array(items) => {
            for i in items {
                payload_profile_ok(i)?;
            }
            Ok(())
        }
        Value::Object(members) => {
            for (k, val) in members {
                if !json::is_bmp_only(k) {
                    return Err(format!(
                        "member name {k:?} carries a code point above U+FFFF"
                    ));
                }
                payload_profile_ok(val)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn eval_record(rec: &Value, idx: usize) -> R<RecordEval> {
    let what = format!("observationRecords[{idx}]");
    if rec.as_object().is_none() {
        return Err(Fail(format!("{what} is not a JSON object")));
    }
    let payload_b64 = req_str(rec, "payload", &what)?;
    let payload_type = req_str(rec, "payloadType", &what)?;
    let sigs = req_arr(rec, "signatures", &what)?;
    if sigs.is_empty() {
        return Err(Fail::new("record-signatures-empty", format!("{what}.signatures carries no entry")));
    }
    let mut sig_bytes = Vec::new();
    for (i, s) in sigs.iter().enumerate() {
        if s.as_object().is_none() {
            return Err(Fail(format!("{what}.signatures[{i}] is not a JSON object")));
        }
        let sig = req_str(s, "sig", &format!("{what}.signatures[{i}]"))?;
        if let Some(kid) = s.get("keyid") {
            if kid.as_str().is_none() {
                return Err(Fail(format!(
                    "{what}.signatures[{i}].keyid is not a JSON string"
                )));
            }
        }
        let bytes = B64
            .decode(sig)
            .map_err(|_| Fail::new("record-undecodable", format!("{what}.signatures[{i}].sig is not valid base64")))?;
        sig_bytes.push(bytes);
    }
    // Strict, canonical base64: decode with the standard alphabet and
    // require the re-encoding to reproduce the carried text, so a payload
    // smuggled through a lenient decoder is rejected as undecodable.
    let payload_bytes = B64.decode(payload_b64).map_err(|_| {
        Fail::new("record-undecodable", format!("{what}.payload is not valid base64"))
    })?;
    if B64.encode(&payload_bytes) != payload_b64 {
        return Err(Fail(format!(
            "{what}.payload is not canonical base64 for the bytes it encodes"
        )));
    }
    let pae = merkle::pae(payload_type, &payload_bytes);
    let leaf = merkle::leaf_hash(&pae);

    let json_media_type = payload_type.ends_with("+json");
    let (payload, payload_err) = match json::parse(&payload_bytes) {
        Ok(v) => {
            if v.as_object().is_none() {
                (None, Some("payload is not a JSON object".to_string()))
            } else if let Err(e) = payload_profile_ok(&v) {
                (None, Some(e))
            } else {
                match json::to_canonical_bytes(&v) {
                    Ok(c) if c == payload_bytes => (Some(v), None),
                    Ok(_) => (
                        None,
                        Some("payload bytes are not in RFC 8785 canonical form".to_string()),
                    ),
                    Err(e) => (None, Some(format!("payload cannot canonicalize: {e}"))),
                }
            }
        }
        Err(e) => (None, Some(format!("payload does not parse as JSON: {e}"))),
    };
    Ok(RecordEval {
        pae,
        leaf,
        sig_bytes,
        json_media_type,
        payload,
        payload_err,
    })
}

/// Outcome of evaluating one referenced record against the run binding and
/// its kind-specific constraints.
struct CoverEval {
    kind: RecordKind,
    method: Option<Method>,
    /// Some(reason) when the record covers nothing for kind-constraint
    /// reasons (distinct from the hard validity requirements).
    non_covering: Option<String>,
    /// For sealed records: additionally covers a clean row, on the conjuncts
    /// that are properties of the record alone.
    sealed_covers_clean: bool,
    /// For sealed records: which of those conjuncts failed, each one evaluated.
    /// Carried so a refusal names the comparisons that ran and failed rather
    /// than the whole conjunction.
    sealed_clean_failures: Vec<&'static str>,
    /// For sealed records: the declared `aeePostureDigest`. Carried out rather
    /// than compared inside, because the remaining conjunct is a property of
    /// (record, row) and this value is cached per record.
    sealed_posture: Option<String>,
}

struct Ctx<'a> {
    run_binding: &'a str,
    posture_digest: &'a str,
    issued_at: time::Instant,
    /// Every attackId the carried manifest declares. `aeeAssessedAttacks` and
    /// `aeeObservedAttacks` entries must each be one of these.
    manifest_attacks: &'a [String],
    /// The value `aeeObservedSet` must equal, recomputed over the carried
    /// interception and examination records.
    observed_set: &'a str,
}

/// The `aeeKind` token of a carried record, read without applying any
/// kind-specific constraint. Needed because 0.7 requirements range over every
/// carried record rather than only the referenced ones: the `aeeObservedSet`
/// recompute, the interception-is-resolved rule, and the unconditional sealed
/// requirement all quantify over the whole array.
fn record_kind_of(rec: &RecordEval) -> RecordKind {
    match rec.payload.as_ref().and_then(|p| p.get("aeeKind")).and_then(|v| v.as_str()) {
        Some(tok) => parse_kind(tok),
        None => RecordKind::Unknown,
    }
}

/// The hard part of the coverage-validity bullet: every referenced payload
/// must be a canonical `+json` object carrying the reserved members with
/// `aeeRunBinding` equal to the derived binding. A violation here is an
/// attestation-validity failure.
fn referenced_record_validity(rec: &RecordEval, idx: usize, ctx: &Ctx) -> R<CoverEval> {
    let what = format!("observationRecords[{idx}]");
    if !rec.json_media_type {
        return Err(Fail::new("payload-media-type", format!(
            "{what} covers a substrate row but its payloadType does not end in +json"
        )));
    }
    let payload = rec.payload.as_ref().ok_or_else(|| {
        Fail::new("payload-not-ijson", format!(
            "{what} covers a substrate row but its payload is not a canonical I-JSON object: {}",
            rec.payload_err.as_deref().unwrap_or("unknown")
        ))
    })?;
    let binding = req_str(payload, "aeeRunBinding", &format!("{what} payload"))?;
    let kind_tok = req_str(payload, "aeeKind", &format!("{what} payload"))?;
    let method_tok = req_str(payload, "aeeMethod", &format!("{what} payload"))?;
    // The spec has the verifier read aeeBindingVersion BEFORE deriving, and
    // reject an unimplemented version fail-closed as "the arming record covers
    // nothing", distinguishably from a run-binding digest mismatch. Both halves
    // matter: read after the comparison and the digest mismatch masks it, and
    // failed at statement altitude it over-rejects a statement that carries a
    // second, valid arming record.
    let unimplemented_binding_version = match payload.get("aeeBindingVersion") {
        Some(bv) => bv.as_str() != Some("2"),
        None => false,
    };
    if !unimplemented_binding_version && binding != ctx.run_binding {
        return Err(Fail::new("run-binding-mismatch", format!(
            "{what} payload aeeRunBinding does not equal the run binding derived from this statement"
        )));
    }
    let kind = parse_kind(kind_tok);
    let method = parse_method(method_tok);
    let mut non_covering: Option<String> = None;
    let mut sealed_covers_clean = false;
    let mut sealed_clean_failures: Vec<&'static str> = Vec::new();
    let mut sealed_posture: Option<String> = None;

    if unimplemented_binding_version {
        non_covering = Some(format!(
            "{what} payload declares a run-binding version this verifier does not implement, so the record covers nothing"
        ));
    } else if kind == RecordKind::CoversNothing {
        // Registered, verified, included in the batchRoot recompute, and
        // admitted to nothing: not a row's coverage, not the method cap, not
        // the aeeObservedSet recompute.
        non_covering = Some(format!(
            "record kind {kind_tok:?} is registered and covers nothing by registration"
        ));
    } else if kind == RecordKind::Unknown {
        non_covering = Some(format!("record kind {kind_tok:?} is not recognized"));
    } else if method.is_none() {
        non_covering = Some(format!(
            "record aeeMethod {method_tok:?} is outside the closed vocabulary"
        ));
    } else {
        match kind {
            RecordKind::Interception => {
                // 0.7: names what an interception has always carried and had
                // no reserved spelling for. Required, non-empty, hex64.
                match read_sorted_unique_strings(
                    payload,
                    "aeePayloadCommitment",
                    "interception record",
                    true,
                ) {
                    Ok(c) if c.is_empty() => {
                        non_covering =
                            Some("interception record aeePayloadCommitment is empty".into());
                    }
                    Ok(_) => {}
                    Err(e) => non_covering = Some(e),
                }
            }
            RecordKind::Arming => {
                if method != Some(Method::Intercepted) {
                    non_covering =
                        Some("arming record is not signed aeeMethod intercepted".into());
                } else if let Err(e) = check_arming(payload, ctx) {
                    non_covering = Some(e.msg);
                }
            }
            RecordKind::Sealed => {
                if method != Some(Method::Intercepted) {
                    non_covering =
                        Some("sealed record is not signed aeeMethod intercepted".into());
                } else {
                    match check_sealed(payload, ctx) {
                        Ok((failures, posture)) => {
                            sealed_covers_clean = failures.is_empty();
                            sealed_clean_failures = failures;
                            sealed_posture = Some(posture);
                        }
                        Err(e) => non_covering = Some(e.msg),
                    }
                }
            }
            RecordKind::Examination => {
                if method != Some(Method::Reconstructed) {
                    non_covering =
                        Some("examination record is not signed aeeMethod reconstructed".into());
                }
            }
            RecordKind::Unknown | RecordKind::CoversNothing => unreachable!(),
        }
    }
    Ok(CoverEval {
        kind,
        method,
        non_covering,
        sealed_covers_clean,
        sealed_clean_failures,
        sealed_posture,
    })
}

/// Arming-record constraints: armedAt in RFC 3339 UTC no later than
/// issuedAt, aeePostureDigest equal to the pinned networkPosture digest,
/// plus the run-chaining member syntax. A violation means the record
/// covers nothing.
fn check_arming(payload: &Value, ctx: &Ctx) -> R<()> {
    let armed_at = payload
        .get("armedAt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Fail("arming record payload is missing armedAt".into()))?;
    let parsed = time::parse_rfc3339(armed_at)
        .ok_or_else(|| Fail("arming record armedAt is not an RFC 3339 timestamp".into()))?;
    if !parsed.profile_ok {
        return Err(Fail(
            "arming record armedAt is RFC 3339 but outside the timestamp profile".into(),
        ));
    }
    if parsed.instant > ctx.issued_at {
        return Err(Fail("arming record armedAt is later than issuedAt".into()));
    }
    // 0.7: the attacks this run declared, before injection, it would assess.
    let assessed = read_sorted_unique_strings(payload, "aeeAssessedAttacks", "arming record", false)
        .map_err(Fail)?;
    for a in &assessed {
        if !ctx.manifest_attacks.iter().any(|m| m == a) {
            return Err(Fail::new(
            "arming-covers-nothing", format!(
                "arming record aeeAssessedAttacks entry {a:?} is not an attackId the carried manifest declares"
            )));
        }
    }
    let posture = payload
        .get("aeePostureDigest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Fail("arming record payload is missing aeePostureDigest".into()))?;
    if posture != ctx.posture_digest {
        return Err(Fail(
            "arming record aeePostureDigest differs from the pinned networkPosture digest".into(),
        ));
    }
    // Optional run-chaining members: syntax-checked in the reserved-member
    // walk; a violation means the record covers nothing.
    let run_seq = payload.get("aeeRunSeq");
    let prev = payload.get("aeePrevRunBinding");
    let scope = payload.get("aeeChainScope");
    match run_seq {
        None => {
            if prev.is_some() || scope.is_some() {
                return Err(Fail(
                    "arming record carries run-chaining members without aeeRunSeq".into(),
                ));
            }
        }
        Some(seq) => {
            let n = seq
                .as_safe_integer()
                .ok_or_else(|| Fail("arming record aeeRunSeq is not a safe-range integer".into()))?;
            if n < 1 {
                return Err(Fail("arming record aeeRunSeq is not positive".into()));
            }
            // Spec: aeeChainScope is "a duplicate-free array of dimension tokens drawn
            // from the closed vocabulary registered below, sorted in the same canonical
            // order as observationVocabulary.labels (UTF-16 code-unit order, RFC 8785
            // section 3.2.3); REQUIRED whenever aeeRunSeq is present". Each token pins a
            // projection to a value already on the wire: subject, corpus, networkPosture.
            // A non-array, an unregistered token, or a non-canonical array is a
            // reserved-member violation, so the record covers nothing. The revision-1
            // free-form string has no alias and fails closed.
            //
            // This previously read the member through `as_str()`, which is the whole of
            // the old contract: an array yielded None and a plain string passed.
            match scope {
                None => {
                    return Err(Fail(
                        "arming record aeeRunSeq is present without an aeeChainScope".into(),
                    ))
                }
                Some(v) => {
                    let arr = v.as_array().ok_or_else(|| {
                        Fail("arming record aeeChainScope is not a JSON array".into())
                    })?;
                    // The empty array is legal: the spec calls it the single global
                    // per-key counter and warns that it makes the chain rules vacuous,
                    // rather than forbidding it.
                    // Named apart from the outer `prev` (`aeePrevRunBinding`), which is
                    // still live at the `match (n, prev)` below.
                    let mut prev_token: Option<Vec<u16>> = None;
                    for (i, t) in arr.iter().enumerate() {
                        let tok = t.as_str().ok_or_else(|| {
                            Fail::new("arming-covers-nothing", format!("arming record aeeChainScope[{i}] is not a JSON string"))
                        })?;
                        if !matches!(tok, "subject" | "corpus" | "networkPosture") {
                            return Err(Fail::new(
            "vocabulary-not-canonical", format!(
                                "arming record aeeChainScope[{i}] {tok:?} is outside the closed dimension vocabulary"
                            )));
                        }
                        let units = json::utf16_units(tok);
                        if let Some(p) = &prev_token {
                            if *p >= units {
                                return Err(Fail::new("arming-covers-nothing", format!(
                                    "arming record aeeChainScope is not strictly ascending by UTF-16 code unit at index {i}"
                                )));
                            }
                        }
                        prev_token = Some(units);
                    }
                }
            }
            match (n, prev) {
                (1, None) => {}
                (1, Some(_)) => {
                    return Err(Fail(
                        "arming record carries aeePrevRunBinding at aeeRunSeq 1".into(),
                    ))
                }
                (_, None) => {
                    return Err(Fail(
                        "arming record aeeRunSeq exceeds 1 without aeePrevRunBinding".into(),
                    ))
                }
                (_, Some(p)) => {
                    let ok = p.as_str().is_some_and(is_lower_hex64);
                    if !ok {
                        return Err(Fail(
                            "arming record aeePrevRunBinding is not a lowercase 64-hex digest"
                                .into(),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Sealed-record constraints. Returns whether the record covers a clean
/// row; a structural violation is an error (covers nothing at all).
/// Assemble the carried-record sweep's refusal from the comparisons that were
/// actually evaluated on this statement and failed.
///
/// A refusal message is a claim about which comparisons ran, so the set it
/// describes has to be the set that was evaluated. Three ways that can break,
/// all of which this function exists to prevent and all of which the corpus is
/// blind to, since verdicts are unchanged either way:
///
///   1. Naming a comparison that never ran. The record-local conjuncts are
///      evaluated individually in `check_sealed` rather than under `&&`, and
///      only the ones that failed are named.
///   2. Naming a comparison whose operand set is empty. `all()` over an empty
///      set is vacuously true, so the arming term decides nothing there and is
///      omitted rather than asserted.
///   3. Describing a set wider than the one compared. The operands are the
///      arming records the rows resolve, never "every carried arming record",
///      a phrase that appears nowhere in the specification.
fn sealed_sweep_reason(
    idx: usize,
    clean_failures: &[&'static str],
    sealed_posture: Option<&str>,
    arming_postures: &[String],
) -> String {
    let mut failed: Vec<String> = clean_failures.iter().map(|s| (*s).to_string()).collect();
    match sealed_posture {
        // Unreachable for a sealed record whose `non_covering` is None, since
        // `check_sealed` requires the member. Named explicitly so an absent
        // value cannot read as a comparison that was made and failed.
        None => failed.push("aeePostureDigest is absent".to_string()),
        Some(pd) if !arming_postures.is_empty() && !arming_postures.iter().all(|a| a == pd) => {
            let n = arming_postures.len();
            failed.push(format!(
                "aeePostureDigest differs from the aeePostureDigest of the {n} arming record{} the rows resolve",
                if n == 1 { "" } else { "s" }
            ));
        }
        Some(_) => {}
    }
    format!(
        "observationRecords[{idx}] is a sealed record binding to this run whose clean-row conjuncts do not hold: {}",
        failed.join("; ")
    )
}

/// The set the `aeeObservedSet` recompute evaluates, named once so both
/// refusal sites state the same set. The recompute filters the carried array
/// to `interception` and `examination` records, and a refusal saying "the
/// carried records" names every carried kind, including `arming` and `sealed`
/// records the recompute never reads: a wider set than the one evaluated,
/// which tells the producer to repair records the check never read.
const OBSERVED_SET_EVALUATED: &str = "the carried interception and examination records";

fn check_sealed(payload: &Value, ctx: &Ctx) -> R<(Vec<&'static str>, String)> {
    let still_armed = payload
        .get("aeeStillArmed")
        .ok_or_else(|| Fail("sealed record payload is missing aeeStillArmed".into()))?
        .as_bool()
        .ok_or_else(|| Fail("sealed record aeeStillArmed is not a boolean".into()))?;
    let drop_count = payload
        .get("aeeDropCount")
        .ok_or_else(|| Fail("sealed record payload is missing aeeDropCount".into()))?
        .as_safe_integer()
        .ok_or_else(|| Fail("sealed record aeeDropCount is not a safe-range integer".into()))?;
    if drop_count < 0 {
        return Err(Fail("sealed record aeeDropCount is negative".into()));
    }
    let posture = payload
        .get("aeePostureDigest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Fail("sealed record payload is missing aeePostureDigest".into()))?;
    let drop_bound = match payload.get("aeeDropBound") {
        None => None,
        Some(v) => Some(v.as_safe_integer().ok_or_else(|| {
            Fail("sealed record aeeDropBound is not a safe-range integer".into())
        })?),
    };
    // 0.7: a commitment, by a party that does not control the carried set, to
    // the set of interception and examination records the substrate emitted.
    let observed_set = payload
        .get("aeeObservedSet")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Fail("sealed record payload is missing aeeObservedSet".into()))?;
    if !is_lower_hex64(observed_set) {
        return Err(Fail("sealed record aeeObservedSet is not lowercase 64-hex".into()));
    }
    if observed_set != ctx.observed_set {
        return Err(Fail(format!(
            "sealed record aeeObservedSet does not equal the value recomputed over {OBSERVED_SET_EVALUATED}"
        )));
    }
    // 0.7: the attacks this run attributed at least one of its own
    // observations to. The empty array is the honest value and is required
    // rather than omissible, so a substrate holding no correspondence says so
    // on the wire instead of leaving an absence nothing records.
    let observed_attacks =
        read_sorted_unique_strings(payload, "aeeObservedAttacks", "sealed record", false)
            .map_err(Fail)?;
    for a in &observed_attacks {
        if !ctx.manifest_attacks.iter().any(|m| m == a) {
            return Err(Fail::new("observed-attack-uncaught", format!(
                "sealed record aeeObservedAttacks entry {a:?} is not an attackId the carried manifest declares"
            )));
        }
    }
    // Clean-row covering conditions (each a check on signed carried bytes).
    // The spec: a sealed record covers no clean row unless its aeePostureDigest
    // "equals both the arming record's and the pinned networkPosture digest".
    // The pinned conjunct alone leaves an arming/sealed posture disagreement
    // uncaught on a statement whose pinned comparison passes.
    // The arming conjunct is deliberately NOT evaluated here. Spec: a sealed
    // record's posture must equal "the pinned `networkPosture` digest and the
    // `aeePostureDigest` of every `arming` record the row resolves". That set is
    // a property of the ROW, and this function's result is memoised per record
    // in `cover_cache`, so folding a row-dependent term in here would let the
    // first row that resolves a record decide the answer for every later one.
    // The caller applies it against the set the row itself resolves.
    //
    // Every conjunct is evaluated rather than short-circuited, so a refusal can
    // name the ones that actually failed. Under `&&` a caller could only name the
    // whole conjunction, which reported comparisons that never ran: `bad-1003`
    // through `bad-1006` fail on four different conjuncts and emitted one
    // byte-identical string. A refusal is a claim about which comparisons ran,
    // so the set it names has to be the set that was evaluated.
    let mut clean_failures: Vec<&'static str> = Vec::new();
    if !still_armed {
        clean_failures.push("aeeStillArmed is false");
    }
    if !(drop_count == 0 || drop_bound.is_some_and(|b| drop_count <= b)) {
        clean_failures
            .push("aeeDropCount is non-zero and exceeds its aeeDropBound, or declares no bound");
    }
    if posture != ctx.posture_digest {
        clean_failures.push("aeePostureDigest differs from the pinned networkPosture digest");
    }
    Ok((clean_failures, posture.to_string()))
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

struct Row<'a> {
    attack_id: &'a str,
    /// containmentObserved token, None when the member is absent.
    label: Option<&'a str>,
    basis: Option<&'a str>,
    method: Option<&'a str>,
    /// 0.7: how firmly the row is bound to the records that cover it.
    /// Closed vocabulary `pinned` / `paired`, fail-closed on absence or an
    /// unrecognized value exactly as `basis` and `method` are.
    attribution: Option<&'a str>,
    refs: Vec<i64>,
}

fn parse_row<'a>(row: &'a Value, idx: usize) -> R<Row<'a>> {
    let what = format!("attackResults[{idx}]");
    if row.as_object().is_none() {
        return Err(Fail(format!("{what} is not a JSON object")));
    }
    let attack_id = req_str(row, "attackId", &what)?;
    // Members the recompute reads are fail-closed on ABSENCE; a present
    // member of the wrong JSON type is a decode-layer fault and the
    // statement is malformed.
    let label = match row.get("containmentObserved") {
        None => None,
        Some(v) => Some(v.as_str().ok_or_else(|| {
            Fail(format!("{what}.containmentObserved is not a JSON string"))
        })?),
    };
    let basis = match row.get("basis") {
        None => None,
        Some(v) => {
            Some(v.as_str().ok_or_else(|| Fail(format!("{what}.basis is not a JSON string")))?)
        }
    };
    let method = match row.get("method") {
        None => None,
        Some(v) => {
            Some(v.as_str().ok_or_else(|| Fail(format!("{what}.method is not a JSON string")))?)
        }
    };
    let attribution = match row.get("attribution") {
        None => None,
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| Fail::new("statement-malformed", format!("{what}.attribution is not a JSON string")))?,
        ),
    };
    // actualLayer is required on every row: a missing member is a
    // malformed statement, and so is a wrong-typed one.
    match row.get("actualLayer") {
        None => {
            return Err(Fail::new("malformed-missing-actual-layer", format!(
                "{what} is missing the required actualLayer member"
            )))
        }
        Some(v) => {
            if v.as_str().is_none() {
                return Err(Fail::new("malformed-missing-actual-layer", format!("{what}.actualLayer is not a JSON string")));
            }
        }
    }
    let mut refs = Vec::new();
    if let Some(r) = row.get("observationRefs") {
        let arr = r
            .as_array()
            .ok_or_else(|| Fail::new("ref-malformed", format!("{what}.observationRefs is not a JSON array")))?;
        for (i, v) in arr.iter().enumerate() {
            let n = v.as_safe_integer().ok_or_else(|| {
                Fail::new("ref-malformed", format!(
                    "{what}.observationRefs[{i}] is not an integer index"
                ))
            })?;
            refs.push(n);
        }
    }
    if let Some(sel) = row.get("observationSelectors") {
        let arr = sel
            .as_array()
            .ok_or_else(|| Fail(format!("{what}.observationSelectors is not a JSON array")))?;
        for (i, v) in arr.iter().enumerate() {
            if v.as_str().is_none() {
                return Err(Fail(format!(
                    "{what}.observationSelectors[{i}] is not a JSON string"
                )));
            }
        }
    }
    Ok(Row {
        attack_id,
        label,
        basis,
        method,
        attribution,
        refs,
    })
}

// ---------------------------------------------------------------------------
// The checker
// ---------------------------------------------------------------------------

pub fn check(statement_bytes: &[u8], pinned_key: Option<&VerifyingKey>) -> Verdict {
    match check_inner(statement_bytes, pinned_key) {
        Ok(v) => v,
        Err(f) => Verdict::Invalid { reason: f.msg, code: f.code },
    }
}

fn check_inner(statement_bytes: &[u8], pinned_key: Option<&VerifyingKey>) -> R<Verdict> {
    let stmt = json::parse(statement_bytes)
        .map_err(|e| Fail(format!("statement does not parse as strict JSON: {e}")))?;
    if stmt.as_object().is_none() {
        return Err(Fail("statement is not a JSON object".into()));
    }
    if req_str(&stmt, "_type", "statement")? != STATEMENT_TYPE {
        return Err(Fail(format!("statement _type is not {STATEMENT_TYPE}")));
    }
    if req_str(&stmt, "predicateType", "statement")? != PREDICATE_TYPE {
        return Err(Fail(format!("predicateType is not {PREDICATE_TYPE}")));
    }
    let subjects = req_arr(&stmt, "subject", "statement")?;
    if subjects.is_empty() {
        return Err(Fail("statement carries no subject".into()));
    }
    let pred = req_obj(&stmt, "predicate", "statement")?;

    // The retired snake_case spelling is rejected, not aliased.
    if pred.get("does_not_assert").is_some() {
        return Err(Fail(
            "predicate carries the retired snake_case does_not_assert spelling".into(),
        ));
    }
    // Predicate-level members beginning with the reserved `aee` prefix and
    // a carried `evidenceTier` are ignored: not read, never a failure.

    if let Some(dna) = pred.get("doesNotAssert") {
        let arr = dna
            .as_array()
            .ok_or_else(|| Fail("doesNotAssert is not a JSON array".into()))?;
        for (i, v) in arr.iter().enumerate() {
            if v.as_str().is_none() {
                return Err(Fail(format!("doesNotAssert[{i}] is not a JSON string")));
            }
        }
    }

    let issued_at_str = req_str(pred, "issuedAt", "predicate")?;
    let issued_at_parsed = time::parse_rfc3339(issued_at_str)
        .ok_or_else(|| Fail("issuedAt is not an RFC 3339 timestamp".into()))?;
    // One profile for both timestamps: uppercase separator and designator, and
    // a zone of Z, +00:00 or -00:00. Restating half of it on one field is what
    // let a statement be conformant here and off-guideline at the same time.
    if !issued_at_parsed.profile_ok {
        return Err(Fail::new("issued-at-outside-profile", 
            "issuedAt is RFC 3339 but outside this predicate's timestamp profile".into(),
        ));
    }
    let issued_at = issued_at_parsed.instant;

    let carried_result = req_str(pred, "result", "predicate")?;

    // ---- observationEnvironment ------------------------------------------
    let env = req_obj(pred, "observationEnvironment", "predicate")?;
    let substrate = req_obj(env, "substrate", "observationEnvironment")?;
    let corpus = req_obj(env, "corpus", "observationEnvironment")?;
    let catch_policy = req_obj(env, "catchPolicy", "observationEnvironment")?;
    let posture = req_obj(env, "networkPosture", "observationEnvironment")?;
    let vocab = req_obj(env, "observationVocabulary", "observationEnvironment")?;

    req_str(substrate, "name", "observationEnvironment.substrate")?;
    let substrate_digest = digest_sha256(substrate, "observationEnvironment.substrate")?;
    req_str(corpus, "name", "observationEnvironment.corpus")?;
    req_str(corpus, "uri", "observationEnvironment.corpus")?;
    let corpus_digest = digest_sha256(corpus, "observationEnvironment.corpus")?;
    let manifest = req_obj(corpus, "manifest", "observationEnvironment.corpus")?;
    let catch_policy_digest = digest_sha256(catch_policy, "observationEnvironment.catchPolicy")?;
    let posture_token = req_str(posture, "posture", "observationEnvironment.networkPosture")?;
    // Closed by registration: a minor version MAY append a value and MUST NOT
    // redefine one, so an unregistered value is malformed rather than ignored.
    if !matches!(
        posture_token,
        "allowlist" | "no_network" | "sinkhole" | "unsafe_bypass_egress"
    ) {
        return Err(Fail::new("posture-vocabulary", format!(
            "networkPosture.posture {posture_token:?} is outside the registered vocabulary"
        )));
    }
    let posture_digest = digest_sha256(posture, "observationEnvironment.networkPosture")?;

    // ---- observationVocabulary rules --------------------------------------
    let labels_arr = req_arr(vocab, "labels", "observationVocabulary")?;
    let caught_arr = req_arr(vocab, "caught", "observationVocabulary")?;
    let vocab_digest = digest_sha256(vocab, "observationVocabulary")?;
    let check_vocab_array = |arr: &[Value], name: &str| -> R<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        let mut prev: Option<Vec<u16>> = None;
        for (i, v) in arr.iter().enumerate() {
            let s = v.as_str().ok_or_else(|| {
                Fail::new("vocabulary-missing", format!("observationVocabulary.{name}[{i}] is not a JSON string"))
            })?;
            if !json::is_bmp_only(s) {
                return Err(Fail::new("vocabulary-missing", format!(
                    "observationVocabulary.{name} entry {s:?} carries a code point above U+FFFF"
                )));
            }
            let units = json::utf16_units(s);
            if let Some(p) = &prev {
                if *p >= units {
                    return Err(Fail::new(
            "vocabulary-not-canonical", format!(
                        "observationVocabulary.{name} is not strictly ascending by UTF-16 code unit at index {i}"
                    )));
                }
            }
            prev = Some(units);
            out.push(s.to_string());
        }
        Ok(out)
    };
    let labels = check_vocab_array(labels_arr, "labels")?;
    let caught = check_vocab_array(caught_arr, "caught")?;
    for c in &caught {
        if !labels.contains(c) {
            return Err(Fail::new("vocabulary-caught-not-subset", format!(
                "observationVocabulary.caught entry {c:?} is not in labels"
            )));
        }
    }
    // Vocabulary digest integrity: JCS of {"caught": [...], "labels": [...]}.
    let vocab_preimage = Value::Object(vec![
        (
            "caught".to_string(),
            Value::Array(caught.iter().cloned().map(Value::String).collect()),
        ),
        (
            "labels".to_string(),
            Value::Array(labels.iter().cloned().map(Value::String).collect()),
        ),
    ]);
    if jcs_sha256_hex(&vocab_preimage)? != vocab_digest {
        return Err(Fail(
            "observationVocabulary.digest does not re-derive from the carried labels and caught arrays".into(),
        ));
    }

    // ---- corpus manifest and digest integrity ------------------------------
    let classes = req_obj(manifest, "classes", "corpus.manifest")?;
    let mut manifest_attacks: Vec<(String, String)> = Vec::new(); // (class, attackId)
    for (class, ids) in classes.as_object().unwrap() {
        let arr = ids.as_array().ok_or_else(|| {
            Fail(format!("corpus.manifest.classes[{class:?}] is not a JSON array"))
        })?;
        for (i, v) in arr.iter().enumerate() {
            let id = v.as_str().ok_or_else(|| {
                Fail(format!(
                    "corpus.manifest.classes[{class:?}][{i}] is not a JSON string"
                ))
            })?;
            if manifest_attacks.iter().any(|(_, a)| a == id) {
                return Err(Fail(format!(
                    "attackId {id:?} appears under more than one manifest class"
                )));
            }
            manifest_attacks.push((class.clone(), id.to_string()));
        }
    }
    // 0.7: optional map from attackId to the commitment values a substrate is
    // expected to carry when it observes that attack. Every key must be an
    // attackId the same manifest declares; every array non-empty, sorted
    // ascending by UTF-16 code unit, duplicate-free, lowercase 64-hex. A
    // manifest violating any of these is malformed.
    let mut expected_payloads: Vec<(String, Vec<String>)> = Vec::new();
    if let Some(ep) = manifest.get("expectedPayloads") {
        let obj = ep.as_object().ok_or_else(|| {
            Fail("corpus.manifest.expectedPayloads is not a JSON object".into())
        })?;
        for (attack, _vals) in obj {
            if !manifest_attacks.iter().any(|(_, a)| a == attack) {
                return Err(Fail::new("manifest-expected-payloads-malformed", format!(
                    "corpus.manifest.expectedPayloads key {attack:?} is not an attackId the manifest declares"
                )));
            }
            let entries = read_sorted_unique_strings(
                ep,
                attack,
                "corpus.manifest.expectedPayloads",
                true,
            )
            .map_err(Fail)?;
            if entries.is_empty() {
                return Err(Fail::new("manifest-expected-payloads-malformed", format!(
                    "corpus.manifest.expectedPayloads[{attack:?}] is empty"
                )));
            }
                    expected_payloads.push((attack.clone(), entries));
        }
    }

    // The manifest floor: coverage integrity is only as strong as the manifest
    // it reads against, so a manifest declaring zero attack identifiers makes
    // the statement malformed. Phrased over identifiers rather than classes
    // because an empty classes object and a named class with an empty array are
    // the same defect.
    if manifest_attacks.is_empty() {
        return Err(Fail::new("manifest-declares-no-attack", 
            "corpus.manifest declares no attack identifier across its classes".into(),
        ));
    }

    if jcs_sha256_hex(manifest)? != corpus_digest {
        return Err(Fail(
            "corpus.digest does not re-derive from the embedded manifest".into(),
        ));
    }

    // ---- coverage -----------------------------------------------------------
    let coverage = req_obj(pred, "coverage", "predicate")?;
    let assessed_arr = req_arr(coverage, "assessedClasses", "coverage")?;
    let mut assessed: Vec<String> = Vec::new();
    for (i, v) in assessed_arr.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| Fail(format!("coverage.assessedClasses[{i}] is not a JSON string")))?;
        assessed.push(s.to_string());
    }
    let read_reason_map = |key: &str| -> R<Vec<String>> {
        let m = req_obj(coverage, key, "coverage")?;
        let mut out = Vec::new();
        for (class, reason) in m.as_object().unwrap() {
            if reason.as_str().is_none() {
                return Err(Fail(format!(
                    "coverage.{key}[{class:?}] is not a reason string"
                )));
            }
            out.push(class.clone());
        }
        Ok(out)
    };
    let out_of_scope = read_reason_map("outOfScope")?;
    let routed_elsewhere = read_reason_map("routedElsewhere")?;

    // Class-granularity completeness: every manifest class must be accounted
    // for in exactly one of the three coverage sets, or a narrowed run could
    // silently read as a full one.
    let manifest_classes: Vec<&String> = {
        let mut v: Vec<&String> = classes
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, _)| k)
            .collect();
        v.dedup();
        v
    };
    for class in &manifest_classes {
        let n = assessed.iter().filter(|c| c == class).count()
            + out_of_scope.iter().filter(|c| c == class).count()
            + routed_elsewhere.iter().filter(|c| c == class).count();
        // Spec: "The three sets are a disjoint partition of the manifest's classes:
        // a class appears in exactly one of assessedClasses, outOfScope,
        // routedElsewhere (a move, not a copy). A class in more than one of the
        // three, or a manifest class in none, is malformed - a class both assessed
        // and disclosed as a gap is contradictory."
        //
        // This read `n == 0` while its own comment said "exactly one", so an
        // overlapping class passed. Disclosing a gap is a move out of the assessed
        // set, and a class in two sets asserts two statuses at once rather than
        // partial assessment.
        if n == 0 {
            return Err(Fail(format!(
                "manifest class {class:?} appears in none of assessedClasses, outOfScope, or routedElsewhere"
            )));
        }
        if n > 1 {
            return Err(Fail(format!(
                "manifest class {class:?} appears in more than one of assessedClasses, outOfScope, or routedElsewhere; the three are a disjoint partition"
            )));
        }
    }
    // A partition is made of subsets of the thing it partitions, so a key in any of
    // the three that is not a manifest class breaks it. Only `assessedClasses` was
    // checked, and the result recompute does not cover the gap: it ignores
    // non-manifest classes entirely, so an unknown key in either reason map was
    // accepted in silence rather than caught downstream.
    for (label, classes) in [
        ("assessed", &assessed),
        ("outOfScope", &out_of_scope),
        ("routedElsewhere", &routed_elsewhere),
    ] {
        for class in classes.iter() {
            if !manifest_classes.contains(&class) {
                return Err(Fail(format!(
                    "{label} class {class:?} does not exist in the corpus manifest"
                )));
            }
        }
    }

    // ---- rows ---------------------------------------------------------------
    let rows_arr = req_arr(pred, "attackResults", "predicate")?;
    let mut rows = Vec::new();
    for (i, r) in rows_arr.iter().enumerate() {
        rows.push(parse_row(r, i)?);
    }
    // Spec: "No two `attackResults` rows may carry the same `attackId`: one row per
    // executed attack is a well-formedness invariant [...] Coverage integrity
    // set-compares row `attackId`s against the manifest, so a duplicate would
    // silently collapse under set semantics; uniqueness is enforced separately,
    // before that comparison, not left to it." Hence this runs ahead of the
    // coverage comparison rather than inside it.
    let mut first_seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (i, row) in rows.iter().enumerate() {
        if let Some(&j) = first_seen.get(row.attack_id) {
            return Err(Fail(format!(
                "attackResults rows {j} and {i} carry the same attackId {:?}; one row per executed attack",
                row.attack_id
            )));
        }
        first_seen.insert(row.attack_id, i);
    }

    for (i, row) in rows.iter().enumerate() {
        if !manifest_attacks.iter().any(|(_, a)| a == row.attack_id) {
            return Err(Fail::new("row-attack-unknown", format!(
                "attackResults[{i}].attackId {:?} does not appear in the corpus manifest",
                row.attack_id
            )));
        }
    }
    // Coverage integrity at attack granularity: the union of row attackIds
    // must exactly equal the manifest's attacks for the assessed classes.
    {
        let expected: Vec<&String> = manifest_attacks
            .iter()
            .filter(|(class, _)| assessed.contains(class))
            .map(|(_, a)| a)
            .collect();
        for a in &expected {
            if !rows.iter().any(|r| r.attack_id == a.as_str()) {
                return Err(Fail::new("coverage-incomplete", format!(
                    "manifest attack {a:?} in an assessed class has no attackResults row"
                )));
            }
        }
        for row in &rows {
            if !expected.iter().any(|a| a.as_str() == row.attack_id) {
                return Err(Fail(format!(
                    "attackResults row {:?} is outside the assessed classes' manifest attacks",
                    row.attack_id
                )));
            }
        }
    }
    // Clean rows carry the literal actualLayer "none".
    for (i, r) in rows_arr.iter().enumerate() {
        let row = &rows[i];
        if let Some(label) = row.label {
            let clean = labels.iter().any(|l| l == label) && !caught.iter().any(|c| c == label);
            if clean {
                let layer = r.get("actualLayer").and_then(|v| v.as_str()).unwrap_or("");
                if layer != "none" {
                    return Err(Fail::new(
            "clean-row-layer-not-none", format!(
                        "attackResults[{i}] is a clean row but actualLayer is {layer:?}, not the literal \"none\""
                    )));
                }
            }
        }
    }

    // Spec: "For this predicate `subject` MUST contain exactly one entry on a
    // statement of any basis; a statement carrying zero or more than one subject is
    // malformed, regardless of whether any row is `basis: substrate`." Only the six
    // binding-digest inputs stay substrate-scoped.
    if subjects.len() != 1 {
        return Err(Fail::new("subject-cardinality", format!(
            "statement carries {} subjects; exactly one is required on a statement of any basis",
            subjects.len()
        )));
    }

    let substrate_carrying = rows.iter().any(|r| r.basis == Some("substrate"));

    // ---- observation records and batch root ---------------------------------
    let records_val = pred.get("observationRecords");
    let mut records: Vec<RecordEval> = Vec::new();
    if let Some(rv) = records_val {
        let arr = rv
            .as_array()
            .ok_or_else(|| Fail("observationRecords is not a JSON array".into()))?;
        for (i, rec) in arr.iter().enumerate() {
            records.push(eval_record(rec, i)?);
        }
    }
    // Spec: "Wherever `observationRefs` is present - on any row, regardless of
    // `basis`, and including rows on which nothing normative reads it - every index
    // MUST be in range for `observationRecords`; an out-of-range index is a
    // structural integrity fault that makes the statement malformed, fail-closed and
    // independent of any gate." It was previously checked only while walking
    // substrate rows, so an artifact row's dangling index was never resolved and
    // never refused.
    for (i, row) in rows.iter().enumerate() {
        for &r in &row.refs {
            if r < 0 || r as usize >= records.len() {
                return Err(Fail::new("ref-out-of-range", format!(
                    "attackResults[{i}].observationRefs index {r} is out of range for observationRecords"
                )));
            }
        }
    }

    // Duplicate detection: a record's canonical identity is its leaf hash.
    for i in 0..records.len() {
        for j in (i + 1)..records.len() {
            if records[i].leaf == records[j].leaf {
                return Err(Fail(format!(
                    "observationRecords[{i}] and observationRecords[{j}] are duplicates of the same record"
                )));
            }
        }
    }
    let batch_root = pred.get("batchRoot");
    if records.is_empty() {
        if batch_root.is_some() {
            return Err(Fail(
                "batchRoot is carried but observationRecords is empty or absent".into(),
            ));
        }
    } else {
        let carried = batch_root
            .ok_or_else(|| Fail("observationRecords is non-empty but batchRoot is missing".into()))?
            .as_str()
            .ok_or_else(|| Fail("batchRoot is not a JSON string".into()))?;
        let leaves: Vec<[u8; 32]> = records.iter().map(|r| r.leaf).collect();
        let root = merkle::root_over_leaves(&leaves).unwrap();
        if hex::encode(root) != carried {
            return Err(Fail::new("batch-root-mismatch", 
                "batchRoot does not recompute over the carried observation records".into(),
            ));
        }
    }

    // ---- run binding (substrate-carrying statements only) --------------------
    let run_binding: Option<String> = if substrate_carrying {
        // Cardinality is already enforced unconditionally above.
        let subject_digest = {
            let s = &subjects[0];
            if s.as_object().is_none() {
                return Err(Fail("subject[0] is not a JSON object".into()));
            }
            let d = req_obj(s, "digest", "subject[0]")?;
            d.get("sha256")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Fail("subject[0].digest carries no sha256 entry".into()))?
        };
        let run_entropy = env.get("runEntropy").ok_or_else(|| {
            Fail("statement carries substrate rows but observationEnvironment.runEntropy is missing".into())
        })?;
        if run_entropy.as_object().is_none() {
            return Err(Fail("observationEnvironment.runEntropy is not a JSON object".into()));
        }
        let run_entropy_digest = digest_sha256(run_entropy, "observationEnvironment.runEntropy")?;
        let six = [
            ("subject", subject_digest),
            ("substrate", substrate_digest),
            ("corpus", corpus_digest),
            ("catchPolicy", catch_policy_digest),
            ("networkPosture", posture_digest),
            ("runEntropy", run_entropy_digest),
        ];
        for (name, v) in six {
            if !is_lower_hex64(v) {
                return Err(Fail(format!(
                    "{name} digest is not lowercase 64-hex, so the run binding cannot derive"
                )));
            }
        }
        // Binding version 2. Two inputs differ from version 1: `networkPosture`
        // is the canonical digest of the CARRIED OBJECT rather than the value of
        // that member's own `digest.sha256` (so the posture string and every
        // further member sit inside the binding), and `observationVocabulary`
        // becomes an input at all (so a narrowed caught set derives a different
        // binding and every record then fails the comparison).
        let posture_object_digest = jcs_sha256_hex(posture)?;
        let preimage = Value::Object(vec![
            ("aeeBindingVersion".into(), Value::String("2".into())),
            ("catchPolicy".into(), Value::String(catch_policy_digest.into())),
            ("corpus".into(), Value::String(corpus_digest.into())),
            ("networkPosture".into(), Value::String(posture_object_digest)),
            (
                "observationVocabulary".into(),
                Value::String(vocab_digest.into()),
            ),
            ("runEntropy".into(), Value::String(run_entropy_digest.into())),
            ("subject".into(), Value::String(subject_digest.into())),
            ("substrate".into(), Value::String(substrate_digest.into())),
        ]);
        Some(jcs_sha256_hex(&preimage)?)
    } else {
        None
    };

    // ---- coverage validity per substrate row ----------------------------------
    // covers[i] = evaluated referenced record i (evaluated lazily, cached).
    let mut cover_cache: Vec<Option<CoverEval>> = (0..records.len()).map(|_| None).collect();
    let mut row_covering: Vec<Vec<usize>> = vec![Vec::new(); rows.len()];

    // The value every carried sealed record must commit to: the duplicate-free,
    // UTF-16-sorted array of the lowercase 64-hex leaf hashes of every carried
    // interception and examination record, canonicalized and hashed. Records
    // registered as covering nothing are excluded by the member's own
    // definition, which names the two kinds it ranges over.
    let observed_set = {
        let mut leaves: Vec<String> = records
            .iter()
            .filter(|r| {
                matches!(
                    record_kind_of(r),
                    RecordKind::Interception | RecordKind::Examination
                )
            })
            .map(|r| hex::encode(r.leaf))
            .collect();
        leaves.sort_by_key(|h| json::utf16_units(h));
        leaves.dedup();
        let arr = Value::Array(leaves.into_iter().map(Value::String).collect());
        jcs_sha256_hex(&arr)?
    };
    let manifest_attack_ids: Vec<String> =
        manifest_attacks.iter().map(|(_, a)| a.clone()).collect();
    // Every arming record's declared posture, for the sealed covering rule's
    // second conjunct. Read from the carried records rather than from the rows,
    // because the rule ranges over the statement and not over a reference.
    // The covering rule says "the arming record's", singular and definite, so the
    // comparison ranges over arming records a row actually resolves and not over
    // every record carrying the kind token. Ranging over all of them re-opens the
    // over-rejection the binding-version fix above closes: a statement carrying a
    // second arming record that covers nothing would be refused on the posture of
    // a record this document removes from consideration. The corpus cannot tell
    // the two readings apart (only bad-902 carries divergent arming postures, and
    // its offending record is referenced), so the scope is untested here and the
    // report says so.
    let referenced_arming: std::collections::BTreeSet<usize> = rows
        .iter()
        .flat_map(|r| r.refs.iter().copied())
        .filter_map(|i| usize::try_from(i).ok())
        .filter(|i| records.get(*i).map(record_kind_of) == Some(RecordKind::Arming))
        .collect();
    let arming_postures: Vec<String> = referenced_arming
        .iter()
        .filter_map(|i| records.get(*i))
        .filter_map(|r| {
            r.payload
                .as_ref()
                .and_then(|p| p.get("aeePostureDigest"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    if substrate_carrying {
        let ctx = Ctx {
            run_binding: run_binding.as_deref().unwrap(),
            posture_digest,
            issued_at,
            manifest_attacks: &manifest_attack_ids,
            observed_set: &observed_set,
        };
        for (i, row) in rows.iter().enumerate() {
            if row.basis != Some("substrate") {
                continue;
            }
            // A substrate row fail-closed on its label or method cannot
            // satisfy the class-match requirement and is therefore invalid.
            let label = row.label.ok_or_else(|| {
                Fail(format!(
                    "attackResults[{i}] is a substrate row with no containmentObserved label"
                ))
            })?;
            if !labels.iter().any(|l| l == label) {
                return Err(Fail::new("substrate-row-label-unknown", format!(
                    "attackResults[{i}] is a substrate row whose label {label:?} is outside the carried vocabulary"
                )));
            }
            let method = row
                .method
                .and_then(parse_method)
                .ok_or_else(|| {
                    Fail::new("substrate-row-method-invalid", format!(
                        "attackResults[{i}] is a substrate row with a missing or out-of-vocabulary method"
                    ))
                })?;
            // `attribution` fail-closes on the same terms as `basis` and
            // `method`, so a substrate row fail-closed on it cannot satisfy the
            // class-match requirement either and the statement is invalid.
            if !matches!(row.attribution, Some("pinned") | Some("paired")) {
                return Err(Fail::new("substrate-row-attribution-invalid", format!(
                    "attackResults[{i}] is a substrate row with a missing or out-of-vocabulary attribution"
                )));
            }
            let is_caught = caught.iter().any(|c| c == label);

            if row.refs.is_empty() {
                return Err(Fail(format!(
                    "attackResults[{i}] is a substrate row with empty observationRefs"
                )));
            }
            let mut covering_kinds: Vec<(RecordKind, Option<Method>, bool)> = Vec::new();
            let mut non_covering_why: Vec<String> = Vec::new();
            for &r in &row.refs {
                if r < 0 || r as usize >= records.len() {
                    return Err(Fail::new("ref-out-of-range", format!(
                        "attackResults[{i}].observationRefs index {r} is out of range for observationRecords"
                    )));
                }
                let idx = r as usize;
                if cover_cache[idx].is_none() {
                    cover_cache[idx] = Some(referenced_record_validity(&records[idx], idx, &ctx)?);
                }
                let ce = cover_cache[idx].as_ref().unwrap();
                if let Some(why) = ce.non_covering.as_ref() {
                    // The spec requires a covers-nothing refusal be reported
                    // distinguishably. Constructing the reason and dropping it
                    // leaves every such row under one generic message.
                    non_covering_why.push(why.clone());
                } else {
                    covering_kinds.push((ce.kind, ce.method, ce.sealed_covers_clean));
                    row_covering[i].push(idx);
                }
            }
            // Class match.
            let has = |k: RecordKind| covering_kinds.iter().any(|(kind, _, _)| *kind == k);
            // Appended to an uncovered-row refusal so the reason names the
            // condition rather than only the consequence.
            let because = |base: String| -> String {
                if non_covering_why.is_empty() {
                    base
                } else {
                    format!("{base} ({})", non_covering_why.join("; "))
                }
            };
            match (is_caught, method) {
                (true, Method::Intercepted) => {
                    if !has(RecordKind::Interception) {
                        return Err(Fail::new("row-uncovered-interception", because(format!("attackResults[{i}] is a caught intercepted row with no covering interception record"))));
                    }
                }
                (_, Method::Reconstructed) => {
                    if !has(RecordKind::Examination) {
                        return Err(Fail::new("row-uncovered-examination", because(format!("attackResults[{i}] is a reconstructed row with no covering examination record"))));
                    }
                }
                (false, Method::Intercepted) => {
                    if !has(RecordKind::Arming) {
                        return Err(Fail::new("row-uncovered-arming", because(format!("attackResults[{i}] is a clean intercepted row with no covering arming record"))));
                    }
                    // Spec: a sealed record's `aeePostureDigest` must equal the pinned
                    // digest "and the `aeePostureDigest` of every `arming` record the
                    // row resolves". The quantifier is stated over THIS row, so the set
                    // is built from this row's own references. The union over every row
                    // that this previously used is over-broad: it can refuse a row on
                    // the posture of an arming record a different row resolves.
                    let row_arming: Vec<&str> = row
                        .refs
                        .iter()
                        .filter_map(|r| usize::try_from(*r).ok())
                        .filter_map(|idx| records.get(idx))
                        .filter(|rec| record_kind_of(rec) == RecordKind::Arming)
                        .filter_map(|rec| {
                            rec.payload
                                .as_ref()
                                .and_then(|p| p.get("aeePostureDigest"))
                                .and_then(|v| v.as_str())
                        })
                        .collect();
                    let sealed_ok = covering_kinds.iter().zip(row_covering[i].iter()).any(
                        |((k, _, clean), idx)| {
                            *k == RecordKind::Sealed
                                && *clean
                                && cover_cache[*idx]
                                    .as_ref()
                                    .and_then(|ce| ce.sealed_posture.as_deref())
                                    .is_some_and(|pd| row_arming.iter().all(|a| *a == pd))
                        },
                    );
                    if !sealed_ok {
                        return Err(Fail::new("row-uncovered-sealed", because(format!("attackResults[{i}] is a clean intercepted row with no covering sealed record"))));
                    }
                }
            }
            // Method cap: the row's method is no stronger than the weakest
            // signed aeeMethod across its covering records.
            let weakest_is_reconstructed = covering_kinds
                .iter()
                .any(|(_, m, _)| *m == Some(Method::Reconstructed));
            if method == Method::Intercepted && weakest_is_reconstructed {
                return Err(Fail::new("row-method-exceeds-coverage", format!(
                    "attackResults[{i}] claims method intercepted but a covering record is signed aeeMethod reconstructed"
                )));
            }
        }
    }

    // ---- 0.7 coverage validity requirements ----------------------------------
    // Five requirements that hold on the statement, or on every row rather than
    // only on a `basis: substrate` row. Each is a function of carried bytes and
    // a violation of any of them makes the attestation invalid.
    {
        let kinds: Vec<RecordKind> = records.iter().map(record_kind_of).collect();
        let is_caught_row = |r: &Row| r.label.is_some_and(|l| caught.iter().any(|c| c == l));
        let is_clean_row = |r: &Row| {
            r.label
                .is_some_and(|l| labels.iter().any(|x| x == l) && !caught.iter().any(|c| c == l))
        };

        // (1) A clean row resolves no index to an interception record: a row
        // stating that nothing was caught while pointing at a record in which
        // the substrate signed that it intercepted traffic states both halves
        // of a contradiction.
        for (i, row) in rows.iter().enumerate() {
            if !is_clean_row(row) {
                continue;
            }
            for &r in &row.refs {
                if kinds.get(r as usize) == Some(&RecordKind::Interception) {
                    return Err(Fail(format!(
                        "attackResults[{i}] is a clean row resolving observationRefs index {r} to an interception record"
                    )));
                }
            }
        }

        // (2) Every carried interception record is resolved by at least one
        // index on a caught row. One record MAY be resolved by more than one
        // row, so this costs none of the sharing the document permits.
        let mut resolved_by_caught: Vec<bool> = vec![false; records.len()];
        for row in rows.iter().filter(|r| is_caught_row(r)) {
            for &r in &row.refs {
                if let Some(slot) = resolved_by_caught.get_mut(r as usize) {
                    *slot = true;
                }
            }
        }
        for (idx, k) in kinds.iter().enumerate() {
            if *k == RecordKind::Interception && !resolved_by_caught[idx] {
                return Err(Fail(format!(
                    "observationRecords[{idx}] is an interception record no caught row resolves"
                )));
            }
        }

        // (3) and (4). A statement carrying a substrate row carries at least one
        // sealed record satisfying every constraint of its kind, whether or not
        // any row resolves an index to it; and every carried sealed record's
        // aeeObservedSet equals the recompute. A rule conditioned on the
        // presence of the record it constrains is a rule a producer switches
        // off by omission, so this ranges over the carried array.
        if substrate_carrying {
            let ctx = Ctx {
                run_binding: run_binding.as_deref().unwrap(),
                posture_digest,
                issued_at,
                manifest_attacks: &manifest_attack_ids,
                observed_set: &observed_set,
            };
            let mut valid_sealed = 0usize;
            for (idx, k) in kinds.iter().enumerate() {
                if *k != RecordKind::Sealed {
                    continue;
                }
                // Requirement 3 is EXISTENTIAL ("carries at least one sealed
                // record that satisfies every constraint of its kind"), so a
                // second sealed record failing a kind constraint does not by
                // itself invalidate the statement. Requirement 4 is UNIVERSAL
                // ("aeeObservedSet on every carried sealed record equals the
                // value recomputed"), so that one is checked here over every
                // carried seal regardless of whether another satisfies its kind.
                if let Some(pl) = records[idx].payload.as_ref() {
                    match pl.get("aeeObservedSet").and_then(|v| v.as_str()) {
                        Some(v) if v == observed_set => {}
                        Some(_) => {
                            return Err(Fail::new("observed-set-mismatch", format!(
                                "observationRecords[{idx}] is a sealed record whose aeeObservedSet does not equal the recompute over {OBSERVED_SET_EVALUATED}"
                            )))
                        }
                        None => {
                            return Err(Fail::new("observed-set-mismatch", format!(
                                "observationRecords[{idx}] is a sealed record carrying no aeeObservedSet"
                            )))
                        }
                    }
                }
                let ce = referenced_record_validity(&records[idx], idx, &ctx)?;
                // 0.7 rev 26: the existential bullet and its universal partner both say
                // "every constraint of its kind", and the author has ruled that for a
                // `sealed` record those include the clean-row conjuncts, not only the
                // structural members. So a record reporting its moat down is not a
                // witness here either: the two bullets differ in quantifier, never in
                // constraint set.
                //
                // The asymmetry this replaces was outcome-free on revision 25 and could
                // not have been caught by running it. Every dirty seal in that corpus was
                // paired with a clean one, so both readings were satisfied by the clean
                // witness and the sweep refused the dirty record either way: 0 of 248
                // vectors discriminated. `bad-1017` is the vector cut to discriminate it,
                // and it grades the condition rather than the verdict, which stays invalid
                // under both readings.
                // The arming conjunct on a check that reads no row. The spec states
                // the sentence over a row and says outright that "which `arming`
                // records supply the set on a check that reads no row is not stated
                // here and is not settled by it", so this is a declared reading and
                // not a derivation. We take every `arming` record any row resolves.
                // Measured against suite 5019931: the vectors that could
                // discriminate it all refuse at row-level coverage before reaching
                // here: bad-703 and bad-902 carry a divergent arming posture, and
                // bad-717 carries none at all, which its name says and which a
                // posture census reads as absence rather than divergence, and
                // on the vectors that do reach it every arming posture equals the
                // pinned digest, so this reading and its two rivals are observationally
                // identical over all 250. Changing it needs a vector, not an opinion.
                let arming_ok = ce
                    .sealed_posture
                    .as_deref()
                    .is_some_and(|pd| arming_postures.iter().all(|a| a == pd));
                if ce.non_covering.is_none() && ce.sealed_covers_clean && arming_ok {
                    valid_sealed += 1;
                }
            }
            if valid_sealed == 0 {
                return Err(Fail::new(
                    "sealed-record-absent",
                    "statement carries a basis: substrate row but no sealed record satisfying its kind".into(),
                ));
            }

            // The universal partner of the requirement above. Spec: "every
            // carried record that binds to this run and whose payload
            // `aeeKind` names a covering kind -- `interception`, `arming`,
            // `sealed`, `examination` -- satisfies every constraint of that
            // kind, whether or not any row resolves an `observationRefs` index
            // to it." The rationale the text gives is the reason this cannot
            // be left to the referenced path: "A constraint evaluated only
            // where a row points is a constraint whose subject the producer
            // chooses: a substrate signs a `sealed` record reporting its moat
            // down, the producer carries that record and points the row at a
            // second seal, and the run reads clean with the record that says
            // otherwise sitting in the statement and inside `batchRoot`."
            //
            // Two scope limits, both taken from the sentence rather than
            // chosen. "that binds to this run" is a FILTER and not a
            // constraint: a carried record whose `aeeRunBinding` names another
            // run is outside this rule, not in violation of it, so it is
            // skipped rather than refused. And the kinds registered as
            // covering nothing and the kinds a verifier does not recognize are
            // unaffected, "since neither carries a constraint that could be
            // violated", so the match below lists the four covering kinds
            // explicitly instead of negating `CoversNothing` and `Unknown`.
            //
            // Placement: the bullet sits in the list that holds "on the
            // statement, or on every row rather than only on a `basis:
            // substrate` row", so it is not conditioned on a substrate row.
            // It is evaluated here because `run_binding` is derived only on
            // the substrate path, and without a derived binding no carried
            // record binds to this run and the rule is vacuous. If a later
            // revision derives a run binding without a substrate row, this
            // sweep moves out with it.
            for (idx, k) in kinds.iter().enumerate() {
                if !matches!(
                    k,
                    RecordKind::Interception
                        | RecordKind::Arming
                        | RecordKind::Sealed
                        | RecordKind::Examination
                ) {
                    continue;
                }
                let binds = records[idx]
                    .payload
                    .as_ref()
                    .and_then(|p| p.get("aeeRunBinding"))
                    .and_then(|v| v.as_str())
                    == Some(ctx.run_binding);
                if !binds {
                    continue;
                }
                let ce = referenced_record_validity(&records[idx], idx, &ctx)?;
                if let Some(why) = ce.non_covering {
                    return Err(Fail::new("carried-record-invalid", format!(
                        "observationRecords[{idx}] binds to this run and its aeeKind names a covering kind, but it does not satisfy every constraint of that kind: {why}"
                    )));
                }
                // For a `sealed` record the clean-row conjuncts are part of
                // "every constraint of that kind" here, and the text settles
                // this rather than leaving it to taste: the attack the bullet
                // exists to close is "a substrate signs a `sealed` record
                // reporting its moat down, the producer carries that record
                // and points the row at a second seal, and the run reads clean
                // with the record that says otherwise sitting in the
                // statement." A moat reported down IS the conjunction below
                // failing: `aeeStillArmed` false, drops with no bound or over
                // it, or a posture digest disagreeing with the pinned value or
                // with an arming record. Reading the sweep to cover only the
                // structural constraints would leave exactly the statement the
                // rationale describes valid, which reads the rule out of the
                // document.
                //
                // Deliberately not applied to the existential requirement
                // above: that bullet asks whether a valid `sealed` record is
                // PRESENT and this one asks whether an invalid one is, which
                // is how the text distinguishes them, so a run whose seal
                // legitimately covers no clean row is refused here on the
                // conjunct it actually violates rather than on absence.
                // The arming conjunct has to be re-applied here too. Before the
                // scope fix it rode inside `sealed_covers_clean` and so reached
                // all three consumers at once; hoisting it out gave it back to
                // the row check and the existential and silently dropped it
                // here, while this refusal message went on telling the producer
                // it had been applied. Restored against the same union the
                // existential uses, which keeps this site's behaviour identical
                // to what it was before the fix.
                //
                // The message names only comparisons that were evaluated on this
                // statement and failed. Three things it used to get wrong, each a
                // way of describing a set that was not the set evaluated:
                //   1. it named all three record-local conjuncts although `&&`
                //      short-circuits, so it reported comparisons that never ran;
                //   2. it named the arming comparison even when the operand set
                //      was empty, where `.all()` is vacuously true and the term
                //      decides nothing (22 of 66 evaluations over the corpus);
                //   3. it called the operand set "every carried arming record"
                //      when the set is built from the records the ROWS RESOLVE.
                //      The phrase appears nowhere in the specification, which
                //      says "every `arming` record the row resolves".
                let sweep_arming_ok = match ce.sealed_posture.as_deref() {
                    // Unreachable for a sealed record whose `non_covering` is
                    // None, since `check_sealed` requires the member; kept
                    // explicit so the absent case cannot silently read as a
                    // failed comparison.
                    None => false,
                    Some(pd) => arming_postures.iter().all(|a| a == pd),
                };
                if ce.kind == RecordKind::Sealed && !(ce.sealed_covers_clean && sweep_arming_ok) {
                    return Err(Fail::new(
                        "carried-record-invalid",
                        sealed_sweep_reason(
                            idx,
                            &ce.sealed_clean_failures,
                            ce.sealed_posture.as_deref(),
                            &arming_postures,
                        ),
                    ));
                }
            }

            // Statement-level obligations carried by the two run-level records.
            //
            // aeeObservedAttacks READS IN ONE DIRECTION ONLY. Spec: "For every
            // identifier in the array the statement MUST carry an attackResults
            // row with that attackId whose containmentObserved is in the carried
            // caught set", and "a seal naming an attack obliges a caught row for
            // that attack; a seal omitting one licenses nothing, and in
            // particular does not oblige a clean row." So the array is a lower
            // bound: a caught row for an attack the seal omits is conformant,
            // and reading the relation as equality would reject it.
            for (idx, k) in kinds.iter().enumerate() {
                if *k != RecordKind::Sealed {
                    continue;
                }
                let payload = match records[idx].payload.as_ref() {
                    Some(p) => p,
                    None => continue,
                };
                if let Some(arr) = payload.get("aeeObservedAttacks").and_then(|v| v.as_array()) {
                    for e in arr {
                        let Some(attack) = e.as_str() else { continue };
                        let obliged = rows.iter().any(|r| {
                            r.attack_id == attack
                                && r.label.is_some_and(|l| caught.iter().any(|c| c == l))
                        });
                        if !obliged {
                            return Err(Fail::new("observed-attack-uncaught", format!(
                                "sealed record aeeObservedAttacks names {attack:?} but the statement carries no caught row for it"
                            )));
                        }
                    }
                }
            }

            // The union of the manifest's identifiers for the carried
            // assessedClasses MUST be a subset of aeeAssessedAttacks. A subset
            // rather than an equality, so a run that loses coverage part-way can
            // still disclose the loss.
            for (idx, k) in kinds.iter().enumerate() {
                if *k != RecordKind::Arming {
                    continue;
                }
                let payload = match records[idx].payload.as_ref() {
                    Some(p) => p,
                    None => continue,
                };
                let declared: Vec<&str> = payload
                    .get("aeeAssessedAttacks")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                for class in &assessed {
                    for (c, attack) in &manifest_attacks {
                        if c == class && !declared.iter().any(|d| d == attack) {
                            return Err(Fail::new("assessed-set-exceeds-declaration", format!(
                                "coverage.assessedClasses names {class:?} but the arming record's aeeAssessedAttacks omits its attackId {attack:?}"
                            )));
                        }
                    }
                }
            }
        }

        // (5) A row declaring `attribution: pinned` resolves at least one index
        // to an interception record, its attackId carries an entry in
        // expectedPayloads, and every interception record it resolves carries
        // at least one value from that entry. The existence requirement is not
        // redundant beside the third: a requirement universally quantified over
        // an empty set is vacuously true.
        for (i, row) in rows.iter().enumerate() {
            if row.attribution != Some("pinned") {
                continue;
            }
            let entry = expected_payloads
                .iter()
                .find(|(a, _)| a == row.attack_id)
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    Fail::new(
            "attribution-unpinnable", format!(
                        "attackResults[{i}] declares attribution pinned but its attackId carries no expectedPayloads entry"
                    ))
                })?;
            let mut resolved_interception = false;
            for &r in &row.refs {
                let idx = r as usize;
                if kinds.get(idx) != Some(&RecordKind::Interception) {
                    continue;
                }
                resolved_interception = true;
                let commitments = records[idx]
                    .payload
                    .as_ref()
                    .and_then(|pl| pl.get("aeePayloadCommitment"))
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if !commitments.iter().any(|c| entry.iter().any(|e| e == c)) {
                    return Err(Fail::new("attribution-commitment-absent", format!(
                        "attackResults[{i}] declares attribution pinned but observationRecords[{idx}] carries no commitment the corpus declared for this attack"
                    )));
                }
            }
            if !resolved_interception {
                return Err(Fail::new("attribution-unresolved", format!(
                    "attackResults[{i}] declares attribution pinned but resolves no interception record"
                )));
            }
        }
    }

    // ---- result recompute ------------------------------------------------------
    let mut any_fail = false;
    for row in &rows {
        let label_fail = match row.label {
            None => true,
            Some(l) => !labels.iter().any(|x| x == l) || caught.iter().any(|c| c == l),
        };
        let basis_fail = !matches!(row.basis, Some("substrate") | Some("artifact"));
        let method_fail = !matches!(row.method, Some("intercepted") | Some("reconstructed"));
        // Spec: "`attribution` enters the recompute through the fail-closed arm
        // of the first condition and nowhere else." A `paired` row is not a
        // weaker result, so the value never moves the token by itself.
        let attribution_fail = !matches!(row.attribution, Some("pinned") | Some("paired"));
        if label_fail || basis_fail || method_fail || attribution_fail {
            any_fail = true;
        }
    }
    // Third condition: any CLEAN row (label in the carried labels and not in the
    // carried caught set) carrying a basis other than `substrate` or a method
    // other than `intercepted` contributes `pass_indirect`. The result is the
    // minimum under fail < degraded < pass_indirect < pass, evaluated as three
    // independent conditions rather than as a cascade, because worst-wins rather
    // than evaluation order is the rule.
    let any_indirect_clean = rows.iter().any(|row| {
        let clean = row
            .label
            .is_some_and(|l| labels.iter().any(|x| x == l) && !caught.iter().any(|c| c == l));
        clean && (row.basis != Some("substrate") || row.method != Some("intercepted"))
    });
    let recomputed = if any_fail {
        "fail"
    } else if !out_of_scope.is_empty() || !routed_elsewhere.is_empty() {
        "degraded"
    } else if any_indirect_clean {
        "pass_indirect"
    } else {
        "pass"
    };
    if carried_result != recomputed {
        return Err(Fail::new("result-recompute-mismatch", format!(
            "carried result {carried_result:?} does not match the recomputed result {recomputed:?}"
        )));
    }

    // ---- evidence tier (trust-relative; never alters the verdict) ---------------
    let record_verifies = |idx: usize, key: &VerifyingKey| -> bool {
        let rec = &records[idx];
        rec.sig_bytes
            .iter()
            .any(|sig| keys::verify(key, &rec.pae, sig))
    };
    let tier_for = |row_idx: usize, row: &Row, key: Option<&VerifyingKey>| -> String {
        if row.basis != Some("substrate") {
            return "declared".to_string();
        }
        let Some(k) = key else {
            return "unattested".to_string();
        };
        let covering = &row_covering[row_idx];
        let all_verify =
            !covering.is_empty() && covering.iter().all(|&idx| record_verifies(idx, k));
        if all_verify {
            "attested".to_string()
        } else {
            "unattested".to_string()
        }
    };
    let tiers_with_key: Vec<String> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| tier_for(i, r, pinned_key))
        .collect();
    let tiers_without_key: Vec<String> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| tier_for(i, r, None))
        .collect();

    Ok(Verdict::Valid {
        result: recomputed.to_string(),
        tiers_with_key,
        tiers_without_key,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// These pin the refusal-message discipline the corpus cannot see. Every case
// below leaves all 250 verdicts unchanged, which is exactly why none of the
// defects they cover was caught by conformance: they live in the free-form
// reason, which the suite declares informative. A rule this file states about
// its own messages has to be held by a test in this file.

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(src: &str) -> Value {
        match json::parse(src.as_bytes()) {
            Ok(v) => v,
            Err(e) => panic!("test payload does not parse: {}", e.0),
        }
    }

    /// `Fail` deliberately carries no `Debug`, so tests unwrap by hand rather
    /// than widening a production type to suit them.
    fn ok_sealed(v: &Value, c: &Ctx) -> (Vec<&'static str>, String) {
        match check_sealed(v, c) {
            Ok(t) => t,
            Err(e) => panic!("unexpected refusal: {}", e.msg),
        }
    }

    fn ctx<'a>(posture: &'a str, observed_set: &'a str, attacks: &'a [String]) -> Ctx<'a> {
        Ctx {
            run_binding: "rb",
            posture_digest: posture,
            issued_at: time::Instant { epoch_seconds: 0, nanos: 0 },
            manifest_attacks: attacks,
            observed_set,
        }
    }

    const PINNED: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const OBSERVED: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";

    fn sealed(still_armed: bool, drops: i64, bound: Option<i64>, posture: &str) -> Value {
        let bound = match bound {
            Some(b) => format!(r#","aeeDropBound":{b}"#),
            None => String::new(),
        };
        payload(&format!(
            r#"{{"aeeStillArmed":{still_armed},"aeeDropCount":{drops}{bound},"aeePostureDigest":"{posture}","aeeObservedSet":"{OBSERVED}","aeeObservedAttacks":[]}}"#
        ))
    }

    // -- check_sealed evaluates every conjunct -----------------------------

    #[test]
    fn clean_sealed_record_reports_no_failure() {
        let a: Vec<String> = vec![];
        let (failures, posture) = ok_sealed(&sealed(true, 0, None, PINNED), &ctx(PINNED, OBSERVED, &a));
        assert!(failures.is_empty(), "unexpected failures: {failures:?}");
        assert_eq!(posture, PINNED);
    }

    /// The regression this file was changed for. Under `&&` only the first
    /// failing conjunct decided the result and the caller named all three, so
    /// four vectors failing on four different conjuncts emitted one identical
    /// string. Every conjunct is evaluated, so every failure is reportable.
    #[test]
    fn every_failing_conjunct_is_reported_not_just_the_first() {
        let a: Vec<String> = vec![];
        let other = "3333333333333333333333333333333333333333333333333333333333333333";
        // still_armed false AND posture mismatched: a short-circuiting
        // implementation can only ever see the first of these.
        let (failures, _) = ok_sealed(&sealed(false, 0, None, other), &ctx(PINNED, OBSERVED, &a));
        assert_eq!(failures.len(), 2, "got {failures:?}");
        assert!(failures.iter().any(|f| f.contains("aeeStillArmed")));
        assert!(failures.iter().any(|f| f.contains("pinned networkPosture")));
    }

    #[test]
    fn each_conjunct_is_named_on_its_own() {
        let a: Vec<String> = vec![];
        let c = ctx(PINNED, OBSERVED, &a);
        let only = |v: &Value| -> Vec<&'static str> { ok_sealed(v, &c).0 };

        assert_eq!(only(&sealed(false, 0, None, PINNED)).len(), 1);
        // drops with no bound declared, and drops over a declared bound
        assert_eq!(only(&sealed(true, 1, None, PINNED)).len(), 1);
        assert_eq!(only(&sealed(true, 5, Some(2), PINNED)).len(), 1);
        // drops within a declared bound is not a failure
        assert!(only(&sealed(true, 2, Some(5), PINNED)).is_empty());
    }

    // -- the refusal names only what was evaluated -------------------------

    fn reason(failures: &[&'static str], posture: Option<&str>, arming: &[&str]) -> String {
        let arming: Vec<String> = arming.iter().map(|s| (*s).to_string()).collect();
        sealed_sweep_reason(1, failures, posture, &arming)
    }

    /// Defect 3. The operand set is the arming records the ROWS RESOLVE. The
    /// old message called it "every carried arming record", a phrase that
    /// appears nowhere in the specification and describes a strict superset.
    #[test]
    fn refusal_never_describes_the_operand_set_as_carried() {
        let other = "3333333333333333333333333333333333333333333333333333333333333333";
        let cases = [
            reason(&["aeeStillArmed is false"], Some(PINNED), &[]),
            reason(&[], Some(PINNED), &[other]),
            reason(&["aeeStillArmed is false"], Some(PINNED), &[other, other]),
            reason(&[], None, &[]),
        ];
        for r in cases {
            assert!(
                !r.contains("carried arming"),
                "refusal describes the operand set as carried: {r}"
            );
        }
    }

    /// Defect 2. `all()` over an empty set is vacuously true, so the arming
    /// comparison decides nothing and must not be named. 22 of 66 evaluations
    /// over the pinned corpus reach the site with this set empty.
    ///
    /// HONEST LIMIT, recorded rather than left to be discovered: this test
    /// pins the message contract, NOT the `!arming_postures.is_empty()` guard
    /// that states it. Deleting that guard leaves every test here green,
    /// measured. The guard is redundant against the current formulation
    /// precisely because `all()` is already vacuously true on empty, so no
    /// input can distinguish its presence — a structural zero, not an
    /// empirical one. It is kept because it states the rule where a reader
    /// meets it, and because a future formulation that is not vacuously true
    /// on empty (an explicit per-record loop, or an `any()`-based inversion)
    /// would need it and would not announce that it did.
    #[test]
    fn empty_operand_set_is_not_named_as_a_comparison() {
        let r = reason(&["aeeStillArmed is false"], Some(PINNED), &[]);
        assert!(
            !r.contains("arming record"),
            "named a comparison over an empty operand set: {r}"
        );
        assert!(r.contains("aeeStillArmed is false"));
    }

    /// The other side of the same rule: a non-empty set that actually
    /// disagrees IS named, and says how many operands it compared.
    #[test]
    fn non_empty_disagreeing_operand_set_is_named_with_its_size() {
        let other = "3333333333333333333333333333333333333333333333333333333333333333";
        let one = reason(&[], Some(PINNED), &[other]);
        assert!(one.contains("1 arming record the rows resolve"), "{one}");
        let two = reason(&[], Some(PINNED), &[other, other]);
        assert!(two.contains("2 arming records the rows resolve"), "{two}");
    }

    /// A non-empty set that agrees is a comparison that ran and passed, so it
    /// is not a failure and is not named either.
    #[test]
    fn agreeing_operand_set_is_not_named() {
        let r = reason(&["aeeStillArmed is false"], Some(PINNED), &[PINNED]);
        assert!(!r.contains("arming record"), "{r}");
    }

    /// Defect 1, at the message layer: distinct failing conjuncts must produce
    /// distinct strings. The old message was byte-identical across all four.
    #[test]
    fn distinct_failures_produce_distinct_refusals() {
        let rs = [
            reason(&["aeeStillArmed is false"], Some(PINNED), &[]),
            reason(&["aeeDropCount is non-zero and exceeds its aeeDropBound, or declares no bound"], Some(PINNED), &[]),
            reason(&["aeePostureDigest differs from the pinned networkPosture digest"], Some(PINNED), &[]),
        ];
        let uniq: std::collections::BTreeSet<&String> = rs.iter().collect();
        assert_eq!(uniq.len(), rs.len(), "refusals collapse distinct faults: {rs:?}");
    }

    /// An absent posture is an absence, not a comparison that was made.
    #[test]
    fn absent_posture_is_reported_as_absence() {
        let r = reason(&[], None, &[]);
        assert!(r.contains("aeePostureDigest is absent"), "{r}");
        assert!(!r.contains("differs from"), "{r}");
    }

    // -- the observed-set refusal names the set the recompute evaluated ----
    //
    // The aeeObservedSet recompute filters the carried array to interception
    // and examination records; the member's own definition names those two
    // kinds. A refusal saying the value was recomputed over "the carried
    // records" names every carried kind, including arming and sealed records
    // the recompute never reads, and the refusal-set clause forbids naming a
    // set wider than the one evaluated: it tells the producer to repair
    // records the check never read.

    #[test]
    fn sealed_observed_set_refusal_names_the_two_evaluated_kinds() {
        let a: Vec<String> = vec![];
        let c = ctx(PINNED, OBSERVED, &a);
        let divergent = "3333333333333333333333333333333333333333333333333333333333333333";
        let pl = payload(&format!(
            r#"{{"aeeStillArmed":true,"aeeDropCount":0,"aeePostureDigest":"{PINNED}","aeeObservedSet":"{divergent}","aeeObservedAttacks":[]}}"#
        ));
        let msg = match check_sealed(&pl, &c) {
            Err(e) => e.msg,
            Ok(_) => panic!("divergent aeeObservedSet unexpectedly covers"),
        };
        assert!(
            msg.contains("recomputed over the carried interception and examination records"),
            "refusal does not name the evaluated set: {msg}"
        );
        assert!(
            !msg.contains("over the carried records"),
            "refusal names a wider set than the recompute evaluated: {msg}"
        );
    }

    fn jcs(v: &Value) -> String {
        match jcs_sha256_hex(v) {
            Ok(h) => h,
            Err(e) => panic!("cannot digest: {}", e.msg),
        }
    }

    fn canonical(v: &Value) -> Vec<u8> {
        match json::to_canonical_bytes(v) {
            Ok(b) => b,
            Err(e) => panic!("cannot canonicalize: {e}"),
        }
    }

    /// A full statement that is valid end to end, except that when `observed`
    /// is Some the carried sealed record commits to that value instead of the
    /// recompute. The two twins differ in nothing else, so the refusal the
    /// divergent twin draws is decided by the observed-set comparison alone.
    fn observed_set_statement(observed: Option<&str>) -> Vec<u8> {
        let hex64 = |c: char| -> String { std::iter::repeat_n(c, 64).collect() };
        let subject_digest = hex64('a');
        let substrate_digest = hex64('b');
        let catch_policy_digest = hex64('c');
        let posture_member_digest = hex64('d');
        let run_entropy_digest = hex64('e');

        let manifest = payload(r#"{"classes":{"cls":["atk-1"]}}"#);
        let corpus_digest = jcs(&manifest);
        let vocab_preimage = payload(r#"{"caught":["caught"],"labels":["caught","clean"]}"#);
        let vocab_digest = jcs(&vocab_preimage);
        let posture = payload(&format!(
            r#"{{"digest":{{"sha256":"{posture_member_digest}"}},"posture":"no_network"}}"#
        ));
        let posture_object_digest = jcs(&posture);
        let binding_preimage = payload(&format!(
            r#"{{"aeeBindingVersion":"2","catchPolicy":"{catch_policy_digest}","corpus":"{corpus_digest}","networkPosture":"{posture_object_digest}","observationVocabulary":"{vocab_digest}","runEntropy":"{run_entropy_digest}","subject":"{subject_digest}","substrate":"{substrate_digest}"}}"#
        ));
        let run_binding = jcs(&binding_preimage);

        let ptype = "application/vnd.test.record+json";
        let envelope = |pl: &Value| -> (String, [u8; 32]) {
            let bytes = canonical(pl);
            let leaf = merkle::leaf_hash(&merkle::pae(ptype, &bytes));
            let env = format!(
                r#"{{"payload":"{}","payloadType":"{ptype}","signatures":[{{"sig":"{}"}}]}}"#,
                B64.encode(&bytes),
                B64.encode(b"sig")
            );
            (env, leaf)
        };

        let commitment = hex64('f');
        let interception = payload(&format!(
            r#"{{"aeeKind":"interception","aeeMethod":"intercepted","aeePayloadCommitment":["{commitment}"],"aeeRunBinding":"{run_binding}"}}"#
        ));
        let (i_env, i_leaf) = envelope(&interception);
        let examination = payload(&format!(
            r#"{{"aeeKind":"examination","aeeMethod":"reconstructed","aeeRunBinding":"{run_binding}"}}"#
        ));
        let (e_env, e_leaf) = envelope(&examination);
        // The recompute's own definition: the leaves of the interception and
        // examination records, never the sealed record's. Derived here from
        // both kinds independently of the production filter, so a filter that
        // drifts to one kind flips the positive control: the reviewer's
        // narrowing mutation left every test green while this array held one
        // leaf, because a one-kind fixture cannot tell the two filters apart.
        let mut observed_leaves = vec![hex::encode(i_leaf), hex::encode(e_leaf)];
        observed_leaves.sort_by_key(|h| json::utf16_units(h));
        let recompute = jcs(&Value::Array(
            observed_leaves.into_iter().map(Value::String).collect(),
        ));
        let sealed_observed = observed.unwrap_or(&recompute).to_string();
        let sealed = payload(&format!(
            r#"{{"aeeDropCount":0,"aeeKind":"sealed","aeeMethod":"intercepted","aeeObservedAttacks":[],"aeeObservedSet":"{sealed_observed}","aeePostureDigest":"{posture_member_digest}","aeeRunBinding":"{run_binding}","aeeStillArmed":true}}"#
        ));
        let (s_env, s_leaf) = envelope(&sealed);
        let batch_root = hex::encode(
            merkle::root_over_leaves(&[i_leaf, s_leaf, e_leaf]).expect("three leaves have a root"),
        );

        format!(
            r#"{{"_type":"{STATEMENT_TYPE}","predicateType":"{PREDICATE_TYPE}","subject":[{{"digest":{{"sha256":"{subject_digest}"}},"name":"artifact"}}],"predicate":{{"issuedAt":"2026-01-01T00:00:00Z","result":"fail","observationEnvironment":{{"substrate":{{"name":"sub","digest":{{"sha256":"{substrate_digest}"}}}},"corpus":{{"name":"corpus","uri":"https://example.invalid/corpus","digest":{{"sha256":"{corpus_digest}"}},"manifest":{{"classes":{{"cls":["atk-1"]}}}}}},"catchPolicy":{{"digest":{{"sha256":"{catch_policy_digest}"}}}},"networkPosture":{{"digest":{{"sha256":"{posture_member_digest}"}},"posture":"no_network"}},"observationVocabulary":{{"labels":["caught","clean"],"caught":["caught"],"digest":{{"sha256":"{vocab_digest}"}}}},"runEntropy":{{"digest":{{"sha256":"{run_entropy_digest}"}}}}}},"coverage":{{"assessedClasses":["cls"],"outOfScope":{{}},"routedElsewhere":{{}}}},"attackResults":[{{"attackId":"atk-1","containmentObserved":"caught","basis":"substrate","method":"intercepted","attribution":"paired","actualLayer":"transport","observationRefs":[0]}}],"observationRecords":[{i_env},{s_env},{e_env}],"batchRoot":"{batch_root}"}}}}"#
        )
        .into_bytes()
    }

    /// Positive control: the fixture is valid when the seal commits to the
    /// recompute, so the divergent twin's refusal is decided by the
    /// observed-set comparison and not by an unrelated defect.
    #[test]
    fn observed_set_statement_is_otherwise_valid() {
        match check_inner(&observed_set_statement(None), None) {
            Ok(Verdict::Valid { .. }) => {}
            Ok(v) => panic!("expected Valid, got {v:?}"),
            Err(f) => panic!("fixture is not otherwise valid: {}", f.msg),
        }
    }

    /// The carried-sweep refusal, drawn through the real path: a statement
    /// whose sealed record commits to a divergent observed set. The reason
    /// must name the set the recompute evaluated, the carried interception
    /// and examination records, and must not say "the carried records",
    /// which includes kinds the recompute never reads.
    #[test]
    fn observed_set_sweep_refusal_names_the_two_evaluated_kinds() {
        let divergent = "3333333333333333333333333333333333333333333333333333333333333333";
        let f = match check_inner(&observed_set_statement(Some(divergent)), None) {
            Err(f) => f,
            Ok(v) => panic!("divergent aeeObservedSet unexpectedly accepted: {v:?}"),
        };
        assert_eq!(f.code, "observed-set-mismatch", "{}", f.msg);
        assert!(f.msg.contains("observationRecords[1]"), "{}", f.msg);
        assert!(
            f.msg
                .contains("recompute over the carried interception and examination records"),
            "refusal does not name the evaluated set: {}",
            f.msg
        );
        assert!(
            !f.msg.contains("over the carried records"),
            "refusal names a wider set than the recompute evaluated: {}",
            f.msg
        );
    }
}
