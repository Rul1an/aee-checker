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
    "https://in-toto.io/attestation/adversarial-execution-evidence/v0.6";

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
    },
}

/// One free-form failure reason; stage one stops at the first violation.
struct Fail(String);

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
        .ok_or_else(|| Fail(format!("{what} is missing required member \"{key}\"")))
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
    Unknown,
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
            .map_err(|_| Fail(format!("{what}.signatures[{i}].sig is not valid base64")))?;
        sig_bytes.push(bytes);
    }
    // Strict, canonical base64: decode with the standard alphabet and
    // require the re-encoding to reproduce the carried text, so a payload
    // smuggled through a lenient decoder is rejected as undecodable.
    let payload_bytes = B64.decode(payload_b64).map_err(|_| {
        Fail(format!("{what}.payload is not valid base64"))
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
    /// For sealed records: additionally covers a clean row.
    sealed_covers_clean: bool,
}

struct Ctx<'a> {
    run_binding: &'a str,
    posture_digest: &'a str,
    issued_at: time::Instant,
}

/// The hard part of the coverage-validity bullet: every referenced payload
/// must be a canonical `+json` object carrying the reserved members with
/// `aeeRunBinding` equal to the derived binding. A violation here is an
/// attestation-validity failure.
fn referenced_record_validity(rec: &RecordEval, idx: usize, ctx: &Ctx) -> R<CoverEval> {
    let what = format!("observationRecords[{idx}]");
    if !rec.json_media_type {
        return Err(Fail(format!(
            "{what} covers a substrate row but its payloadType does not end in +json"
        )));
    }
    let payload = rec.payload.as_ref().ok_or_else(|| {
        Fail(format!(
            "{what} covers a substrate row but its payload is not a canonical I-JSON object: {}",
            rec.payload_err.as_deref().unwrap_or("unknown")
        ))
    })?;
    let binding = req_str(payload, "aeeRunBinding", &format!("{what} payload"))?;
    let kind_tok = req_str(payload, "aeeKind", &format!("{what} payload"))?;
    let method_tok = req_str(payload, "aeeMethod", &format!("{what} payload"))?;
    if binding != ctx.run_binding {
        return Err(Fail(format!(
            "{what} payload aeeRunBinding does not equal the run binding derived from this statement"
        )));
    }
    // A binding version this verifier does not implement is rejected
    // fail-closed rather than attempting another construction.
    if let Some(bv) = payload.get("aeeBindingVersion") {
        if bv.as_str() != Some("1") {
            return Err(Fail(format!(
                "{what} payload declares a run-binding version this verifier does not implement"
            )));
        }
    }
    let kind = match kind_tok {
        "interception" => RecordKind::Interception,
        "arming" => RecordKind::Arming,
        "sealed" => RecordKind::Sealed,
        "examination" => RecordKind::Examination,
        _ => RecordKind::Unknown,
    };
    let method = parse_method(method_tok);
    let mut non_covering: Option<String> = None;
    let mut sealed_covers_clean = false;

    if kind == RecordKind::Unknown {
        non_covering = Some(format!("record kind {kind_tok:?} is not recognized"));
    } else if method.is_none() {
        non_covering = Some(format!(
            "record aeeMethod {method_tok:?} is outside the closed vocabulary"
        ));
    } else {
        match kind {
            RecordKind::Interception => {}
            RecordKind::Arming => {
                if method != Some(Method::Intercepted) {
                    non_covering =
                        Some("arming record is not signed aeeMethod intercepted".into());
                } else if let Err(e) = check_arming(payload, ctx) {
                    non_covering = Some(e.0);
                }
            }
            RecordKind::Sealed => {
                if method != Some(Method::Intercepted) {
                    non_covering =
                        Some("sealed record is not signed aeeMethod intercepted".into());
                } else {
                    match check_sealed(payload, ctx) {
                        Ok(covers_clean) => sealed_covers_clean = covers_clean,
                        Err(e) => non_covering = Some(e.0),
                    }
                }
            }
            RecordKind::Examination => {
                if method != Some(Method::Reconstructed) {
                    non_covering =
                        Some("examination record is not signed aeeMethod reconstructed".into());
                }
            }
            RecordKind::Unknown => unreachable!(),
        }
    }
    Ok(CoverEval {
        kind,
        method,
        non_covering,
        sealed_covers_clean,
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
    if !parsed.utc_offset {
        return Err(Fail("arming record armedAt is not stated in UTC".into()));
    }
    if parsed.instant > ctx.issued_at {
        return Err(Fail("arming record armedAt is later than issuedAt".into()));
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
                            Fail(format!("arming record aeeChainScope[{i}] is not a JSON string"))
                        })?;
                        if !matches!(tok, "subject" | "corpus" | "networkPosture") {
                            return Err(Fail(format!(
                                "arming record aeeChainScope[{i}] {tok:?} is outside the closed dimension vocabulary"
                            )));
                        }
                        let units = json::utf16_units(tok);
                        if let Some(p) = &prev_token {
                            if *p >= units {
                                return Err(Fail(format!(
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
fn check_sealed(payload: &Value, ctx: &Ctx) -> R<bool> {
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
    // Clean-row covering conditions (each a check on signed carried bytes).
    let covers_clean = still_armed
        && (drop_count == 0 || drop_bound.is_some_and(|b| drop_count <= b))
        && posture == ctx.posture_digest;
    Ok(covers_clean)
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
    // actualLayer is required on every row: a missing member is a
    // malformed statement, and so is a wrong-typed one.
    match row.get("actualLayer") {
        None => {
            return Err(Fail(format!(
                "{what} is missing the required actualLayer member"
            )))
        }
        Some(v) => {
            if v.as_str().is_none() {
                return Err(Fail(format!("{what}.actualLayer is not a JSON string")));
            }
        }
    }
    let mut refs = Vec::new();
    if let Some(r) = row.get("observationRefs") {
        let arr = r
            .as_array()
            .ok_or_else(|| Fail(format!("{what}.observationRefs is not a JSON array")))?;
        for (i, v) in arr.iter().enumerate() {
            let n = v.as_safe_integer().ok_or_else(|| {
                Fail(format!(
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
        refs,
    })
}

// ---------------------------------------------------------------------------
// The checker
// ---------------------------------------------------------------------------

pub fn check(statement_bytes: &[u8], pinned_key: Option<&VerifyingKey>) -> Verdict {
    match check_inner(statement_bytes, pinned_key) {
        Ok(v) => v,
        Err(Fail(reason)) => Verdict::Invalid { reason },
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
    let issued_at = time::parse_rfc3339(issued_at_str)
        .ok_or_else(|| Fail("issuedAt is not an RFC 3339 timestamp".into()))?
        .instant;

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
    req_str(posture, "posture", "observationEnvironment.networkPosture")?;
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
                Fail(format!("observationVocabulary.{name}[{i}] is not a JSON string"))
            })?;
            if !json::is_bmp_only(s) {
                return Err(Fail(format!(
                    "observationVocabulary.{name} entry {s:?} carries a code point above U+FFFF"
                )));
            }
            let units = json::utf16_units(s);
            if let Some(p) = &prev {
                if *p >= units {
                    return Err(Fail(format!(
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
            return Err(Fail(format!(
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
            return Err(Fail(format!(
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
                return Err(Fail(format!(
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
                    return Err(Fail(format!(
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
        return Err(Fail(format!(
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
                return Err(Fail(format!(
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
            return Err(Fail(
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
        let preimage = Value::Object(vec![
            ("aeeBindingVersion".into(), Value::String("1".into())),
            ("catchPolicy".into(), Value::String(catch_policy_digest.into())),
            ("corpus".into(), Value::String(corpus_digest.into())),
            ("networkPosture".into(), Value::String(posture_digest.into())),
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

    if substrate_carrying {
        let ctx = Ctx {
            run_binding: run_binding.as_deref().unwrap(),
            posture_digest,
            issued_at,
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
                return Err(Fail(format!(
                    "attackResults[{i}] is a substrate row whose label {label:?} is outside the carried vocabulary"
                )));
            }
            let method = row
                .method
                .and_then(parse_method)
                .ok_or_else(|| {
                    Fail(format!(
                        "attackResults[{i}] is a substrate row with a missing or out-of-vocabulary method"
                    ))
                })?;
            let is_caught = caught.iter().any(|c| c == label);

            if row.refs.is_empty() {
                return Err(Fail(format!(
                    "attackResults[{i}] is a substrate row with empty observationRefs"
                )));
            }
            let mut covering_kinds: Vec<(RecordKind, Option<Method>, bool)> = Vec::new();
            for &r in &row.refs {
                if r < 0 || r as usize >= records.len() {
                    return Err(Fail(format!(
                        "attackResults[{i}].observationRefs index {r} is out of range for observationRecords"
                    )));
                }
                let idx = r as usize;
                if cover_cache[idx].is_none() {
                    cover_cache[idx] = Some(referenced_record_validity(&records[idx], idx, &ctx)?);
                }
                let ce = cover_cache[idx].as_ref().unwrap();
                if ce.non_covering.is_none() {
                    covering_kinds.push((ce.kind, ce.method, ce.sealed_covers_clean));
                    row_covering[i].push(idx);
                }
            }
            // Class match.
            let has = |k: RecordKind| covering_kinds.iter().any(|(kind, _, _)| *kind == k);
            match (is_caught, method) {
                (true, Method::Intercepted) => {
                    if !has(RecordKind::Interception) {
                        return Err(Fail(format!(
                            "attackResults[{i}] is a caught intercepted row with no covering interception record"
                        )));
                    }
                }
                (_, Method::Reconstructed) => {
                    if !has(RecordKind::Examination) {
                        return Err(Fail(format!(
                            "attackResults[{i}] is a reconstructed row with no covering examination record"
                        )));
                    }
                }
                (false, Method::Intercepted) => {
                    if !has(RecordKind::Arming) {
                        return Err(Fail(format!(
                            "attackResults[{i}] is a clean intercepted row with no covering arming record"
                        )));
                    }
                    let sealed_ok = covering_kinds
                        .iter()
                        .any(|(k, _, clean)| *k == RecordKind::Sealed && *clean);
                    if !sealed_ok {
                        return Err(Fail(format!(
                            "attackResults[{i}] is a clean intercepted row with no covering sealed record"
                        )));
                    }
                }
            }
            // Method cap: the row's method is no stronger than the weakest
            // signed aeeMethod across its covering records.
            let weakest_is_reconstructed = covering_kinds
                .iter()
                .any(|(_, m, _)| *m == Some(Method::Reconstructed));
            if method == Method::Intercepted && weakest_is_reconstructed {
                return Err(Fail(format!(
                    "attackResults[{i}] claims method intercepted but a covering record is signed aeeMethod reconstructed"
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
        if label_fail || basis_fail || method_fail {
            any_fail = true;
        }
    }
    let recomputed = if any_fail {
        "fail"
    } else if !out_of_scope.is_empty() || !routed_elsewhere.is_empty() {
        "degraded"
    } else {
        "pass"
    };
    if carried_result != recomputed {
        return Err(Fail(format!(
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
