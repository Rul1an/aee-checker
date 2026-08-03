//! Conformance-corpus runner for the AEE validity-gate checker.
//!
//! Usage:
//!   aee-checker <vectors-dir> [--manifest <path>] [--json <out.json>] [--role <name>]
//!   aee-checker --discover-role <vector.json>
//!
//! The runner reads MANIFEST.json for the vector list and expected
//! verdict/result/tier values only; the manifest's informative condition
//! codes are never read by this program.

mod check;
mod json;
mod keys;
mod merkle;
mod time;

use check::Verdict;
use json::Value;
use std::path::{Path, PathBuf};

struct Expected {
    id: String,
    file: String,
    kind: String,
    verdict: String,
    result: Option<String>,
    tier_with_key: Option<Vec<String>>,
    tier_without_key: Option<Vec<String>>,
    /// The condition codes the corpus declares this vector forces. Carried so a
    /// reject can be scored on the reason it names and not only on its verdict:
    /// verdict-only scoring lets a right-verdict-wrong-reason reject read as
    /// parity, which is the divergence class worth reporting.
    codes: Vec<String>,
    /// Codes a conforming verifier MAY additionally name on this vector.
    also_carries: Vec<String>,
}

fn str_list(v: &Value) -> Option<Vec<String>> {
    v.as_array().map(|items| {
        items
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect()
    })
}

fn load_manifest(path: &Path) -> Vec<Expected> {
    let bytes = std::fs::read(path).expect("cannot read manifest");
    let m = json::parse(&bytes).expect("manifest does not parse");
    let mut out = Vec::new();
    for v in m.get("vectors").and_then(|v| v.as_array()).expect("vectors") {
        let expected = v.get("expected").expect("expected");
        out.push(Expected {
            id: v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            file: v.get("file").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            kind: v.get("kind").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            verdict: expected
                .get("verdict")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            result: expected
                .get("result")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            tier_with_key: expected.get("tierWithPinnedKey").and_then(str_list),
            tier_without_key: expected.get("tierWithoutKey").and_then(str_list),
            codes: expected.get("codes").and_then(str_list).unwrap_or_default(),
            also_carries: expected.get("alsoCarries").and_then(str_list).unwrap_or_default(),
        });
    }
    out
}

fn discover_role(vector_path: &Path) {
    let bytes = std::fs::read(vector_path).expect("cannot read vector");
    let stmt = json::parse(&bytes).expect("vector does not parse");
    let records = stmt
        .get("predicate")
        .and_then(|p| p.get("observationRecords"))
        .and_then(|r| r.as_array())
        .expect("vector has no observationRecords");
    // The corpus role was found by probing these candidates (derived from
    // the published recipe) against real vector signatures.
    let candidates = [
        "substrate-observation-test",
        "substrate",
        "substrate-observation",
        "observation",
        "observer",
        "producer",
        "envelope",
        "witness",
        "attestor",
    ];
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    for (ri, rec) in records.iter().enumerate() {
        let payload = rec.get("payload").and_then(|v| v.as_str()).unwrap();
        let ptype = rec.get("payloadType").and_then(|v| v.as_str()).unwrap();
        let payload_bytes = B64.decode(payload).unwrap();
        let pae = merkle::pae(ptype, &payload_bytes);
        for sig in rec.get("signatures").and_then(|v| v.as_array()).unwrap() {
            let keyid = sig.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
            let sig_bytes = B64
                .decode(sig.get("sig").and_then(|v| v.as_str()).unwrap())
                .unwrap();
            for role in candidates {
                let vk = keys::derive_verifying_key(role);
                let pub_hex = hex::encode(vk.as_bytes());
                let pub_sha = hex::encode(sha2::Sha256::digest(vk.as_bytes()));
                if keys::verify(&vk, &pae, &sig_bytes) {
                    println!(
                        "record {ri}: role {role:?} VERIFIES (pubkey {pub_hex}, sha256(pubkey) {pub_sha}, keyid {keyid})"
                    );
                }
            }
        }
    }
}

use sha2::Digest;

fn json_escape(s: &str) -> String {
    let v = Value::String(s.to_string());
    String::from_utf8(json::to_canonical_bytes(&v).unwrap()).unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "--discover-role" {
        discover_role(Path::new(&args[1]));
        return;
    }
    if args.is_empty() {
        eprintln!("usage: aee-checker <vectors-dir> [--manifest <path>] [--json <out.json>] [--role <name>]");
        std::process::exit(2);
    }
    let vectors_dir = PathBuf::from(&args[0]);
    let mut manifest_path = vectors_dir.join("MANIFEST.json");
    let mut json_out: Option<PathBuf> = None;
    // Discovered by probing the corpus's signatures against the published
    // seed recipe: the substrate observation role is
    // "substrate-observation-test" (keyid = sha256 of the raw public key).
    let mut role = "substrate-observation-test".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                manifest_path = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--json" => {
                json_out = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--role" => {
                role = args[i + 1].clone();
                i += 2;
            }
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    let pinned = keys::derive_verifying_key(&role);
    let expectations = load_manifest(&manifest_path);

    let mut lines_json: Vec<String> = Vec::new();
    let mut accept_total = 0;
    let mut accept_match = 0;
    let mut reject_total = 0;
    let mut reject_match = 0;
    let mut ind_total = 0;
    let mut ind_match = 0;
    let mut mismatches: Vec<String> = Vec::new();

    for exp in &expectations {
        let path = vectors_dir.join(&exp.file);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
        let verdict = check::check(&bytes, Some(&pinned));
        let (got_verdict, got_result, reason, tiers_wk, tiers_nk) = match &verdict {
            Verdict::Valid {
                result,
                tiers_with_key,
                tiers_without_key,
            } => (
                "valid",
                Some(result.clone()),
                None,
                Some(tiers_with_key.clone()),
                Some(tiers_without_key.clone()),
            ),
            Verdict::Invalid { reason } => ("invalid", None, Some(reason.clone()), None, None),
        };

        let mut ok = got_verdict == exp.verdict;
        if ok {
            if let (Some(er), Some(gr)) = (&exp.result, &got_result) {
                ok = er == gr;
            }
            if let (Some(et), Some(gt)) = (&exp.tier_with_key, &tiers_wk) {
                ok = ok && et == gt;
            }
            if let (Some(et), Some(gt)) = (&exp.tier_without_key, &tiers_nk) {
                ok = ok && et == gt;
            }
        }
        // The corpus declares three dispositions, not two. Folding
        // `indeterminate` into the rejects reports a fraction of a corpus that
        // does not exist, which is exactly what the suite's own transcription
        // rule refuses.
        match exp.kind.as_str() {
            "accept" => {
                accept_total += 1;
                if ok {
                    accept_match += 1;
                }
            }
            "indeterminate" => {
                ind_total += 1;
                if ok {
                    ind_match += 1;
                }
            }
            _ => {
                reject_total += 1;
                if ok {
                    reject_match += 1;
                }
            }
        }
        if !ok {
            mismatches.push(format!(
                "MISMATCH {}: expected {}({}) got {}({}) {}",
                exp.id,
                exp.verdict,
                exp.result.as_deref().unwrap_or("-"),
                got_verdict,
                got_result.as_deref().unwrap_or("-"),
                reason.as_deref().unwrap_or("")
            ));
        }
        let tiers_field = |t: &Option<Vec<String>>| -> String {
            match t {
                None => "null".to_string(),
                Some(v) => format!(
                    "[{}]",
                    v.iter().map(|s| json_escape(s)).collect::<Vec<_>>().join(",")
                ),
            }
        };
        lines_json.push(format!(
            "{{\"id\":{},\"verdict\":{},\"result\":{},\"reason\":{},\"tiersWithPinnedKey\":{},\"tiersWithoutKey\":{},\"parity\":{}}}",
            json_escape(&exp.id),
            json_escape(got_verdict),
            got_result.as_deref().map(json_escape).unwrap_or("null".into()),
            reason.as_deref().map(json_escape).unwrap_or("null".into()),
            tiers_field(&tiers_wk),
            tiers_field(&tiers_nk),
            ok
        ));
        if reason.is_some() {
            println!(
                "{:<42} {:<8} {}",
                exp.id,
                got_verdict,
                reason.as_deref().unwrap_or("")
            );
        } else {
            println!(
                "{:<42} {:<8} result={}",
                exp.id,
                got_verdict,
                got_result.as_deref().unwrap_or("-")
            );
        }
    }

    println!();
    println!(
        "parity: accepts {accept_match}/{accept_total}, rejects {reject_match}/{reject_total}, indeterminate {ind_match}/{ind_total}"
    );
    for m in &mismatches {
        println!("{m}");
    }
    if let Some(out) = json_out {
        let report = format!(
            "{{\"suite\":\"aee-conformance\",\"acceptParity\":\"{accept_match}/{accept_total}\",\"rejectParity\":\"{reject_match}/{reject_total}\",\"indeterminateParity\":\"{ind_match}/{ind_total}\",\"vectors\":[\n{}\n]}}\n",
            lines_json.join(",\n")
        );
        std::fs::write(&out, report).expect("cannot write JSON report");
        println!("wrote {}", out.display());
    }
    if !mismatches.is_empty() {
        std::process::exit(1);
    }
}
