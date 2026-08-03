#!/usr/bin/env python3
"""Check that reports/INDEX.json still describes the records it claims to.

The index carries the provenance the record files cannot carry themselves, which
only helps if it is bound to them. Without this, a report could be swapped or the
metadata could drift and nothing would fail. Checked here: the record set is
exactly the indexed set, each report's sha256 matches, the counts and parity
strings in the index match the record's own contents, and the current record's
checkerSourceDigest matches the source in the working tree.
"""
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from checker_digest import checker_source_digest, checker_source_digest_at

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
INDEX = REPORTS / "INDEX.json"


def main() -> int:
    index = json.loads(INDEX.read_text())
    problems = []

    files = [r["file"] for r in index["records"]]
    for name in sorted({f for f in files if files.count(f) > 1}):
        problems.append(f"{name}: appears {files.count(name)} times in INDEX.json; one entry per record")

    indexed = set(files)
    on_disk = {p.name for p in REPORTS.glob("*.json") if p.name != "INDEX.json"}
    for extra in sorted(on_disk - indexed):
        problems.append(f"{extra}: present in reports/ but absent from INDEX.json")
    for missing in sorted(indexed - on_disk):
        problems.append(f"{missing}: named in INDEX.json but absent from reports/")

    live = checker_source_digest(ROOT)

    for rec in index["records"]:
        path = REPORTS / rec["file"]
        if not path.exists():
            continue
        raw = path.read_bytes()
        actual = "sha256:" + hashlib.sha256(raw).hexdigest()
        if actual != rec["reportSha256"]:
            problems.append(
                f"{rec['file']}: reportSha256 is {rec['reportSha256']} but the file hashes to {actual}"
            )

        report = json.loads(raw)
        if len(report.get("vectors", [])) != rec["vectors"]:
            problems.append(
                f"{rec['file']}: index says {rec['vectors']} vectors, record has {len(report.get('vectors', []))}"
            )
        for key in ("acceptParity", "rejectParity", "indeterminateParity"):
            # indeterminateParity exists only on records made after the corpus
            # grew a third disposition; older records legitimately omit it.
            if key not in rec:
                continue
            if report.get(key) != rec[key]:
                problems.append(
                    f"{rec['file']}: index says {key}={rec[key]!r}, record says {report.get(key)!r}"
                )

        # Only the continuously verified record is expected to match the working
        # tree; the others were produced by an earlier checker on purpose.
        if rec.get("continuouslyVerified") and rec["checkerSourceDigest"] != live:
            problems.append(
                f"{rec['file']}: checkerSourceDigest is {rec['checkerSourceDigest']} "
                f"but the working tree hashes to {live}; regenerate the report or update the index"
            )

    # Suite provenance. It cannot be verified offline against the suite itself, so
    # what is checked is shape, internal agreement, and for the record CI actually
    # re-runs, equality with the pins the workflow uses. Without this the fields
    # the index exists to carry were the only ones nothing looked at.
    HEX40 = re.compile(r"^[0-9a-f]{40}$")
    DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
    by_revision = {}
    verified = [r for r in index["records"] if r.get("continuouslyVerified")]

    for rec in index["records"]:
        if not HEX40.match(rec.get("suiteCommit", "")):
            problems.append(f"{rec['file']}: suiteCommit is not a 40-character lowercase hex commit")
        for key in ("reportSha256", "checkerSourceDigest", "specDigest"):
            if key not in rec:
                continue
            # An explicit null is a permitted value for checkerSourceDigest and
            # for it alone: it records that the build behind a figure is not
            # recoverable, which is a fact a provenance index must be able to
            # state. Omitting the key instead would hide the same fact, and
            # filling it with another build's digest would name the wrong
            # implementation. A null demands a note saying why.
            if rec[key] is None:
                if key != "checkerSourceDigest":
                    problems.append(f"{rec['file']}: {key} may not be null")
                elif not rec.get("sourceUnrecoverable"):
                    # A note is prose anything can satisfy. The claim that a build
                    # is unrecoverable is a specific one, so it gets its own field
                    # and a record cannot shed provenance behind a one-word note.
                    problems.append(
                        f"{rec['file']}: checkerSourceDigest is null without a "
                        f"sourceUnrecoverable field recording why"
                    )
                elif rec.get("checkerCommit"):
                    # A named commit is a recoverable build by definition.
                    problems.append(
                        f"{rec['file']}: checkerSourceDigest is null but the record "
                        f"names checkerCommit {rec['checkerCommit']}, from which the "
                        f"digest is recomputable"
                    )
                continue
            if not DIGEST.match(rec[key]):
                problems.append(f"{rec['file']}: {key} is not a sha256:<64 hex> digest")
        prior = by_revision.setdefault(
            rec["suiteRevision"], (rec["file"], rec.get("suiteCommit"), rec.get("specDigest"))
        )
        if (rec.get("suiteCommit"), rec.get("specDigest")) != prior[1:]:
            problems.append(
                f"{rec['file']}: suiteRevision {rec['suiteRevision']} disagrees with {prior[0]} "
                f"on suiteCommit or specDigest"
            )

    # Historical provenance. `checkerCommit` was the one field nothing looked at, so
    # it could name anything at all. Recomputing the digest from that commit is what
    # makes it a claim rather than a label: the commit has to exist and its source has
    # to hash to what the record says. Needs full history, hence fetch-depth: 0 in CI.
    for rec in index["records"]:
        commit = rec.get("checkerCommit")
        if commit is None:
            continue
        if not HEX40.match(commit):
            problems.append(f"{rec['file']}: checkerCommit is not a 40-character lowercase hex commit")
            continue
        try:
            recomputed = checker_source_digest_at(ROOT, commit)
        except Exception:
            problems.append(
                f"{rec['file']}: checkerCommit {commit[:12]} is not resolvable in this repository "
                f"(CI needs fetch-depth: 0 for full history)"
            )
            continue
        if rec["checkerSourceDigest"] is None:
            # Already reported above as a null beside a named commit; do not
            # subscript None here.
            continue
        if recomputed != rec["checkerSourceDigest"]:
            problems.append(
                f"{rec['file']}: checkerSourceDigest is {rec['checkerSourceDigest'][:19]}… "
                f"but commit {commit[:12]} hashes to {recomputed[:19]}…"
            )

    if len(verified) != 1:
        problems.append(
            f"expected exactly one continuouslyVerified record, found {len(verified)}; "
            f"CI re-runs one and only one"
        )
    else:
        wf = (ROOT / ".github/workflows/conformance.yml").read_text()
        for key, field in (("SUITE_COMMIT", "suiteCommit"), ("SPEC_DIGEST", "specDigest")):
            m = re.search(rf"^\s*{key}:\s*(\S+)\s*$", wf, re.M)
            if not m:
                problems.append(f"workflow does not pin {key}")
                continue
            pinned = m.group(1)
            claimed = verified[0].get(field, "")
            if claimed.removeprefix("sha256:") != pinned:
                problems.append(
                    f"{verified[0]['file']}: {field} is {claimed!r} but the workflow pins {key}={pinned!r}"
                )

    if problems:
        for p in problems:
            print(f"INDEX: {p}", file=sys.stderr)
        return 1
    print(f"INDEX.json binds {len(index['records'])} records; digests, counts and parity all match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
