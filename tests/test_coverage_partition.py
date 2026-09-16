#!/usr/bin/env python3
"""The coverage partition must hold for all three sets, not only assessedClasses.

Revision 2 does not force this. `bad-819-assessed-class-not-in-manifest` covers
`assessedClasses`; nothing in the corpus puts an unknown key in `outOfScope` or
`routedElsewhere`. The gap was real rather than theoretical: with an unknown key in
either map and `result` left alone, the checker reported full parity. The result
recompute does not cover it either, because it ignores non-manifest classes
entirely, so nothing downstream caught what this misses.

Skips when the conformance suite is not checked out, and runs in CI where it is.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def suite_dir():
    """The checked-out suite, or None when none is present locally.

    A directory named by AEE_CONFORMANCE_DIR must be usable: CI sets it, and a
    suite that is checked out but unreadable has to fail the step rather than
    skip it, or the test goes quiet exactly when the corpus layout moves.
    """
    named = os.environ.get("AEE_CONFORMANCE_DIR")
    if named:
        if not (pathlib.Path(named) / "vectors" / "MANIFEST.json").exists():
            raise SystemExit(f"FAIL: AEE_CONFORMANCE_DIR={named} has no vectors/MANIFEST.json")
        return pathlib.Path(named)
    for candidate in (
        # The suite was renamed; the new name is what the README clones to.
        # The old name stays as a fallback for checkouts made before the rename.
        ROOT / "agent-evidence-vectors",
        ROOT.parent / "agent-evidence-vectors",
        ROOT / "aee-conformance",
        ROOT.parent / "aee-conformance",
    ):
        if (candidate / "vectors" / "MANIFEST.json").exists():
            return candidate
    return None


def accept_vector(suite: pathlib.Path):
    """The first accepted statement whose result is fail, read from the manifest.

    The manifest names each statement's file, so the test follows it instead of
    assuming a directory layout. A fail result keeps the recompute from masking
    the coverage fault: the mutation below leaves the result alone.
    """
    manifest = json.loads((suite / "vectors" / "MANIFEST.json").read_text())
    for entry in manifest.get("vectors", []):
        if entry.get("kind") == "accept" and entry.get("expected", {}).get("result") == "fail":
            return entry["id"], entry["file"]
    raise SystemExit("FAIL: the manifest lists no accepted statement with result fail")


def run_with_unknown_key(suite: pathlib.Path, reason_map: str):
    tmp = pathlib.Path(tempfile.mkdtemp())
    vectors = tmp / "vectors"
    shutil.copytree(suite / "vectors", vectors)

    vector_id, vector_file = accept_vector(suite)
    target = vectors / vector_file
    doc = json.loads(target.read_text())
    # `result` is deliberately left alone: changing it would make the result
    # recompute fire and mask the coverage fault behind an unrelated one.
    doc["predicate"]["coverage"][reason_map] = {"XZZ": "not a manifest class"}
    target.write_text(json.dumps(doc, indent=2))

    r = subprocess.run(
        ["cargo", "run", "--locked", "--release", "--quiet", "--", str(vectors)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    shutil.rmtree(tmp, ignore_errors=True)
    return vector_id, r


def main() -> int:
    suite = suite_dir()
    if suite is None:
        print("skip: conformance suite not checked out (set AEE_CONFORMANCE_DIR)")
        return 0

    for reason_map in ("outOfScope", "routedElsewhere"):
        vector_id, r = run_with_unknown_key(suite, reason_map)
        out = r.stdout + r.stderr
        assert f"MISMATCH {vector_id}" in out, (
            f"an unknown {reason_map} class must be refused; the checker accepted it:\n{out[-800:]}"
        )
        assert f"{reason_map} class" in out, (
            f"the refusal should name {reason_map}; got:\n{out[-800:]}"
        )
        print(f"ok  unknown {reason_map} class is refused")

    print("all coverage-partition tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
