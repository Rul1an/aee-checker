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
ACCEPT_VECTOR = "accept/ok-001-caught-intercepted-fail.json"


def suite_dir():
    for candidate in (
        os.environ.get("AEE_CONFORMANCE_DIR"),
        ROOT / "aee-conformance",
        ROOT.parent / "aee-conformance",
    ):
        if candidate and (pathlib.Path(candidate) / "vectors" / ACCEPT_VECTOR).exists():
            return pathlib.Path(candidate)
    return None


def run_with_unknown_key(suite: pathlib.Path, reason_map: str):
    tmp = pathlib.Path(tempfile.mkdtemp())
    vectors = tmp / "vectors"
    shutil.copytree(suite / "vectors", vectors)

    target = vectors / ACCEPT_VECTOR
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
    return r


def main() -> int:
    suite = suite_dir()
    if suite is None:
        print("skip: conformance suite not checked out (set AEE_CONFORMANCE_DIR)")
        return 0

    for reason_map in ("outOfScope", "routedElsewhere"):
        r = run_with_unknown_key(suite, reason_map)
        out = r.stdout + r.stderr
        assert "MISMATCH ok-001" in out, (
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
