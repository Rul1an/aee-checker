#!/usr/bin/env python3
"""Hold the comparator's mismatch path shut.

The equal path is self-testing: CI runs it every build. The mismatch path only
runs when something is already wrong, which is exactly when a crash is least
useful, so it gets a test of its own. An earlier revision indexed on the wrong
member name and raised KeyError there while still exiting 1, so an exit-code
check alone would not have caught it.
"""
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "compare-report.py"
PINNED = ROOT / "reports" / "suite-revision-2.json"


def run(fresh_path, pinned_path):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(fresh_path), str(pinned_path)],
        capture_output=True,
        text=True,
    )


def test_identical_reports_pass():
    r = run(PINNED, PINNED)
    assert r.returncode == 0, r.stderr
    assert "reproduces exactly" in r.stdout


def test_a_mutated_vector_is_named_without_a_traceback():
    report = json.loads(PINNED.read_text())
    target = report["vectors"][0]["id"]
    report["vectors"][0]["verdict"] = "mutated-for-test"

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(report, fh)
        mutated = fh.name

    r = run(mutated, PINNED)
    assert r.returncode == 1, f"expected exit 1, got {r.returncode}"
    assert target in r.stderr, f"the differing vector id must be named; stderr was:\n{r.stderr}"
    assert "verdict" in r.stderr, f"the differing field should be named; stderr was:\n{r.stderr}"
    assert "Traceback" not in r.stderr, f"a diagnosis, not a crash; stderr was:\n{r.stderr}"


def test_a_vector_only_in_the_fresh_run_is_named():
    """The absent-from branches had no test, which is the same untested-error-path
    shape the id fix was about."""
    report = json.loads(PINNED.read_text())
    extra = dict(report["vectors"][0])
    extra["id"] = "ok-999-invented"
    report["vectors"].append(extra)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(report, fh)
        mutated = fh.name

    r = run(mutated, PINNED)
    assert r.returncode == 1
    assert "ok-999-invented" in r.stderr, r.stderr
    assert "absent from the checked-in report" in r.stderr, r.stderr
    assert "Traceback" not in r.stderr, r.stderr


def test_a_vector_missing_from_the_fresh_run_is_named():
    report = json.loads(PINNED.read_text())
    dropped = report["vectors"].pop(0)["id"]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(report, fh)
        mutated = fh.name

    r = run(mutated, PINNED)
    assert r.returncode == 1
    assert dropped in r.stderr, r.stderr
    assert "absent from the fresh run" in r.stderr, r.stderr
    assert "Traceback" not in r.stderr, r.stderr


def test_a_duplicate_vector_id_fails_readably():
    """Silently keeping the last of two same-id records would drop a vector from the
    comparison entirely, which is the opposite of what a comparator is for."""
    report = json.loads(PINNED.read_text())
    report["vectors"].append(dict(report["vectors"][0]))
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(report, fh)
        dup = fh.name

    r = run(dup, PINNED)
    assert r.returncode != 0
    assert "appears more than once" in r.stderr, r.stderr
    assert "Traceback" not in r.stderr, r.stderr


def test_a_non_string_vector_id_fails_readably():
    report = json.loads(PINNED.read_text())
    report["vectors"][0]["id"] = 17
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(report, fh)
        bad = fh.name

    r = run(bad, PINNED)
    assert r.returncode != 0
    assert "non-string" in r.stderr, r.stderr
    assert "Traceback" not in r.stderr, r.stderr


def test_a_report_with_the_wrong_member_name_fails_readably():
    report = json.loads(PINNED.read_text())
    report["vectors"][0] = {"vector": "renamed", "verdict": "x"}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(report, fh)
        broken = fh.name

    r = run(broken, PINNED)
    assert r.returncode != 0
    assert "has no 'id'" in r.stderr, r.stderr
    assert "Traceback" not in r.stderr, r.stderr


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all comparator tests passed")
