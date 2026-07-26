#!/usr/bin/env python3
"""Negative tests for the index validator.

The validator exists to make the provenance fields checkable, so the cases worth
holding shut are the ones where it could pass while those fields are wrong. Two of
these were live: forged suite provenance and a duplicated entry both returned exit
0, because the validator bound report bytes and counts but nothing about the suite.
"""
import copy
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = "scripts/validate-index.py"


def in_copy(mutate):
    """Run the validator over a throwaway copy of the repo with `mutate` applied."""
    tmp = pathlib.Path(tempfile.mkdtemp())
    work = tmp / "repo"
    shutil.copytree(
        ROOT, work, ignore=shutil.ignore_patterns("target", "__pycache__", "*.lock.tmp")
    )
    mutate(work)
    r = subprocess.run(
        [sys.executable, SCRIPT], cwd=work, capture_output=True, text=True
    )
    shutil.rmtree(tmp, ignore_errors=True)
    return r


def load(work):
    return json.loads((work / "reports/INDEX.json").read_text())


def save(work, index):
    (work / "reports/INDEX.json").write_text(json.dumps(index, indent=2) + "\n")


def expect_fail(r, needle):
    assert r.returncode == 1, f"expected exit 1, got {r.returncode}\n{r.stdout}{r.stderr}"
    assert needle in r.stderr, f"expected {needle!r} in stderr, got:\n{r.stderr}"
    assert "Traceback" not in r.stderr, r.stderr


def test_clean_repo_passes():
    r = in_copy(lambda w: None)
    assert r.returncode == 0, r.stderr


def test_forged_suite_commit_is_refused():
    def m(w):
        i = load(w)
        for rec in i["records"]:
            if rec.get("continuouslyVerified"):
                rec["suiteCommit"] = "0" * 40
        save(w, i)
    expect_fail(in_copy(m), "the workflow pins SUITE_COMMIT")


def test_forged_spec_digest_is_refused():
    def m(w):
        i = load(w)
        for rec in i["records"]:
            if rec.get("continuouslyVerified"):
                rec["specDigest"] = "sha256:" + "0" * 64
        save(w, i)
    expect_fail(in_copy(m), "the workflow pins SPEC_DIGEST")


def test_a_malformed_commit_is_refused():
    def m(w):
        i = load(w)
        i["records"][0]["suiteCommit"] = "not-a-commit"
        save(w, i)
    expect_fail(in_copy(m), "not a 40-character lowercase hex commit")


def test_duplicate_entries_are_refused():
    def m(w):
        i = load(w)
        i["records"].append(copy.deepcopy(i["records"][-1]))
        save(w, i)
    expect_fail(in_copy(m), "one entry per record")


def test_two_records_of_one_revision_must_agree_on_the_suite():
    def m(w):
        i = load(w)
        for rec in i["records"]:
            if rec["file"] == "suite-revision-2-baseline.json":
                rec["suiteCommit"] = "b" * 40
        save(w, i)
    expect_fail(in_copy(m), "disagrees with")


def test_a_forged_historical_checker_commit_is_refused():
    """checkerCommit was the one provenance field nothing looked at, so it could
    name anything. This is the exact mutation that once passed."""
    def m(w):
        i = load(w)
        for rec in i["records"]:
            if rec["file"] == "suite-revision-1.json":
                rec["checkerCommit"] = "not-a-commit"
                rec["checkerSourceDigest"] = "sha256:" + "0" * 64
        save(w, i)
    expect_fail(in_copy(m), "checkerCommit is not a 40-character lowercase hex commit")


def test_a_historical_digest_that_disagrees_with_its_commit_is_refused():
    """A well-formed commit that hashes to something else. Catching this is what
    makes checkerCommit a claim rather than a label."""
    def m(w):
        i = load(w)
        for rec in i["records"]:
            if rec["file"] == "suite-revision-1.json":
                rec["checkerSourceDigest"] = "sha256:" + "a" * 64
        save(w, i)
    expect_fail(in_copy(m), "hashes to")


def test_an_unresolvable_historical_commit_is_refused():
    def m(w):
        i = load(w)
        for rec in i["records"]:
            if rec["file"] == "suite-revision-1.json":
                rec["checkerCommit"] = "0" * 40
        save(w, i)
    expect_fail(in_copy(m), "not resolvable in this repository")


def test_more_than_one_continuously_verified_record_is_refused():
    def m(w):
        i = load(w)
        for rec in i["records"]:
            rec["continuouslyVerified"] = True
        save(w, i)
    expect_fail(in_copy(m), "exactly one continuouslyVerified record")


def test_no_continuously_verified_record_is_refused():
    def m(w):
        i = load(w)
        for rec in i["records"]:
            rec["continuouslyVerified"] = False
        save(w, i)
    expect_fail(in_copy(m), "exactly one continuouslyVerified record")


def test_an_unindexed_report_is_refused():
    def m(w):
        shutil.copy(w / "reports/suite-revision-2.json", w / "reports/extra.json")
    expect_fail(in_copy(m), "absent from INDEX.json")


def test_a_missing_report_is_refused():
    def m(w):
        (w / "reports/suite-revision-1.json").unlink()
    expect_fail(in_copy(m), "absent from reports/")


def test_a_changed_report_is_refused():
    def m(w):
        p = w / "reports/suite-revision-2.json"
        d = json.loads(p.read_text())
        d["acceptParity"] = "99/99"
        p.write_text(json.dumps(d, indent=2))
    expect_fail(in_copy(m), "reportSha256")


def test_changed_checker_source_without_a_regenerated_report_is_refused():
    def m(w):
        (w / "src/main.rs").write_text((w / "src/main.rs").read_text() + "\n")
    expect_fail(in_copy(m), "working tree hashes to")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("all index-validator tests passed")
