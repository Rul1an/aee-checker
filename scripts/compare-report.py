#!/usr/bin/env python3
"""Compare a freshly generated parity report against the checked-in evidence.

The parity number in the README is only worth what someone else can re-run, so a
drift has to surface as the vectors that moved rather than as a byte diff nobody
reads. That means the mismatch path is the important one: it has to name the
vectors and exit non-zero, without a traceback standing in for a diagnosis.
"""
import json
import sys

# Each vector record is keyed by `id`. An earlier revision of this script used
# `vector`, which only ever ran on the equal path, so the mismatch path raised
# KeyError and exited 1 for the wrong reason. `tests/test_compare_report.py`
# holds that path shut.
ID = "id"


def index(report, path):
    out = {}
    for i, v in enumerate(report.get("vectors", [])):
        if ID not in v:
            raise SystemExit(f"{path}: vectors[{i}] has no {ID!r} member; keys are {sorted(v)}")
        key = v[ID]
        if not isinstance(key, str):
            raise SystemExit(
                f"{path}: vectors[{i}] has a non-string {ID!r} ({type(key).__name__}: {key!r})"
            )
        if key in out:
            raise SystemExit(f"{path}: {ID} {key!r} appears more than once; ids must be unique")
        out[key] = v
    return out


def main(fresh_path: str, pinned_path: str) -> int:
    with open(fresh_path) as f:
        fresh = json.load(f)
    with open(pinned_path) as f:
        pinned = json.load(f)

    if fresh == pinned:
        print(f"{pinned_path} reproduces exactly")
        return 0

    fk = index(fresh, fresh_path)
    pk = index(pinned, pinned_path)
    for name in sorted(set(fk) | set(pk)):
        a, b = fk.get(name), pk.get(name)
        if a == b:
            continue
        if a is None:
            print(f"differs: {name}: absent from the fresh run", file=sys.stderr)
        elif b is None:
            print(f"differs: {name}: absent from the checked-in report", file=sys.stderr)
        else:
            fields = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
            print(f"differs: {name}: {', '.join(fields)}", file=sys.stderr)

    for key in ("suite", "acceptParity", "rejectParity"):
        if fresh.get(key) != pinned.get(key):
            print(
                f"differs: {key}: fresh={fresh.get(key)!r} pinned={pinned.get(key)!r}",
                file=sys.stderr,
            )

    print(f"{pinned_path} does not match a fresh run", file=sys.stderr)
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: compare-report.py <fresh.json> <pinned.json>")
    sys.exit(main(sys.argv[1], sys.argv[2]))
