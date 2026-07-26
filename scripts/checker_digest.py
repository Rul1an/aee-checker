#!/usr/bin/env python3
"""Deterministic digest of the checker's own source.

Importable: `validate-index.py` uses `checker_source_digest` directly rather than
keeping a second copy of the algorithm, since two implementations of one digest is
two chances to disagree about what identity means.

A run record is a statement about an implementation under test, so it has to name
which implementation produced it. A commit SHA cannot do that from inside the
commit it names, so this hashes the source that actually decides the outcome:
`Cargo.toml`, `Cargo.lock` and everything under `src/`. Same source, same digest,
regardless of which commit carries it or what is written in the docs beside it.

Usage: checker_digest.py [repo-root]
"""
import hashlib
import pathlib
import sys


def checker_source_digest(root: pathlib.Path) -> str:
    files = [root / "Cargo.toml", root / "Cargo.lock"]
    files += sorted(p for p in (root / "src").rglob("*") if p.is_file())

    h = hashlib.sha256()
    for path in files:
        rel = path.relative_to(root).as_posix()
        data = path.read_bytes()
        # Length-prefixed so a rename cannot collide with a content change.
        h.update(f"{rel}\0{len(data)}\0".encode())
        h.update(data)
    return "sha256:" + h.hexdigest()


def checker_source_digest_at(root: pathlib.Path, commit: str) -> str:
    """The same digest, computed from a commit rather than the working tree.

    Historical records name a checker that is no longer checked out. Recomputing
    their digest from the commit is what turns `checkerCommit` from a label into a
    claim: the two have to agree, or one of them is wrong.
    """
    import subprocess

    def git(*args: str) -> bytes:
        return subprocess.run(
            ["git", "-C", str(root), *args], check=True, capture_output=True
        ).stdout

    listed = git("ls-tree", "-r", "--name-only", commit, "--", "src").decode().split()
    paths = ["Cargo.toml", "Cargo.lock"] + sorted(listed)

    h = hashlib.sha256()
    for rel in paths:
        data = git("show", f"{commit}:{rel}")
        h.update(f"{rel}\0{len(data)}\0".encode())
        h.update(data)
    return "sha256:" + h.hexdigest()


if __name__ == "__main__":
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    print(checker_source_digest(root))
