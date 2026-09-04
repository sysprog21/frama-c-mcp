#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

python3 - << 'PY'
from pathlib import Path
import os
import re
import subprocess
import sys

roots = [
    Path("README.md"),
    Path("Cargo.toml"),

    # Scanned like any other source. The build script was simply never listed,
    # so nothing read it for CJK, translator output or a misspelled Frama-C.
    Path("build.rs"),
    Path("docs"),
    Path("src"),
    Path("tests"),
    Path("ast-utils"),
    Path("scripts"),
    Path(".github"),
    Path(".ci"),
]
skip_dirs = {".git", ".frama-c-mcp", "_build", "_opam", "target"}
skip_files = {Path("scripts/check-artifacts.sh")}

cjk = re.compile(r"[\u2e80-\u9fff\u3040-\u30ff\u3100-\u312f\uac00-\ud7af\uff00-\uffef]")
translator = re.compile(
    r"Google Translate|Translated by Google|This page could not be translated|"
    r"enable JavaScript and cookies|Attention Required!|Just a moment\.\.\.|"
    r"Checking if the site connection is secure|Sorry, you have been blocked|Access denied",
    re.IGNORECASE,
)
bad_frama = re.compile(r"\b(Frama C|Frama\.C|Frama[–—‑]C|frame-c)\b", re.IGNORECASE)
doc_path = re.compile(r"docs/[A-Za-z0-9._/#?=-]+\.(?:md|png|svg|json|txt|c|h)")


def active_files():
    for root in roots:
        if not root.exists() or root in skip_files:
            continue
        paths = [root] if root.is_file() else (p for p in root.rglob("*") if p.is_file())
        for path in paths:
            if path in skip_files or any(part in skip_dirs for part in path.parts):
                continue
            yield path


def read_text(path):
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def report(path, line_no, message, line):
    print(f"{path}:{line_no}: {message}: {line}", file=sys.stderr)


failed = False
for path in active_files():
    for line_no, line in enumerate(read_text(path), 1):
        for name, pattern in (
            ("CJK text", cjk),
            ("translator artifact", translator),
            ("misspelled Frama-C reference", bad_frama),
        ):
            if pattern.search(line):
                report(path, line_no, name, line)
                failed = True

seen = set()
for path in active_files():
    for line_no, line in enumerate(read_text(path), 1):
        for match in doc_path.finditer(line):
            target = match.group(0).rstrip(").,;:'\"]`>")
            target = target.split("#", 1)[0].split("?", 1)[0]
            if not target:
                continue
            key = (path, line_no, target)
            if key in seen:
                continue
            seen.add(key)
            if not Path(target).exists():
                report(path, line_no, f"dead docs path {target}", line)
                failed = True

# Relative markdown links, resolved against the tracked file list rather than
# against the working tree. CLAUDE.md, TODO.md and DONE.md live in a checkout
# nobody publishes: they sit in the working tree and are never committed, so
# os.path.exists answers yes on the machine that wrote the link and the link is
# a 404 for every reader. Measured once, on docs/agent-playbook.md linking to
# ../TODO.md, which every local check passed and no reader could follow.
#
# The doc_path scan above is not a substitute. It matches paths beginning with
# "docs/" wherever they appear, so a link that climbs out of the directory, or
# points at a file at the repository root, is not a path it recognises.
# In a repository the tracked list is the oracle, for the reason above. Outside
# one, an unpacked release tarball say, there is no such list and the files
# present are exactly the files published, so the filesystem answers the same
# question correctly. Falling back rather than skipping, because a check that
# quietly does nothing outside git is the failure this whole script is about.
listing = subprocess.run(["git", "ls-files"], capture_output=True, text=True)
tracked = set(listing.stdout.split()) if listing.returncode == 0 else None


def is_published(rel_path):
    return rel_path in tracked if tracked is not None else Path(rel_path).exists()


# A file the build reads that git does not carry. dune's "(modules :standard)"
# and cargo both glob the working tree, so an untracked source compiles on the
# machine that wrote it and every checkout fails on an unbound module in files
# nobody edited. This happened twice in one change: ast-utils/scripts, named by
# a preprocess action, and ast_utils_compat.ml, opened by seven modules.
#
# Asked of git rather than by walking directories. git already knows which files
# are untracked and not ignored, so there is no second root list to keep in step
# with the one above, no skip list to re-derive, and a deliberately ignored file
# cannot be reported. A hand-maintained list would have the same failure mode as
# the bug it catches: ast-utils/scripts was new in the change that added this.
#
# This is the one check here that cannot fire in CI, where a checkout is tracked
# by definition. That is the argument for it rather than against it: the mistake
# is local, so the catch has to be local too.
# Extends `roots` rather than restating it. A second hand-written list is the
# shape of the bug this check exists to catch: two lists to keep in step, and a
# source directory added to one and not the other goes unwatched. Everything
# `roots` covers is watched here for free, so a new root only has to be named
# once; below it are the build inputs that sit outside `roots` because the
# scans above have no reason to read them.
build_roots = [str(r) for r in roots] + ["Cargo.lock", ".cargo"]

# Narrowed by what the file is, since `roots` deliberately reaches into docs/
# and the markdown at the top, where an untracked draft is ordinary work in
# progress. A stray .md is a draft; a stray .ml under ast-utils/src is a module
# the build reads on the machine that wrote it and on no other. Failing the
# gate on drafts is how a reader learns to ignore it.
build_input_suffixes = {
    ".rs", ".ml", ".mli", ".sh", ".c", ".h", ".json", ".toml", ".lock", ".yml", ".yaml", ".opam"
}
build_input_names = {"dune", "dune-project"}


def is_build_input(rel_path):
    path = Path(rel_path)
    return path.name in build_input_names or path.suffix in build_input_suffixes


untracked = subprocess.run(
    ["git", "ls-files", "--others", "--exclude-standard", "--"] + build_roots,
    capture_output=True,
    text=True,
)
if untracked.returncode == 0:
    for rel_path in untracked.stdout.split():
        if is_build_input(rel_path):
            report(Path(rel_path), 0, "build input not tracked by git", "")
            failed = True

md_link = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
md_files = (
    sorted(p for p in tracked if p.endswith(".md"))
    if tracked is not None
    else sorted(str(p) for p in Path(".").rglob("*.md") if not any(part in skip_dirs for part in p.parts))
)
for path in md_files:
    for line_no, line in enumerate(read_text(Path(path)), 1):
        for target in md_link.findall(line):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
            if not is_published(resolved):
                report(path, line_no, f"link to untracked or missing {target}", line)
                failed = True

if failed:
    sys.exit(1)
PY
