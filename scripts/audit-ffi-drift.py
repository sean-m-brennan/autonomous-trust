#!/usr/bin/env python3
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
#
# Audit native FFI drift: compare the CFFI cdef in
#   src/autonomous-trust/autonomous_trust/core/_native/_ffi.py
# against the authoritative C declarations in src/c, and report any function
# whose argument COUNT disagrees. This is the cheap, env-free static check for
# the recurring class of bug where the C surface gains/loses a parameter but
# the Python cdef (and its callers) silently keep the old arity -- which CFFI
# does NOT validate until call time, where it shows up as a segfault (the C
# function reads a garbage extra arg off the stack).
#
# Severity:
#   DANGEROUS  drift in a function that a _native wrapper actually calls
#              (`lib.<name>(...)`). This is a latent segfault -> exit 1.
#   LATENT     drift in a cdef-only function nothing calls from Python yet.
#              Reported, but does not fail unless --strict.
#
# Authoritative source is the C *header* prototype (`...name(args);`); if a
# name has no header prototype we fall back to its `.c` definition
# (`...name(args){`). third_party/ is excluded. The `.c` fallback is noisier,
# so always eyeball a reported hit against the real header before editing.
#
# Usage:
#   scripts/audit-ffi-drift.py            # fail only on DANGEROUS drift
#   scripts/audit-ffi-drift.py --strict   # fail on LATENT drift too
#   scripts/audit-ffi-drift.py --quiet    # only print drift (for CI logs)
#
# Exit: 0 clean (or only LATENT without --strict); 1 drift; 2 could not parse.
#
# No third-party deps; runs without the conda env, so it is safe as a fast
# pre-build gate in CI or scripts/ci-local.sh.

import argparse
import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FFI = os.path.join(REPO, "src/autonomous-trust/autonomous_trust/core/_native/_ffi.py")
NATIVE_DIR = os.path.join(REPO, "src/autonomous-trust/autonomous_trust/core/_native")


def strip_comments(text):
    """Remove /* ... */ (incl. Frama-C /*@ ACSL @*/) and // comments."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def count_args(argstr):
    """Count C parameters: split on top-level commas; 'void'/'' -> 0."""
    argstr = argstr.strip()
    if argstr == "" or argstr.replace(" ", "") == "void":
        return 0
    depth = 0
    n = 1
    for c in argstr:
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "," and depth == 0:
            n += 1
    return n


def args_after(text, open_idx):
    """Given text[open_idx] == '(', return (arg_substring, next_nonspace_char)
    by balancing parens. Returns (None, '') if unbalanced."""
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                j = i + 1
                while j < len(text) and text[j].isspace():
                    j += 1
                return text[open_idx + 1:i], (text[j] if j < len(text) else "")
    return None, ""


def parse_cdef():
    """Return {name: argcount} for every function declared in the cdef(s)."""
    src = open(FFI, errors="replace").read()
    blocks = re.findall(r'cdef\(\s*(?:r|f)?"""(.*?)"""', src, re.S)
    if not blocks:
        print("ERROR: could not find ffi.cdef(\"\"\"...\"\"\") in _ffi.py", file=sys.stderr)
        sys.exit(2)
    blob = strip_comments("\n".join(blocks))
    funcs = {}
    for stmt in blob.split(";"):
        s = " ".join(stmt.split())
        if not s or "typedef" in s:
            continue
        # a declaration looks like:  <ret-type tokens> name(args)
        m = re.match(r"^[A-Za-z_].*?\b([A-Za-z_]\w*)\s*\((.*)\)\s*$", s)
        if m:
            funcs[m.group(1)] = count_args(m.group(2))
    return funcs


def collect(patterns):
    """Concatenate + comment-strip files matching patterns, skipping third_party."""
    out = []
    for pat in patterns:
        for f in glob.glob(os.path.join(REPO, pat), recursive=True):
            if "third_party" in f or f"{os.sep}build" in f:
                continue
            try:
                out.append(strip_comments(open(f, errors="replace").read()))
            except OSError:
                pass
    return "\n".join(out)


def c_arity(blob, name, terminator):
    """First `name(args)<terminator>` in blob -> argcount, else None.
    terminator ';' = prototype, '{' = definition."""
    for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(", blob):
        args, nxt = args_after(blob, m.end() - 1)
        if args is not None and nxt == terminator:
            return count_args(args)
    return None


def main():
    ap = argparse.ArgumentParser(description="Audit native FFI cdef arg-count drift.")
    ap.add_argument("--strict", action="store_true",
                    help="also fail on LATENT (uncalled) drift")
    ap.add_argument("--quiet", action="store_true",
                    help="print only drift lines")
    args = ap.parse_args()

    cdef = parse_cdef()
    headers = collect(["src/c/**/*.h"])
    sources = collect(["src/c/**/*.c"])
    pynative = collect_py()

    dangerous, latent, no_c = [], [], []
    for name, n_cdef in sorted(cdef.items()):
        n_c = c_arity(headers, name, ";")
        src_kind = "header"
        if n_c is None:
            n_c = c_arity(sources, name, "{")
            src_kind = ".c def"
        if n_c is None:
            no_c.append(name)
            continue
        if n_c != n_cdef:
            called = bool(re.search(r"\blib\." + re.escape(name) + r"\b", pynative))
            row = (name, n_cdef, n_c, src_kind, called)
            (dangerous if called else latent).append(row)

    if not args.quiet:
        print(f"cdef functions: {len(cdef)}  |  DANGEROUS: {len(dangerous)}  "
              f"LATENT: {len(latent)}  |  no C decl: {len(no_c)}\n")

    if dangerous:
        print("DANGEROUS drift (called by a _native wrapper -> latent segfault):")
        for name, nc, cc, kind, _ in dangerous:
            print(f"  ✗ {name}: cdef={nc} args, C {kind}={cc} args")
    if latent or not args.quiet:
        print("\nLATENT drift (cdef-only; nothing calls it from Python yet):")
        for name, nc, cc, kind, _ in latent:
            print(f"  ! {name}: cdef={nc} args, C {kind}={cc} args")
        if not latent:
            print("  (none)")
    if no_c and not args.quiet:
        print("\nNo C declaration found (macro / header-only / inline — review):")
        for name in no_c:
            print(f"  - {name}")

    fail = bool(dangerous) or (args.strict and bool(latent))
    if not args.quiet:
        print("\n" + ("FAIL: FFI drift detected." if fail else "OK: no blocking FFI drift."))
    return 1 if fail else 0


def collect_py():
    out = []
    for f in glob.glob(os.path.join(NATIVE_DIR, "**/*.py"), recursive=True):
        try:
            out.append(open(f, errors="replace").read())
        except OSError:
            pass
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
