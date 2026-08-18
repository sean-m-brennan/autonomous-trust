#!/usr/bin/env python3
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
#
# Audit native FFI drift: compare the CFFI cdef in
#   src/autonomous-trust/autonomous_trust/core/_native/_ffi.py
# against the authoritative C declarations in src/c. Two independent checks:
#
# FUNCTIONS  argument COUNT per function. CFFI does NOT validate arity until call time,
# where a mismatch is a segfault (the C function reads a garbage extra arg off the
# stack). STRUCTS    ordered FIELD-NAME LIST per struct the cdef mirrors. The cdef
# hand-mirrors C struct layouts, and a layout mismatch is worse than an arity one: it
# corrupts memory on every call, silently, until an unrelated free() aborts.
# `public_identity_t` drifted twice in seven days
# (doc/architecture/native-ffi-dual-implementation.md, §9.2.2) -- 48 bytes short, then
# 912 -- and both times this script was blind to it because it compared only arity. A
# comment in the cdef stated the rule that
#              the next commit broke; a comment is not a check.
#
# Severity (both checks):
#   DANGEROUS  the drifting name is one Python actually uses -- a function a
#              _native wrapper calls (`lib.<name>(...)`), or a struct Python
#              allocates or sizes (`ffi.new('X *')`, `ffi.sizeof('X')`). A short
#              allocation is a heap overflow on every write -> exit 1.
#   LATENT     drift in something nothing touches from Python yet. A struct in
#              this class is a MISREAD (wrong field offsets) rather than an
#              overflow. Reported, but does not fail unless --strict.
#
# What the struct check does and does not catch: it compares field NAMES in
# order, so it catches an added, removed, renamed or reordered field -- the shape
# of both real recurrences. It does NOT catch a type-width or padding change
# (`uint32_t` -> `uint64_t` keeps every name), because it deliberately does not
# compile anything. `--abi` does exactly that instead: it generates a probe from
# the same struct list, compiles it against the real headers
# (`-DAT_ZTA_ENABLED -fms-extensions`), and diffs `sizeof`/`offsetof` against
# `ffi.sizeof`/`ffi.offsetof` -- localizing a size difference to the first field
# whose offset disagrees. It needs a compiler, cffi and the generated
# `*.pb-c.h`, so it stays opt-in and reports plainly when it cannot run rather
# than passing quietly. Two checks at two speeds, as §9.2 recommends.
#
# Two wrinkles the struct check has to handle, because C and the cdef spell the
# same ABI differently:
#   * ANONYMOUS MEMBERS. C embeds `smrt_ptr_t;` with no field name (needs
#     -fms-extensions, see the header note in identity.h); the cdef flattens it
#     to `bool alloc; size_t refs;`. Both sides are therefore flattened through
#     the typedef map before comparison, so the spellings converge.
#   * CONDITIONAL FIELDS. C wraps the ZTA fields in `#ifdef AT_ZTA_ENABLED`
#     while the cdef lists them unconditionally -- correctly, since the native
#     lib is built AT_ZTA=ON. Conditionals are resolved against DEFINED below
#     rather than diffed as text, and any OTHER macro met inside a mirrored
#     struct is reported as a warning instead of being silently assumed off.
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
#   scripts/audit-ffi-drift.py --only structs   # one check at a time
#   scripts/audit-ffi-drift.py --abi      # ALSO measure sizeof/offsetof by
#                                         # compiling a probe (needs a compiler,
#                                         # cffi and the generated *.pb-c.h;
#                                         # says so and skips if absent)
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


def cdef_blob():
    """The comment-stripped text of every ffi.cdef(\"\"\"...\"\"\") block."""
    src = open(FFI, errors="replace").read()
    blocks = re.findall(r'cdef\(\s*(?:r|f)?"""(.*?)"""', src, re.S)
    if not blocks:
        print("ERROR: could not find ffi.cdef(\"\"\"...\"\"\") in _ffi.py", file=sys.stderr)
        sys.exit(2)
    return strip_comments("\n".join(blocks))


def parse_cdef():
    """Return {name: argcount} for every function declared in the cdef(s)."""
    blob = cdef_blob()
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


# --- struct field-name mirroring (doc/architecture/native-ffi-dual-implementation.md)
# ----------------------------

#: Macros the native library IS built with, so fields they guard are part of the
#: ABI the cdef must mirror. `build-native.sh` passes -DAT_ZTA=ON, which defines
#: AT_ZTA_ENABLED. Anything NOT listed here is treated as undefined -- and, when
#: it guards part of a mirrored struct, reported rather than assumed.
DEFINED = ('AT_ZTA_ENABLED',)

#: Field spellings that differ between C and the cdef ON PURPOSE, per struct, as
#: {struct: {cdef_name: c_name}}. Both sides are ABI-identical here -- same type,
#: same position -- so listing them keeps the check from stopping at a known
#: difference and going blind to the rest of the struct. Keep this table tiny and
#: justified: an entry is a place this check cannot see. A TYPE change under one
#: of these names is invisible to a name comparison either way; that is the
#: probe's job (see the header note).
FIELD_ALIASES = {
    # C spells these `private` / `public`; the cdef is explicit that they are
    # keys, which reads better at the Python call sites.
    "signature_t": {"private_key": "private", "public_key": "public"},
    "encryptor_t": {"private_key": "private", "public_key": "public"},
}

#: Anonymous embeds of a SYSTEM struct we cannot parse, and the field list they
#: contribute. `datetime_t` embeds glibc's `struct tm;` anonymously (again via
#: -fms-extensions) and the cdef writes those fields out inline, because CFFI has
#: no `struct tm` of its own -- so without this the two spellings of one ABI look
#: like drift. If glibc ever reordered these the ABI would change with them,
#: which a name check could not see anyway.
EXTERNAL_ANON = {
    "tm": ["tm_sec", "tm_min", "tm_hour", "tm_mday", "tm_mon", "tm_year",
           "tm_wday", "tm_yday", "tm_isdst", "tm_gmtoff", "tm_zone"],
}


def resolve_conditionals(text, defined=DEFINED):
    """Evaluate #ifdef/#ifndef/#if defined(...) so guarded fields resolve.

    Returns (resolved_text, dropped_macros), where dropped_macros names every
    macro whose guarded text was REMOVED because the macro is not in `defined` --
    the ones that could hide a field, so the caller can say so out loud rather
    than silently assuming the field is not part of the ABI. A guard that KEPT its
    text (an `#ifndef` include guard, say) is not reported: nothing is missing.
    Conditions other than `defined()`-style are treated as false and reported the
    same way. Naive text-diffing is not an option here: C guards the ZTA fields
    while the cdef lists them unconditionally, which is correct, so the
    conditional has to be resolved rather than compared.
    """
    out, unknown = [], set()
    stack = []          # (keeping_now, seen_true, condition_text)
    for line in text.splitlines():
        stripped = line.strip()
        directive = re.match(r"#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)", stripped)
        if directive:
            kind, rest = directive.group(1), directive.group(2).strip()
            if kind in ("ifdef", "ifndef", "if"):
                if kind == "ifdef":
                    value = rest in defined
                    # A dropped `#ifdef` block is exactly where a field can hide,
                    # so name the macro whether or not the condition parsed.
                    if not value:
                        unknown.add(rest.split()[0] if rest.split() else rest)
                elif kind == "ifndef":
                    value = rest not in defined
                else:
                    value, known = _eval_if(rest, defined)
                    if not value or not known:
                        unknown.update(re.findall(r"[A-Za-z_]\w*", rest) or [rest])
                stack.append([value, value, rest])
            elif kind == "elif":
                if stack:
                    value, known = _eval_if(rest, defined)
                    if not known:
                        unknown.update(re.findall(r"[A-Za-z_]\w*", rest) or [rest])
                    keep = value and not stack[-1][1]
                    stack[-1][0] = keep
                    stack[-1][1] = stack[-1][1] or keep
            elif kind == "else":
                if stack:
                    stack[-1][0] = not stack[-1][1]
                    stack[-1][1] = True
            else:                       # endif
                if stack:
                    stack.pop()
            out.append("")              # keep line numbering stable
            continue
        out.append(line if all(frame[0] for frame in stack) else "")
    return "\n".join(out), unknown


def _eval_if(expr, defined):
    """(value, understood) for a `#if` condition, over defined()/!/&&/|| only."""
    text = expr
    text = re.sub(r"defined\s*\(\s*([A-Za-z_]\w*)\s*\)",
                  lambda m: "1" if m.group(1) in defined else "0", text)
    text = re.sub(r"defined\s+([A-Za-z_]\w*)",
                  lambda m: "1" if m.group(1) in defined else "0", text)
    if re.search(r"[A-Za-z_]", text):
        return False, False             # unresolvable identifiers remain
    py = text.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    try:
        return bool(eval(py, {"__builtins__": {}}, {})), True   # noqa: S307
    except Exception:
        return False, False


def _balanced_body(text, open_idx):
    """text[open_idx] == '{' -> (body, index_after_matching_brace)."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i + 1
    return None, len(text)


def parse_structs(blob):
    """{typedef_name: body} for every `typedef struct [tag] {...} name;`.

    Later definitions do not overwrite earlier ones: the first one found wins, so
    a stale copy under a checked-in build dir cannot shadow the real header (those
    are excluded by `collect`, but the tree has bitten us there before).
    """
    structs = {}
    for m in re.finditer(r"\btypedef\s+struct\b[^{;]*\{", blob):
        body, end = _balanced_body(blob, m.end() - 1)
        if body is None:
            continue
        tail = blob[end:end + 200]
        name = re.match(r"\s*([A-Za-z_]\w*)\s*;", tail)
        if name and name.group(1) not in structs:
            structs[name.group(1)] = body
    return structs


def split_members(body):
    """Top-level `;`-separated members, keeping nested braces intact."""
    members, depth, current = [], 0, []
    for char in body:
        if char in "{([":
            depth += 1
        elif char in "})]":
            depth -= 1
        if char == ";" and depth == 0:
            members.append("".join(current))
            current = []
        else:
            current.append(char)
    if "".join(current).strip():
        members.append("".join(current))
    return [" ".join(m.split()) for m in members if m.strip()]


def declarator_names(member):
    """Field names declared by one member, in order (`int a, *b[2]` -> a, b)."""
    names = []
    member = re.sub(r":\s*\d+\s*$", "", member)          # bitfield width
    for part in _split_top_level_commas(member):
        part = part.strip()
        fptr = re.search(r"\(\s*\*+\s*([A-Za-z_]\w*)\s*\)\s*\(", part)
        if fptr:                                          # int (*fn)(args)
            names.append(fptr.group(1))
            continue
        part = re.sub(r"\[[^\]]*\]", "", part)            # array extents
        tokens = re.findall(r"[A-Za-z_]\w*", part)
        if tokens:
            names.append(tokens[-1])
    return names


def _split_top_level_commas(text):
    parts, depth, current = [], 0, []
    for char in text:
        if char in "{([":
            depth += 1
        elif char in "})]":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


#: Type keywords, so a single-token member can be told from an anonymous
#: embedded typedef (`smrt_ptr_t;`), which contributes its OWN fields.
_TYPE_WORDS = {"void", "char", "short", "int", "long", "float", "double",
               "signed", "unsigned", "bool", "_Bool", "size_t", "ssize_t"}


def struct_fields(name, structs, seen=None):
    """Ordered field names of `name`, flattening anonymous members.

    Flattening is what lets the two spellings of the same ABI compare equal: C
    writes `smrt_ptr_t;` as an anonymous member (-fms-extensions) while the cdef
    writes out `bool alloc; size_t refs;`. Anonymous nested structs and unions are
    flattened for the same reason. A recursion guard keeps a self-referential
    typedef from looping.
    """
    seen = seen or set()
    if name in seen or name not in structs:
        return None
    seen = seen | {name}
    fields = []
    for member in split_members(structs[name]):
        if "{" in member:
            body, end = _balanced_body(member, member.index("{"))
            tail = member[end:].strip()
            if tail:                                      # named nested struct
                fields.extend(declarator_names(member[:member.index("{")] + tail)
                              or [tail.strip("*[] ")])
            else:                                         # anonymous: flatten
                nested = {"__anon__": body}
                nested.update(structs)
                inner = struct_fields("__anon__", nested, seen)
                fields.extend(inner or [])
            continue
        tokens = re.findall(r"[A-Za-z_]\w*", member)
        if (len(tokens) == 2 and tokens[0] in ("struct", "union")
                and "*" not in member):
            # `struct tm;` -- an anonymous embed of a struct declared elsewhere
            # (a system header we do not parse). Its fields sit at this position.
            fields.extend(EXTERNAL_ANON.get(tokens[1],
                                            struct_fields(tokens[1], structs, seen)
                                            or [tokens[1]]))
            continue
        if len(tokens) == 1 and tokens[0] not in _TYPE_WORDS and "*" not in member:
            # `smrt_ptr_t;` -- an anonymous embedded struct, so its fields are
            # this struct's fields at this position.
            inner = struct_fields(tokens[0], structs, seen)
            fields.extend(inner if inner is not None else [tokens[0]])
            continue
        fields.extend(declarator_names(member))
    return fields


def collect_files(patterns):
    """[(path, comment-stripped text)] for files matching patterns."""
    out = []
    for pat in patterns:
        for f in sorted(glob.glob(os.path.join(REPO, pat), recursive=True)):
            if "third_party" in f or f"{os.sep}build" in f:
                continue
            try:
                out.append((f, strip_comments(open(f, errors="replace").read())))
            except OSError:
                pass
    return out


def struct_sources(patterns=("src/c/**/*.h",)):
    """{struct_name: header_path} for every typedef'd struct with a body.

    Needed by --abi to know which headers a probe must include. First definition
    wins, matching parse_structs.
    """
    where = {}
    for path, text in collect_files(list(patterns)):
        resolved, _ = resolve_conditionals(text)
        for name in parse_structs(resolved):
            where.setdefault(name, path)
    return where


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


def audit_structs(cdef_blob, header_blob, pynative, quiet=False):
    """Compare the ordered field-name list of every struct the cdef mirrors.

    Returns (dangerous, latent, unmirrored, warnings). A struct counts as
    DANGEROUS when Python allocates or sizes it, because then a short mirror is a
    heap overflow rather than a misread.
    """
    resolved, unknown = resolve_conditionals(header_blob)
    c_structs = parse_structs(resolved)
    cdef_structs = parse_structs(cdef_blob)

    dangerous, latent, unmirrored, warnings = [], [], [], []
    if unknown:
        interesting = sorted(m for m in unknown
                             if m.startswith("AT_") or m.startswith("ZTA_"))
        if interesting:
            warnings.append(
                "conditionals treated as UNDEFINED: " + ", ".join(interesting) +
                " — if the native build defines one of these, add it to DEFINED")

    for name in sorted(cdef_structs):
        mine = struct_fields(name, cdef_structs)
        theirs = struct_fields(name, c_structs)
        if theirs is None:
            unmirrored.append(name)
            continue
        aliases = FIELD_ALIASES.get(name, {})
        if aliases:
            mine = [aliases.get(field, field) for field in mine]
        if mine == theirs:
            continue
        used = bool(re.search(r"""ffi\.(?:new|sizeof)\(\s*['"]\s*""" +
                              re.escape(name) + r"\b", pynative))
        row = (name, mine, theirs, used)
        (dangerous if used else latent).append(row)
    return dangerous, latent, unmirrored, warnings


#: Where the generated protobuf-c headers live, in preference order. The C
#: headers include them, so a probe cannot compile without one.
PB_C_DIRS = ("src/c/protobuf/autonomous_trust/core/protobuf",
             "src/c/protobuf",
             "src/c/build/protobuf/autonomous_trust/core/protobuf")


def _probe_includes(names, sources):
    """`#include "..."` lines for the headers declaring `names`."""
    root = os.path.join(REPO, "src/c/autonomous_trust")
    includes = []
    for name in names:
        path = sources.get(name)
        if not path:
            continue
        rel = os.path.relpath(path, root)
        if rel.startswith(".."):
            rel = os.path.relpath(path, os.path.join(REPO, "src/c"))
        line = f'#include "{rel}"'
        if line not in includes:
            includes.append(line)
    return includes


def measure_c(names, sources, fields=None, cc=None):
    """Compile a probe against the real headers; return ({name: sizeof},
    {(name, field): offsetof}, error_text).

    This is the check the name comparison cannot do -- a type-width or padding
    change keeps every field name. It needs a compiler and the generated
    protobuf-c headers, so it is opt-in (`--abi`) and reports plainly when the
    environment cannot support it rather than passing quietly.
    """
    import shutil
    import subprocess
    import tempfile

    cc = cc or os.environ.get("CC") or shutil.which("clang") or shutil.which("cc")
    if not cc:
        return None, None, "no C compiler found (set CC, or install clang)"
    pb_dir = next((d for d in PB_C_DIRS
                   if glob.glob(os.path.join(REPO, d, "**/*.pb-c.h"), recursive=True)),
                  None)
    if not pb_dir:
        return None, None, ("generated *.pb-c.h not found -- run "
                            "scripts/build-py.sh proto-only (or a C build) first")

    lines = ["#include <stdio.h>", "#include <stdbool.h>", "#include <stddef.h>"]
    lines += _probe_includes(names, sources)
    lines += ["int main(void) {"]
    for name in names:
        lines.append(f'    printf("S {name} %zu\\n", sizeof({name}));')
    for name, field in (fields or []):
        lines.append(f'    printf("O {name} {field} %zu\\n", '
                     f'(size_t)offsetof({name}, {field}));')
    lines += ["    return 0;", "}"]

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "probe.c")
        exe = os.path.join(tmp, "probe")
        open(src, "w").write("\n".join(lines) + "\n")
        cmd = [cc, "-fms-extensions", "-DAT_ZTA_ENABLED", "-w",
               "-I", os.path.join(REPO, "src/c"),
               "-I", os.path.join(REPO, "src/c/autonomous_trust"),
               "-I", os.path.join(REPO, pb_dir),
               "-I", os.path.join(REPO, "src/c/protobuf"),
               "-o", exe, src]
        # -fms-extensions is REQUIRED: AT embeds `smrt_ptr_t;` and `struct tm;`
        # anonymously, and without it the compiler silently drops those members --
        # which would make the probe disagree with the library it is measuring.
        built = subprocess.run(cmd, capture_output=True, text=True)
        if built.returncode != 0:
            return None, None, "probe did not compile:\n" + built.stderr.strip()[:2000]
        ran = subprocess.run([exe], capture_output=True, text=True)
        if ran.returncode != 0:
            return None, None, "probe did not run:\n" + ran.stderr.strip()[:500]

    sizes, offsets = {}, {}
    for line in ran.stdout.splitlines():
        parts = line.split()
        if parts[:1] == ["S"] and len(parts) == 3:
            sizes[parts[1]] = int(parts[2])
        elif parts[:1] == ["O"] and len(parts) == 4:
            offsets[(parts[1], parts[2])] = int(parts[3])
    return sizes, offsets, None


def audit_abi(cdef_text, pynative, quiet=False):
    """Measured comparison: ffi.sizeof/offsetof from the cdef vs the compiler.

    Returns (dangerous, latent, skipped_reason).
    """
    try:
        import cffi
    except ImportError:
        return [], [], "cffi not installed (it ships with the runtime env)"

    ffi = cffi.FFI()
    try:
        ffi.cdef(cdef_text)
    except Exception as err:                                  # noqa: BLE001
        return [], [], f"cdef does not parse: {err}"

    sources = struct_sources()
    cdef_structs = parse_structs(cdef_text)
    names = [n for n in sorted(cdef_structs) if n in sources]
    sizes, _, error = measure_c(names, sources)
    if error:
        return [], [], error

    dangerous, latent = [], []
    for name in names:
        try:
            mine = ffi.sizeof(name)
        except Exception:                                     # noqa: BLE001
            continue                  # opaque on the cdef side; nothing to size
        theirs = sizes.get(name)
        if theirs is None or mine == theirs:
            continue
        used = bool(re.search(r"""ffi\.(?:new|sizeof)\(\s*['"]\s*""" +
                              re.escape(name) + r"\b", pynative))
        detail = _localize(ffi, name, cdef_structs, sources)
        (dangerous if used else latent).append((name, mine, theirs, detail))
    return dangerous, latent, None


def _localize(ffi, name, cdef_structs, sources):
    """First field whose offset disagrees, so a size diff points somewhere."""
    fields = struct_fields(name, cdef_structs) or []
    aliases = FIELD_ALIASES.get(name, {})
    probe_fields = [(name, aliases.get(f, f)) for f in fields]
    _, offsets, error = measure_c([name], sources, fields=probe_fields)
    if error or not offsets:
        return ""
    for field in fields:
        c_field = aliases.get(field, field)
        try:
            mine = ffi.offsetof(name, field)
        except Exception:                                     # noqa: BLE001
            continue
        theirs = offsets.get((name, c_field))
        if theirs is not None and mine != theirs:
            return f"first bad offset at .{field}: cdef {mine} vs C {theirs}"
    # Every field the cdef knows about sits where C puts it, so the difference is
    # past the end of the mirror: either fields C has and the cdef does not (the
    # common case, and the struct check names them), or trailing padding.
    c_fields = struct_fields(name, parse_structs(resolve_conditionals(
        "\n".join(text for _, text in collect_files(["src/c/**/*.h"])))[0])) or []
    tail = [f for f in c_fields if f not in fields]
    if tail:
        return ("every offset the cdef knows agrees, so the mirror is SHORT at "
                "the tail: C also has " + ", ".join(tail))
    return "sizes differ but every probed offset agrees — trailing padding"


def describe_field_drift(mine, theirs):
    """One line naming what actually differs, so the reader can act on it."""
    missing = [f for f in theirs if f not in mine]
    extra = [f for f in mine if f not in theirs]
    notes = []
    if missing:
        notes.append("cdef MISSING %s" % ", ".join(missing))
    if extra:
        notes.append("cdef has extra %s" % ", ".join(extra))
    if not notes:
        notes.append("same fields, different ORDER: cdef %s vs C %s"
                     % (mine, theirs))
    return "; ".join(notes)


def main():
    ap = argparse.ArgumentParser(description="Audit native FFI cdef drift "
                                            "(function arity + struct fields).")
    ap.add_argument("--strict", action="store_true",
                    help="also fail on LATENT (unused-from-Python) drift")
    ap.add_argument("--quiet", action="store_true",
                    help="print only drift lines")
    ap.add_argument("--only", choices=("arity", "structs", "abi"), default=None,
                    help="run just one of the checks")
    ap.add_argument("--abi", action="store_true",
                    help="also MEASURE sizeof/offsetof by compiling a probe "
                         "against the real headers (needs a compiler, cffi and "
                         "the generated *.pb-c.h); catches type-width and "
                         "padding drift a name comparison cannot see")
    args = ap.parse_args()

    do_arity = args.only in (None, "arity")
    do_structs = args.only in (None, "structs")
    do_abi = args.abi or args.only == "abi"
    if args.only == "abi":
        do_arity = do_structs = False

    abi_fail = False
    if do_abi:
        a_dangerous, a_latent, skipped = audit_abi(cdef_blob(), collect_py(),
                                                   args.quiet)
        if skipped:
            print(f"  ⚠ ABI measurement SKIPPED: {skipped}")
        else:
            if not args.quiet:
                print(f"ABI measured (cdef vs compiler)  |  "
                      f"DANGEROUS: {len(a_dangerous)}  LATENT: {len(a_latent)}\n")
            for label, rows in (("DANGEROUS", a_dangerous), ("LATENT", a_latent)):
                for name, mine, theirs, detail in rows:
                    mark = "✗" if label == "DANGEROUS" else "!"
                    extra = f" — {detail}" if detail else ""
                    print(f"  {mark} {name}: cdef sizeof={mine}, C={theirs}{extra}")
            if not a_dangerous and not a_latent and not args.quiet:
                print("  (every mirrored struct measures equal to C)")
            abi_fail = bool(a_dangerous) or (args.strict and bool(a_latent))
        if args.only == "abi":
            if not args.quiet:
                print("\n" + ("FAIL: ABI drift detected." if abi_fail
                              else "OK: no blocking ABI drift."))
            return 1 if abi_fail else 0
        if not args.quiet:
            print()

    cdef = parse_cdef()
    headers = collect(["src/c/**/*.h"])
    sources = collect(["src/c/**/*.c"])
    pynative = collect_py()

    struct_fail = False
    if do_structs:
        s_dangerous, s_latent, s_unmirrored, s_warnings = audit_structs(
            cdef_blob(), headers, pynative, args.quiet)
        if not args.quiet:
            print(f"cdef structs mirrored: "
                  f"{len(parse_structs(cdef_blob()))}  |  "
                  f"DANGEROUS: {len(s_dangerous)}  LATENT: {len(s_latent)}  |  "
                  f"no C struct: {len(s_unmirrored)}\n")
        for warning in s_warnings:
            print(f"  ⚠ {warning}")
        if s_dangerous:
            print("DANGEROUS struct drift (Python allocates/sizes it -> "
                  "heap overflow on every write):")
            for name, mine, theirs, _ in s_dangerous:
                print(f"  ✗ {name}: {describe_field_drift(mine, theirs)}")
        if s_latent or not args.quiet:
            print("\nLATENT struct drift (cdef-only; a MISREAD, not an overflow):")
            for name, mine, theirs, _ in s_latent:
                print(f"  ! {name}: {describe_field_drift(mine, theirs)}")
            if not s_latent:
                print("  (none)")
        if s_unmirrored and not args.quiet:
            print("\nNo C struct found (cdef-local shim / opaque — review):")
            for name in s_unmirrored:
                print(f"  - {name}")
        struct_fail = bool(s_dangerous) or (args.strict and bool(s_latent))
        if not do_arity:
            struct_fail = struct_fail or abi_fail
            if not args.quiet:
                print("\n" + ("FAIL: struct drift detected." if struct_fail
                              else "OK: no blocking struct drift."))
            return 1 if struct_fail else 0
        if not args.quiet:
            print()

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

    fail = (bool(dangerous) or (args.strict and bool(latent))
            or struct_fail or abi_fail)
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
