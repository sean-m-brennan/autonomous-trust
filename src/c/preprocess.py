#!/usr/bin/env -S python3
# ******************
#  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

import os
import re
import sys
from typing import List, Tuple


class MalformedError(RuntimeError):
    pass


# Matches // line-comments and /* block-comments. Comments are stripped
# before scanning for the DECLARE_* delimiter so doc references like
# ``@ref DECLARE_CONFIGURATION`` don't get picked up as macro call sites
# (see configuration/generate.h: the @ref token is immediately followed
# by an unrelated function declaration whose parens then get consumed).
_C_COMMENT_RE = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")


def _strip_c_comments(text: str) -> str:
    return _C_COMMENT_RE.sub("", text)


def find_next_matching_parens(content, index) -> Tuple[int, int]:
    o_paren = content.find('(', index)
    if o_paren < 0:
        raise MalformedError
    c_paren = content.find(')', o_paren)
    if c_paren < 0:
        raise MalformedError
    while True:
        num_open = content[o_paren + 1:c_paren].count('(')
        num_close = content[o_paren + 1:c_paren].count(')')
        if num_open == num_close:
            break
        c_paren = content.find(')', c_paren + 1)
        if c_paren < 0:
            raise MalformedError
    return o_paren, c_paren


def preprocess(target_filepath: str, output_file: str, directory: str, rel_path: str = None, exclude_dirs: list = None):
    prefix = 'DECLARE_'
    if rel_path is None:
        rel_path = ''
    if exclude_dirs is None:                                                                                
        exclude_dirs = []  
    ignore_list = []

    definition = ''
    with open(target_filepath, 'r') as f:
        lines = f.readlines()
        def_lines = []
        for idx, line in enumerate(list(lines)):
            if line.startswith('#include') and line.count('"') == 2:
                i = line.find('"')
                j = line.find('"', i + 1)
                ignore_list.append(line[i + 1:j])
            elif line.startswith('#define') and prefix in line:
                i = line.find(prefix)
                j = line.find('(', i + 1)
                delimiter = line[i:j]
                target_type = line[i + 8:j]
                jdx = idx
                while line.strip().endswith('\\'):
                    def_lines.append(line)
                    jdx += 1
                    line = lines[jdx]
                def_lines.append(line)
                # note cannot handle multiple definitions
        definition = ''.join(def_lines).replace('\\', '')
        definition = ' '.join(definition.split())
    index = definition.find(delimiter)
    o_paren = definition.find('(', index)
    c_paren = definition.find(')', o_paren)
    if o_paren < 0 or c_paren < 0:
        print("No definition for %s provided in %s" % (delimiter, target_filepath))
        sys.exit(-1)
    args = [a.strip() for a in definition[o_paren + 1:c_paren].split(',')]
    definition = definition[c_paren + 1:]
    while 'QUOTE' in definition:
        index = definition.find('QUOTE')
        o_paren, c_paren = find_next_matching_parens(definition, index)
        definition = definition[:c_paren] + '"' + definition[c_paren + 1:]  # must come first
        definition = definition.replace('QUOTE(', '"', 1)

    declarations: List[str] = []
    includes: List[str] = []
    for root, dirs, files in os.walk(os.path.abspath(directory)):
        # Prune excluded subdirectories in-place so os.walk skips them entirely.
        # Also skip CMake build trees: they hold *copies* of the source headers,
        # so descending into build/, build-asan/, etc. would count every
        # DECLARE_* site once per build dir present, inflating the generated
        # table past its fixed size (e.g. error_table_size > ERROR_TABLE_MAX),
        # which overruns the array at runtime. A dir with a CMakeCache.txt is a
        # build directory, never source.
        dirs[:] = [d for d in dirs
                   if d not in exclude_dirs
                   and not os.path.exists(os.path.join(root, d, 'CMakeCache.txt'))]
        for filename in files:
            ignore = False
            for path in ignore_list:
                if path in os.path.join(root, filename):
                    ignore = True
            if (filename.endswith('.c') or filename.endswith('.h')) and not ignore:
                with open(os.path.join(root, filename), 'r') as f:
                    contents = _strip_c_comments(f.read())
                    if delimiter in contents:
                        index = contents.find(delimiter)
                        while index > -1:
                            try:
                                o_paren, c_paren = find_next_matching_parens(contents, index)
                            except MalformedError:
                                break
                            decl_args = contents[o_paren + 1:c_paren]
                            declarations.append(decl_args)
                            index = contents.find(delimiter, index + 1)
                        incl_path = os.path.relpath(os.path.join(root, filename),
                                                    os.path.join(os.path.abspath(directory), rel_path))
                        if incl_path.endswith('.c'):
                            incl_path = incl_path[:-2] + '_priv.h'
                            if not os.path.basename(incl_path) in files:
                                incl_path = incl_path[:-7] + '.h'
                        includes.append('#include "' + incl_path + '"')

    substitutions = []
    for decl in declarations:
        decl_tokens = [a.strip() for a in decl.split(',')]
        if len(args) != len(decl_tokens):
            print("Mismatched declaration/definition: %s vs %s" % (decl, ', '.join(args)))
            sys.exit(-1)
        new_def = str(definition)
        for idx, arg in enumerate(args):
            new_def = new_def.replace(arg, decl_tokens[idx])
        substitutions.append(new_def)

    # Safety guard: a fixed-size table must not overflow its declared array
    # bound. Tables declared `<type> <name>[CAP] = { LIST__... }` truncate the
    # initializer silently if there are more than CAP entries, and a
    # `for (i < *_table_size)` lookup then reads past the array end at runtime
    # (an over-count once crashed every error-logging test with SIGSEGV).
    # Catch it here as a clear build error. Unsized arrays (`[]`) auto-grow and
    # are skipped.
    with open(target_filepath, 'r') as _tf:
        _tmpl = _strip_c_comments(_tf.read())
    _arr = re.search(r'\[\s*([A-Za-z_][A-Za-z0-9_]*|\d+)?\s*\]\s*=\s*\{(.*?)\}\s*;',
                     _tmpl, re.DOTALL)
    if _arr is not None and _arr.group(1):
        _dim = _arr.group(1)
        if _dim.isdigit():
            _cap = int(_dim)
        else:
            _m = re.search(r'#define\s+' + re.escape(_dim) + r'\s+(\d+)', _tmpl)
            _cap = int(_m.group(1)) if _m else None
        if _cap is not None:
            # Literal sentinel/initializer rows already in the template body
            # (e.g. capability_table's trailing `{ .name = "" }`) occupy slots
            # too, so count them alongside the generated entries.
            _sentinels = len(re.findall(r'\{\s*\.', _arr.group(2)))
            _need = len(substitutions) + _sentinels
            if _need > _cap:
                print("ERROR: %s table needs %d slots (%d entries + %d sentinel) "
                      "but %s is %d. Raise the cap or remove entries (%s)."
                      % (target_type, _need, len(substitutions), _sentinels,
                         _dim, _cap, target_filepath), file=sys.stderr)
                sys.exit(1)

    with open(output_file, 'w') as o_file:
        with open(target_filepath, 'r') as i_file:
            in_includes = False
            post_list = False
            for line in i_file.readlines():
                if line.startswith('#include'):
                    in_includes = True
                elif in_includes:
                    in_includes = False
                    o_file.write('\n'.join(includes) + '\n')
                if 'LIST__' + delimiter in line:
                    o_file.write('\n'.join(substitutions) + '\n')
                    index = line.find(delimiter)
                    if index > 0:
                        o_file.write(line[index + len(delimiter):])
                    post_list = True
                elif line not in def_lines:
                    if post_list:
                        if ';' in line:
                            o_file.write(line)
                        o_file.write('size_t %s_table_size = %d;\n' %
                                     (target_type.lower(), len(substitutions)))
                        if ';' not in line:
                            o_file.write(line)
                        post_list = False
                    else:
                        o_file.write(line)


if __name__ == '__main__':
      import argparse                                                                                         
      ap = argparse.ArgumentParser()
      ap.add_argument('target')                                                                               
      ap.add_argument('output')                                                                               
      ap.add_argument('srcdir')
      ap.add_argument('rel_path', nargs='?', default=None)                                                    
      ap.add_argument('--exclude', action='append', default=[],                                               
                      help='Subdirectory name to skip (may repeat)')
      args = ap.parse_args()                                                                                  
      preprocess(args.target, args.output, args.srcdir, args.rel_path,
                 exclude_dirs=args.exclude)                                                                   
 