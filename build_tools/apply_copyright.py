#!/usr/bin/env python3

import os
import sys

from git import Repo


py_marker = '# ******************\n'


def py_copy():
    path = os.path.join(this_dir, 'COPYING')
    lines = []
    with open(path, 'r') as f:
        first = True
        for line in f.readlines():
            if first:
                first = False
                lines.append(py_marker)
            line = '#' + line
            lines.append(line)
        lines.append(py_marker + '\n')
    return lines


c_mark_begin = '/********************\n'
c_mark_end = ' *******************/\n'


def c_copy():
    path = os.path.join(this_dir, 'COPYING')
    lines = []
    with open(path, 'r') as f:
        first = True
        for line in f.readlines():
            if first:
                first = False
                lines.append(c_mark_begin)
            line = ' *' + line
            lines.append(line)
        lines.append(c_mark_end + '\n')
    return lines


def flatten(lst):
    return [x for xs in lst for x in xs]


def get_lines(path, dry_run, verbose):
    with open(path, 'r') as f:
        lines = f.readlines()
    if len(lines) == 0:
        return None
    if dry_run:
        print('Convert %s' % path)
        return None
    if verbose:
        print('Convert %s' % path)
    return lines


def put_lines(lines, path, marker, idx, copytext):
    with open(path, 'w') as f:
        if idx > 0:
            f.writelines(lines[:idx])
        f.writelines(copytext)
        contents = ''.join(lines)
        if marker in contents:
            idx = len(lines) - 1
            while idx > 0 and not lines[idx].endswith(marker):
                idx -= 1
            idx += 1
        while idx < len(lines) and lines[idx].strip() == '':
            idx += 1
        f.writelines(lines[idx:])


def add_copy_to_source(path, sources, dry_run, verbose, show_skipped):
    if path not in sources:
        return

    if path.endswith(".py"):
        lines = get_lines(path, dry_run, verbose)
        if lines is None:
            return
        idx = 0
        if lines[0].startswith('#!'):
            idx += 1
        put_lines(lines, path, py_marker, idx, py_copy())

    elif path.endswith('.c') or path.endswith('.cpp') or path.endswith('.h') or path.endswith('.h.in'):
        lines = get_lines(path, dry_run, verbose)
        if lines is None:
            return
        idx = 0
        put_lines(lines, path, c_mark_end, idx, c_copy())

    elif path.endswith('.proto'):
        lines = get_lines(path, dry_run, verbose)
        if lines is None:
            return
        idx = 0
        if lines[0].startswith('syntax'):
            idx += 1
        put_lines(lines, path, c_mark_end, idx, c_copy())

    # FIXME .sh, .js, .css, .tex
    elif show_skipped:
        print('Skipped %s' % path)


def add_copy_to_sources(base_dir, sources, dry_run, verbose, show_skipped):
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            path = os.path.join(root, file)
            add_copy_to_source(path, sources, dry_run, verbose, show_skipped)


if __name__ == "__main__":
    this_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

    args = this_dir, True, False, False
    # FIXME argparse instead

    repo = Repo(args[0])
    git_files = repo.commit().tree.traverse()
    git_paths = [entry.abspath for entry in git_files]

    if len(sys.argv) < 2:
        add_copy_to_sources(this_dir, git_paths, dry_run=args[1], verbose=args[2], show_skipped=args[3])
    else:
        for s in sys.argv[1:]:
            filepath = os.path.join(this_dir, s)
            add_copy_to_source(filepath, git_paths, dry_run=args[1], verbose=args[2], show_skipped=True)
