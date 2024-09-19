#!/usr/bin/env python3
import argparse
import os
import re

from git import Repo


base_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
copy_file = os.path.join(base_dir, 'COPYING')


def needs_copyright(file, show_skipped, show_exists):
    try:
        with open(file, 'r') as f:
            content = f.read()
            if len(content) == 0:
                if show_skipped:
                    print('Empty %s' % file)
                return False
            if "Copyright" in content:
                if show_exists:
                    print('Copyright present %s' % file)
                return False
            return True
    except UnicodeDecodeError:
        if show_skipped:
            print('Binary %s' % file)
        return False


py_marker = '# ******************\n'


def py_copy():
    lines = []
    with open(copy_file, 'r') as f:
        first = True
        for line in f.readlines():
            if first:
                first = False
                lines.append(py_marker)
            line = '#' + line
            lines.append(line)
        lines.append(py_marker + '\n')
    return lines


tex_marker = '% ******************\n'


def tex_copy():
    lines = []
    with open(copy_file, 'r') as f:
        first = True
        for line in f.readlines():
            if first:
                first = False
                lines.append(tex_marker)
            line = '%' + line
            lines.append(line)
        lines.append(tex_marker + '\n')
    return lines


c_mark_begin = '/********************\n'
c_mark_end = ' *******************/\n'


def c_copy():
    lines = []
    with open(copy_file, 'r') as f:
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


def add_copy_to_source(path, sources, dry_run, verbose, show_skipped, show_exists):
    if path not in sources:
        return
    py_ext = ['.py']
    tex_ext = ['.tex', '.sty', '.bib']
    c_ext = ['.c', '.cpp', '.h', '.h.in']
    proto_ext = ['.proto']
    ext_list = py_ext + tex_ext + c_ext + proto_ext
    if '.' not in path:
        if show_skipped:
            print('No ext %s' % path)
        return
    ext = path[path.rindex('.'):]
    if ext in ext_list and not needs_copyright(path, show_skipped, show_exists):
        return

    if ext in py_ext:
        lines = get_lines(path, dry_run, verbose)
        if lines is None:
            return
        idx = 0
        if lines[0].startswith('#!'):
            idx += 1
        put_lines(lines, path, py_marker, idx, py_copy())

    elif ext in tex_ext:
        lines = get_lines(path, dry_run, verbose)
        if lines is None:
            return
        put_lines(lines, path, tex_marker, 0, tex_copy())

    elif ext in c_ext:
        lines = get_lines(path, dry_run, verbose)
        if lines is None:
            return
        idx = 0
        put_lines(lines, path, c_mark_end, idx, c_copy())

    elif ext in proto_ext:
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


def add_copy_to_sources(directory, sources, excludes, dry_run, verbose, show_skipped, show_exists):
    for root, dirs, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            exclude = False
            for ex in excludes:
                if re.match(ex, path):
                    exclude = True
            if exclude:
                continue
            add_copy_to_source(path, sources, dry_run, verbose, show_skipped, show_exists)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='*', default=[])
    parser.add_argument('--excludes', default=[], action='append')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--show-skipped', action='store_true')
    parser.add_argument('--show-existing', action='store_true')
    args = parser.parse_args()

    repo = Repo(base_dir)
    git_files = repo.commit().tree.traverse()
    git_paths = [entry.abspath for entry in git_files]

    if len(args.files) == 0:
        add_copy_to_sources(base_dir, git_paths, args.excludes, dry_run=args.dry_run, verbose=args.verbose,
                            show_skipped=args.show_skipped, show_exists=args.show_existing)
    else:
        for src in args.files:
            filepath = os.path.join(base_dir, src)
            add_copy_to_source(filepath, git_paths, dry_run=args.dry_run, verbose=args.verbose,
                               show_skipped=args.show_skipped, show_exists=args.show_existing)
