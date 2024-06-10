#!/usr/bin/env -S python3
import os
import sys


class MalformedError(RuntimeError):
    pass


def find_next_matching_parens(content, index) -> tuple[int, int]:
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


def preprocess(target_filepath: str, output_file: str, directory: str, rel_path: str = None):
    prefix = 'DECLARE_'
    if rel_path is None:
        rel_path = ''
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

    declarations: list[str] = []
    includes: list[str] = []
    for root, dirs, files in os.walk(os.path.abspath(directory)):
        for filename in files:
            ignore = False
            for path in ignore_list:
                if path in os.path.join(root, filename):
                    ignore = True
            if (filename.endswith('.c') or filename.endswith('.h')) and not ignore:
                with open(os.path.join(root, filename), 'r') as f:
                    contents = f.read()
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
    # TODO argparse
    preprocess(*sys.argv[1:])
