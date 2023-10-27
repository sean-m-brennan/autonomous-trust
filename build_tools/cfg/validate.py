import os
import re
from typing import Optional

from ..config import packages


SUBSTITUTES = {'opencv-python': 'py-opencv',}


def split_spec(spec: str) -> tuple[str, Optional[str]]:
    tpl = re.split('>=|<=|==', spec)
    if len(tpl) < 2:
        return tpl[0].strip(), None
    return tuple(map(str.strip, tpl))  # noqa


def check_version(pkg, ver, content):
    lines = content.split('\n')
    for line in lines:
        cmp = split_spec(line.strip())
        if pkg in line.lower() and ver not in line and pkg == cmp[0].lower():
            print('WARNING: Package %s wrong version: %s vs %s' % (pkg, ver, cmp[1]))


def validate_packages():
    all_reqs = []
    for pkg_dir in packages.values():
        with open(os.path.join(pkg_dir, 'requirements.txt'), 'r') as rf:
            reqs = list(map(str.strip, rf.read().split('\n')))
        for r in list(reqs):
            if r == '':
                reqs.remove(r)
            if r.startswith('autonomous-trust'):
                reqs.remove(r)
        all_reqs += reqs
        toml_file = os.path.join(pkg_dir, 'pyproject.toml')
        with open(toml_file, 'r') as t:
            toml = t.read()
        meta_file = os.path.join(pkg_dir, 'meta.yaml')
        with open(meta_file, 'r') as m:
            meta = m.read()
        for pkg, ver in list(map(split_spec, reqs)):
            if pkg not in toml.lower():
                print('WARNING: Package %s missing in %s' % (pkg, toml_file))
            elif ver is not None:
                check_version(pkg, ver, toml)

            if pkg in SUBSTITUTES:
                pkg = SUBSTITUTES[pkg]
            if pkg not in meta.lower():
                print('WARNING: Package %s missing in %s' % (pkg, meta_file))
            elif ver is not None:
                check_version(pkg, ver, meta)

    this_dir = os.path.dirname(__file__)
    environ_file = os.path.join(this_dir, 'environment.yaml')
    with open(environ_file, 'r') as e:
        environ = e.read()
    for pkg, _ in list(map(split_spec, all_reqs)):
        if pkg in SUBSTITUTES:
            pkg = SUBSTITUTES[pkg]
        if pkg not in environ:
            print('WARNING: Package %s missing in %s' % (pkg, environ_file))


if __name__ == '__main__':
    validate_packages()
