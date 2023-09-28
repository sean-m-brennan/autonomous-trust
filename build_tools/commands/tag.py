import os
import re
import subprocess

from ..config import base_dir


class TagLevel(object):
    major = 'major'
    minor = 'minor'
    patch = 'patch'


def git_tag(incr: TagLevel):
    import git
    src_dirs = [os.path.join(base_dir, 'src', 'autonomous-trust'),
                os.path.join(base_dir, 'src', 'autonomous-trust-inspector')]
    repo = git.Repo()
    assert not repo.bare

    version = repo.git.describe()
    major, minor, patch = version[1:].split('.', 2)
    major, minor = int(major), int(minor)
    patch, extra = patch.split('-', 1)
    patch = int(patch)
    if incr == TagLevel.major:
        major += 1
        minor = 0
        patch = 0
    elif incr == TagLevel.minor:
        minor += 1
        patch = 0
    elif incr == TagLevel.patch:
        patch += 1

    next_version = '%d.%d.%d' % (major, minor, patch)
    print("Tagging v%s.   Commit? (y/N) " % next_version, end='')
    affirm = input()
    if not affirm.lower().startswith('y'):
        print("  Cancelled")

    for src in src_dirs:
        path = os.path.join(src, 'pyproject.toml')
        with open(path, 'r') as f:
            toml = f.read()
        alt_toml = re.sub('version.*=.*\".*\"', 'version = \"$next_version\"', toml)
        with open(path, 'w') as f:
            f.write(alt_toml)

    msg = 'Release v%s' % next_version
    subprocess.run(['git', 'commit', '-a', '-m', msg])
    subprocess.run(['git', 'tag', '-a', 'v%s' % next_version, '-m', msg])
