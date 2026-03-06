import sys
import os

# Add sibling package source dirs to sys.path for monorepo development
_repo_src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
for _pkg in ('autonomous-trust',):
    _pkg_dir = os.path.join(_repo_src, _pkg)
    if _pkg_dir not in sys.path and os.path.isdir(_pkg_dir):
        sys.path.insert(0, _pkg_dir)
