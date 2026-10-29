# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
import sys
import os

import pytest

# Add sibling package source dirs to sys.path for monorepo development
_repo_src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
for _pkg in ('autonomous-trust', 'autonomous-trust-oracle', 'autonomous-trust-services', 'autonomous-trust-inspector', 'autonomous-trust-evaluation'):
    _pkg_dir = os.path.join(_repo_src, _pkg)
    if _pkg_dir not in sys.path and os.path.isdir(_pkg_dir):
        sys.path.insert(0, _pkg_dir)

# Add repo root for examples/ imports (e.g. examples.appalachia)
_repo_root = os.path.abspath(os.path.join(_repo_src, '..'))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)


def pytest_addoption(parser):
    parser.addoption(
        '--backend', default='python', choices=('native', 'python'),
        help='AutonomousTrust backend: python (default) or native',
    )


def pytest_configure(config):
    """Set AUTONOMOUS_TRUST_BACKEND early, before test modules are collected."""
    backend = config.getoption('--backend', default='python')
    os.environ['AUTONOMOUS_TRUST_BACKEND'] = backend


def pytest_collection_finish(session):
    """Drop a sys.path entry left behind by a failed ``import cv2``.

    OpenCV's bootstrap puts its own package directory on sys.path and leaves it
    there when the import fails part-way (e.g. libxcb.so.1 missing). That
    directory holds a ``typing`` package, so every later spawn/forkserver child
    inherits the path, imports cv2/typing in place of the stdlib and dies on
    startup (test_appalachian_inprocess). Test modules that import the video
    code under try/except (test_video, test_noise) trigger it at collection.
    """
    if 'cv2' in sys.modules:
        return  # cv2 loaded; its path entry is legitimate
    sys.path[:] = [p for p in sys.path
                   if not (os.path.basename(p) == 'cv2'
                           and os.path.isfile(os.path.join(p, '__init__.py')))]


@pytest.fixture(scope='session')
def backend(request):
    """Expose the selected backend name for tests that need it."""
    return request.config.getoption('--backend')
