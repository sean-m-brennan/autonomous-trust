import sys
import os

import pytest

# Add sibling package source dirs to sys.path for monorepo development
_repo_src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
for _pkg in ('autonomous-trust', 'autonomous-trust-services', 'autonomous-trust-inspector'):
    _pkg_dir = os.path.join(_repo_src, _pkg)
    if _pkg_dir not in sys.path and os.path.isdir(_pkg_dir):
        sys.path.insert(0, _pkg_dir)


def pytest_addoption(parser):
    parser.addoption(
        '--backend', default='python', choices=('native', 'python'),
        help='AutonomousTrust backend: python (default) or native',
    )


def pytest_configure(config):
    """Set AUTONOMOUS_TRUST_BACKEND early, before test modules are collected."""
    backend = config.getoption('--backend', default='python')
    os.environ['AUTONOMOUS_TRUST_BACKEND'] = backend


@pytest.fixture(scope='session')
def backend(request):
    """Expose the selected backend name for tests that need it."""
    return request.config.getoption('--backend')
