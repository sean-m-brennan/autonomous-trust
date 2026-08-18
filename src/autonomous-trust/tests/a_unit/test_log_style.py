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
"""One logging convention, enforced (the S13 logging sweep).

The convention: build a log message with **lazy %-args** --
``logger.info('peer %s joined', uuid)`` -- never by interpolating first
(``'peer %s joined' % uuid``, an f-string, or concatenation).

This is not only house style. Interpolating first does the work even when the
level is switched off, and -- the part that bites -- a formatting error then
raises *out of the logging call into the caller*, so a bad diagnostic takes
down the code path it was trying to describe. With lazy args, `logging` owns
the formatting and handles its own errors.

The entry has to be a TEST rather than a note in a style guide because the
project has no linter and no lint step in CI: the gap it records
(211 eager call sites against 147 lazy, four different ways of building a
message) is precisely what happens to a convention nobody can check. A sweep
without a guard is a sweep you repeat in six months.

Scope is the shipped packages' own source. Tests are excluded deliberately: a
test asserting on log output sometimes wants the eager form to build an
expected string, and that is not a diagnostic anyone reads.
"""
import ast
import os
import re

import pytest

LEVELS = {'debug', 'info', 'warning', 'warn', 'error', 'critical', 'exception'}

#: Package source roots, relative to the repo. Each is a shipped runtime, so
#: each has operators reading its logs.
PACKAGES = (
    'autonomous-trust/autonomous_trust',
    'autonomous-trust-services/autonomous_trust',
    'autonomous-trust-inspector/autonomous_trust',
    'autonomous-trust-evaluation/autonomous_trust',
    'autonomous-trust-simulator/autonomous_trust',
)

SKIP_DIRS = {'__pycache__', '.venv', '.tox', 'site-packages', 'node_modules',
             'build', 'dist', 'third_party', 'protobuf'}


def _src_root():
    """The `src/` directory holding the packages, or None when this checkout
    does not have it (an installed-wheel run)."""
    here = os.path.dirname(os.path.abspath(__file__))
    # tests/a_unit -> tests -> autonomous-trust -> src
    root = os.path.abspath(os.path.join(here, '..', '..', '..'))
    return root if os.path.isdir(os.path.join(root, PACKAGES[0])) else None


def _is_logger_call(func):
    if not isinstance(func, ast.Attribute) or func.attr not in LEVELS:
        return False
    value = func.value
    name = None
    if isinstance(value, ast.Name):
        name = value.id
    elif isinstance(value, ast.Attribute):
        name = value.attr
    return bool(name) and ('logger' in name.lower() or name.lower() == 'log')


def _offenders_in(path):
    """(lineno, kind) for every eagerly-interpolated logging call in `path`."""
    with open(path, encoding='utf-8') as fd:
        src = fd.read()
    try:
        tree = ast.parse(src)
    except SyntaxError:                       # not ours to police
        return []
    found = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_logger_call(node.func)):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.JoinedStr):
            found.append((node.lineno, 'f-string'))
        elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Mod):
            found.append((node.lineno, "'...' % arg"))
        elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
            found.append((node.lineno, 'concatenation'))
        elif (isinstance(first, ast.Call)
              and isinstance(first.func, ast.Attribute)
              and first.func.attr == 'format'):
            found.append((node.lineno, '.format()'))
    return found


#: A %-conversion, so a format string's placeholders can be counted.
_SPEC = re.compile(r'%(?:\((?P<key>[^)]*)\))?[-+ #0]*[0-9*]*'
                   r'(?:\.[0-9*]+)?[hlL]?(?P<conv>[diouxXeEfFgGcrsa%])')


def _placeholders(fmt):
    """(count, is_mapping_form) for a %-format string. `%%` is a literal."""
    count, mapping = 0, False
    for m in _SPEC.finditer(fmt):
        if m.group('conv') == '%':
            continue
        if m.group('key') is not None:
            mapping = True
        count += 1
    return count, mapping


def _arity_mismatches_in(path):
    """Lazy logging calls whose placeholder count != the args supplied.

    Its own defect class, and a nastier one than the style it rides in with:
    `logging` renders `msg % args` at emit time, so a mismatch raises INSIDE
    logging, and logging swallows it -- the line is dropped and only a
    "--- Logging error ---" traceback reaches stderr. The diagnostic you were
    relying on is simply gone.

    Converting this project to lazy args produced three of these in one pass:
    `'%s:%s' % addr` SPLATS a tuple, while `('%s:%s', addr)` passes it as one
    argument, so `sock.getsockname()` stopped printing. It also surfaced a
    pre-existing one (`'Skipping ', name`, no placeholder at all) that had been
    dropping its message for as long as it had existed.
    """
    with open(path, encoding='utf-8') as fd:
        src = fd.read()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    found = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_logger_call(node.func)
                and node.args):
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant)
                and isinstance(first.value, str)):
            continue
        if any(isinstance(a, ast.Starred) for a in node.args):
            continue          # *splat: the arity is not knowable statically
        if node.keywords:
            continue          # exc_info=/stacklevel= etc. are not message args
        count, mapping = _placeholders(first.value)
        if mapping:
            continue          # %(name)s form takes a single mapping
        supplied = len(node.args) - 1
        if count != supplied:
            found.append((node.lineno, count, supplied, first.value[:60]))
    return found


def _walk(root):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(files):
            if name.endswith('.py'):
                yield os.path.join(dirpath, name)


@pytest.mark.parametrize('package', PACKAGES)
def test_logging_calls_use_lazy_args(package):
    root = _src_root()
    if root is None:
        pytest.skip('package sources not present in this checkout')
    base = os.path.join(root, package)
    if not os.path.isdir(base):
        pytest.skip('%s not present' % package)
    bad = []
    for path in _walk(base):
        for lineno, kind in _offenders_in(path):
            bad.append('%s:%d  (%s)' % (os.path.relpath(path, root), lineno,
                                        kind))
    assert not bad, (
        '%d logging call(s) build the message before handing it to logging.\n'
        'Use lazy args -- logger.info("x %%s", y) -- so nothing is formatted '
        'when the level is off and a bad format cannot raise into the '
        'caller:\n  %s' % (len(bad), '\n  '.join(bad)))


@pytest.mark.parametrize('package', PACKAGES)
def test_logging_placeholders_match_their_arguments(package):
    root = _src_root()
    if root is None:
        pytest.skip('package sources not present in this checkout')
    base = os.path.join(root, package)
    if not os.path.isdir(base):
        pytest.skip('%s not present' % package)
    bad = []
    for path in _walk(base):
        for lineno, want, got, msg in _arity_mismatches_in(path):
            bad.append('%s:%d  %r wants %d arg(s), got %d'
                       % (os.path.relpath(path, root), lineno, msg, want, got))
    assert not bad, (
        '%d logging call(s) would raise inside logging and lose the message '
        'entirely:\n  %s' % (len(bad), '\n  '.join(bad)))


def test_the_arity_check_can_actually_fail():
    """Including the tuple case, which is the one that bit."""
    import tempfile
    sample = (
        'import logging\n'
        'logger = logging.getLogger(__name__)\n'
        'def f(addr, name):\n'
        '    logger.info("at %s:%s", addr)        # tuple, not two args\n'
        '    logger.info("skipping ", name)       # no placeholder at all\n'
        '    logger.info("at %s:%s", *addr)       # correct: splatted\n'
        '    logger.info("pct 100%% done")        # literal %, no args\n'
        '    logger.info("one %s", name)          # correct\n'
    )
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as fd:
        fd.write(sample)
        tmp = fd.name
    try:
        got = sorted((want, supplied) for _ln, want, supplied, _m
                     in _arity_mismatches_in(tmp))
    finally:
        os.unlink(tmp)
    assert got == [(0, 1), (2, 1)], got


def test_the_check_can_actually_fail():
    """A guard that cannot fire is not a guard.

    Each offending form is fed through the same detector the test above uses,
    from a real file, so a refactor that quietly stops recognising one of them
    is caught here rather than by the convention rotting unnoticed.
    """
    import tempfile
    sample = (
        'import logging\n'
        'logger = logging.getLogger(__name__)\n'
        'def f(x):\n'
        '    logger.info("a %s" % x)\n'
        '    logger.info(f"b {x}")\n'
        '    logger.info("c" + str(x))\n'
        '    logger.info("d {}".format(x))\n'
        '    logger.info("e %s", x)      # the only acceptable form\n'
    )
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as fd:
        fd.write(sample)
        tmp = fd.name
    try:
        kinds = sorted(kind for _ln, kind in _offenders_in(tmp))
    finally:
        os.unlink(tmp)
    assert kinds == sorted(["'...' % arg", 'f-string', 'concatenation',
                            '.format()']), kinds


def test_one_canonical_line_format():
    """Every handler in the project renders the same shape.

    The AT processes and the entry-point scripts used to disagree, and in an
    entry point BOTH handlers are live at once -- so one framework event
    printed twice, in two different shapes. Pinning the constant here means a
    future edit has to be deliberate.
    """
    from autonomous_trust.core import LOG_FORMAT, LOG_DATEFMT
    assert LOG_FORMAT == '%(asctime)s.%(msecs)03d - %(levelname)s %(message)s'
    assert LOG_DATEFMT == '%Y-%m-%d %H:%M:%S'


def test_no_entry_point_defines_its_own_line_format():
    """basicConfig callers must take the shared constant, not spell out a
    format of their own -- that is how the nine of them drifted."""
    root = _src_root()
    if root is None:
        pytest.skip('package sources not present in this checkout')
    repo = os.path.abspath(os.path.join(root, '..'))
    offenders = []
    for area in ('src/autonomous-trust', 'examples'):
        base = os.path.join(repo, area)
        if not os.path.isdir(base):
            continue
        for path in _walk(base):
            if 'third_party' in path or os.path.abspath(path) == __file__:
                continue        # vendored code, and this checker's own literals
            with open(path, encoding='utf-8') as fd:
                text = fd.read()
            if 'basicConfig' not in text:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if 'format=' in line and '%(levelname)s' in line:
                    offenders.append('%s:%d' % (os.path.relpath(path, repo), i))
    assert not offenders, (
        'entry point(s) spell out a log format instead of importing '
        'LOG_FORMAT/LOG_DATEFMT from autonomous_trust.core:\n  %s'
        % '\n  '.join(offenders))
