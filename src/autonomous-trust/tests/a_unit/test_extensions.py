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
"""The feature-extension hook (core/_python/extensions.py, FEATURE_SPLIT_PLAN
Phase 0) and the backend redirector's feature prefixes.

Pins: ``enabled`` is re-read on every load, and handlers go only to the
process the extension names. First contact's own registration is pinned in its
distribution (autonomous-trust-first-contact, test_first_contact_extension.py).
"""
import sys
import types

import pytest

from autonomous_trust.core import _backend_prefixes, register_backend_prefix
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import Configuration
from autonomous_trust.core._python import extensions
from autonomous_trust.core._python.extensions import (Extension, load_extensions,
                                                      run_post_fork, reset_extensions)


@pytest.fixture(autouse=True)
def _isolate_data_dir(monkeypatch, tmp_path):
    """First contact's durable nonce store goes to a per-test temp dir."""
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))


class _Recorder:
    """A test extension: counts gate reads and records where it registered."""
    def __init__(self, name='probe', proc_name='identity', open_=True):
        self.gate_reads = 0
        self.open = open_
        self.registered = []
        self.post_forked = []
        self.resets = 0
        self.ext = Extension(name=name, enabled=self._gate,
                             register_handlers=self._register,
                             post_fork=self.post_forked.append,
                             reset=self._reset)
        self._proc_name = proc_name

    def _gate(self):
        self.gate_reads += 1
        return self.open

    def _register(self, proc, proc_name):
        if proc_name == self._proc_name:
            self.registered.append((proc, proc_name))

    def _reset(self):
        self.resets += 1


@pytest.fixture
def only(monkeypatch):
    """Replace the known extensions with the given ones."""
    def _set(*exts):
        monkeypatch.setattr(extensions, '_builtin', lambda: list(exts))
        monkeypatch.setattr(extensions, '_installed', lambda: [])
        monkeypatch.setattr(extensions, '_source_tree', lambda: [])
    return _set


def _proc():
    return types.SimpleNamespace()


# -- load_extensions ----------------------------------------------------------
def test_enabled_is_read_on_every_load(only):
    rec = _Recorder(open_=False)
    only(rec.ext)
    assert load_extensions(_proc(), 'identity') == []
    rec.open = True
    p = _proc()
    assert load_extensions(p, 'identity') == ['probe']
    assert rec.gate_reads == 2
    assert p._extensions == ['probe']


def test_handlers_go_only_to_the_named_process(only):
    rec = _Recorder(proc_name='reputation')
    only(rec.ext)
    for name in (CfgIds.identity, CfgIds.network, CfgIds.reputation,
                 CfgIds.negotiation):
        load_extensions(_proc(), name)
    assert [n for _, n in rec.registered] == [CfgIds.reputation]


def test_a_process_loads_an_extension_once(only):
    rec = _Recorder()
    only(rec.ext)
    p = _proc()
    load_extensions(p, 'identity')
    load_extensions(p, 'identity')
    assert len(rec.registered) == 1


def test_duplicate_name_keeps_the_first(only):
    first, second = _Recorder(), _Recorder()
    only(first.ext, second.ext)
    load_extensions(_proc(), 'identity')
    assert len(first.registered) == 1 and second.registered == []


def test_post_fork_runs_only_for_loaded_extensions(only):
    on, off = _Recorder('on'), _Recorder('off', open_=False)
    only(on.ext, off.ext)
    p = _proc()
    load_extensions(p, 'identity')
    run_post_fork(p)
    assert on.post_forked == [p] and off.post_forked == []
    run_post_fork(_proc())  # never loaded anything: a no-op
    assert on.post_forked == [p]


def test_reset_reaches_every_extension(only):
    on, off = _Recorder('on'), _Recorder('off', open_=False)
    only(on.ext, off.ext)
    reset_extensions()
    assert (on.resets, off.resets) == (1, 1)


def test_a_broken_installed_extension_is_skipped(monkeypatch, caplog):
    class _EP:
        name = 'broken'
        def load(self):
            raise ImportError('nope')
    monkeypatch.setattr(extensions.importlib.metadata, 'entry_points',
                        lambda group: [_EP()])
    assert extensions._installed() == []
    assert 'broken' in caplog.text


# -- a feature asked for but absent ------------------------------------------
@pytest.mark.parametrize('value,refused', [('1', True), ('on', True), ('0', False),
                                           ('', False)])
def test_first_contact_asked_for_but_absent(only, monkeypatch, value, refused):
    """AT_FIRST_CONTACT is a switch: on without first contact's distribution,
    the node refuses to start rather than run without it; off, it asks for
    nothing. Same as C's identity_ext_check_env."""
    only()
    monkeypatch.setenv('AT_FIRST_CONTACT', value)
    if refused:
        with pytest.raises(extensions.ExtensionMissingError):
            extensions.check_env()
    else:
        extensions.check_env()


@pytest.mark.parametrize('env,value,refused', [
    ('AT_USE_RELAY', '198.51.100.1:27790', True), ('AT_USE_RELAY', '', False),
    ('AT_RELAY', '1', True), ('AT_RELAY', '0', False),
    ('AT_RELAY_SEED_FALLBACK', 'yes', True), ('AT_RELAY_SEED_FALLBACK', 'off', False)])
def test_a_relay_asked_for_without_rendezvous(only, monkeypatch, env, value, refused):
    """A node told to use a relay, serve as one, or fall back on the rosters and
    seed list refuses to start without rendezvous (FEATURE_SPLIT_PLAN 7b); the
    two switches set off declare nothing. Same as C's identity_ext_check_env."""
    only()
    monkeypatch.setenv(env, value)
    if refused:
        with pytest.raises(extensions.ExtensionMissingError):
            extensions.check_env()
    else:
        extensions.check_env()


# -- backend redirector feature prefixes -------------------------------------
def test_redirector_serves_a_registered_prefix(tmp_path, monkeypatch):
    from autonomous_trust.core import _active_backend
    pkg = tmp_path / 'at_feature_probe'
    for sub in ('', _active_backend, '_python'):
        (pkg / sub).mkdir(exist_ok=True)
        (pkg / sub / '__init__.py').write_text('')
    (pkg / '_python' / 'widget.py').write_text("WHERE = '_python'\n")
    if _active_backend != '_python':
        (pkg / _active_backend / 'widget.py').write_text(
            f"WHERE = {_active_backend!r}\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(sys, 'modules', dict(sys.modules))
    monkeypatch.setattr('autonomous_trust.core._backend_prefixes',
                        list(_backend_prefixes), raising=True)

    with pytest.raises(ModuleNotFoundError):
        __import__('at_feature_probe.widget')
    register_backend_prefix('at_feature_probe')
    import importlib
    widget = importlib.import_module('at_feature_probe.widget')
    assert widget.WHERE == _active_backend
    assert widget.__name__ == f'at_feature_probe.{_active_backend}.widget'


def test_register_backend_prefix_is_idempotent(monkeypatch):
    monkeypatch.setattr('autonomous_trust.core._backend_prefixes',
                        list(_backend_prefixes), raising=True)
    import autonomous_trust.core as core
    register_backend_prefix('x.y')
    register_backend_prefix('x.y.')
    assert core._backend_prefixes.count('x.y.') == 1
