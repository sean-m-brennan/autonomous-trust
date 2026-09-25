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

Pins: ``enabled`` is re-read on every load, handlers go only to the process
the extension names, first contact is the built-in client, and an
``IdentityProcess`` with first contact on still pickles -- multiproc mode
ships it to its worker that way, and the old lambda handlers did not pickle.
"""
import pickle
import sys
import types

import pytest

from autonomous_trust.core import _backend_prefixes, register_backend_prefix
from autonomous_trust.core.system import CfgIds, PackageHash
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.capabilities import PeerCapabilities
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core._python import extensions
from autonomous_trust.core._python.extensions import (Extension, load_extensions,
                                                      run_post_fork, reset_extensions)
from autonomous_trust.core._python.identity.idprocess import IdentityProcess


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


# -- first contact, the built-in client ---------------------------------------
def test_first_contact_is_builtin():
    assert 'first_contact' in [e.name for e in extensions.all_extensions()]


def _identity_process():
    configurations = {
        CfgIds.identity: Identity.initialize('alice@ex', 'alice@ex', '10.0.0.1'),
        CfgIds.peers: Peers(),
        CfgIds.capabilities: PeerCapabilities(),
        PackageHash.key: 'test',
        'processes': [types.SimpleNamespace(name=CfgIds.network)],
    }
    return IdentityProcess(configurations, ProcessTracker(), log_q=None,
                           suppress_log=True)


@pytest.mark.parametrize('flag,expect', [('1', True), ('0', False)])
def test_first_contact_registers_exactly_when_enabled(monkeypatch, flag, expect):
    monkeypatch.setenv('AT_FIRST_CONTACT', flag)
    proc = _identity_process()
    assert (IdentityProtocol.hello in proc.protocol.handlers) is expect
    assert (IdentityProtocol.hello_ack in proc.protocol.handlers) is expect
    assert ('first_contact' in proc._extensions) is expect


def test_identity_process_with_first_contact_pickles(monkeypatch):
    """Multiproc mode pickles the process (pool.apply_async(proc.process));
    the old lambda handlers made that fail whenever AT_FIRST_CONTACT=1."""
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    proc = _identity_process()
    clone = pickle.loads(pickle.dumps(proc))
    assert 'first_contact' in clone._extensions
    handler = clone.protocol.handlers[IdentityProtocol.hello]
    assert handler.args[0] is clone  # bound to the clone, not the original


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
