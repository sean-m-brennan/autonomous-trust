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
"""First contact as an extension (FEATURE_SPLIT_PLAN Phase 7): the core finds
it from this distribution, it registers its handlers exactly when
``AT_FIRST_CONTACT`` is on, and an ``IdentityProcess`` with it on still pickles
-- multiproc mode ships it to its worker that way, and the old lambda handlers
did not pickle.
"""
import pickle
import types

import pytest

from autonomous_trust.core.system import CfgIds, PackageHash
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.core.capabilities import PeerCapabilities
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core._python import extensions
from autonomous_trust.core._python.identity.idprocess import IdentityProcess
from autonomous_trust.first_contact.fc_protocol import FirstContactProtocol


@pytest.fixture(autouse=True)
def _isolate_data_dir(monkeypatch, tmp_path):
    """First contact's durable nonce store goes to a per-test temp dir."""
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))


def test_first_contact_is_found():
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
    assert (FirstContactProtocol.hello in proc.protocol.handlers) is expect
    assert (FirstContactProtocol.hello_ack in proc.protocol.handlers) is expect
    assert ('first_contact' in proc._extensions) is expect


def test_identity_process_with_first_contact_pickles(monkeypatch):
    """Multiproc mode pickles the process (pool.apply_async(proc.process));
    the old lambda handlers made that fail whenever AT_FIRST_CONTACT=1."""
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    proc = _identity_process()
    clone = pickle.loads(pickle.dumps(proc))
    assert 'first_contact' in clone._extensions
    handler = clone.protocol.handlers[FirstContactProtocol.hello]
    assert handler.args[0] is clone  # bound to the clone, not the original


def test_both_halves_are_found():
    """The handshake and its always-on network half, as C registers two hooks."""
    names = [e.name for e in extensions.all_extensions()]
    assert 'first_contact' in names and 'first_contact_network' in names


def test_asking_for_it_is_honoured(monkeypatch):
    """Present, so AT_FIRST_CONTACT=1 is no undeclared feature (the core's
    test_extensions pins the refusal without this distribution)."""
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    extensions.check_env()
