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
"""A core-only node (FEATURE_SPLIT_PLAN Phase 5): social is a separate
distribution (src/autonomous-trust-social), not on this suite's path, so
absent means off.

Pins: no social extension is found, the identity process registers none of
the social verb strings and carries no ``proc.social``, the tier read needs no
block hook, and a node told to publish a position or profile refuses to start
rather than silently publish nothing. The social side is the distribution's
own test_social_registration.py.
"""
import types

import pytest

from autonomous_trust.core.system import CfgIds, PackageHash
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.core.capabilities import PeerCapabilities
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core._python import extensions
from autonomous_trust.core._python.identity.idprocess import IdentityProcess

#: The wire strings social registers (SocialProtocol's values).
SOCIAL_STRINGS = (
    'peer_position_query', 'peer_position_response', 'peer_profile_query',
    'peer_profile_response', 'peer_connection_request',
    'peer_connection_response', 'peer_dm', 'peer_post', 'peer_reaction',
    'peer_report', 'peer_business_ad', 'peer_business_post',
    'peer_cosign_request', 'peer_cosign_sig', 'peer_proximity_probe',
    'peer_proximity_reply', 'peer_proximity_trigger')

_DECLARED = ('AT_OWN_GEOHASH', 'AT_OWN_EXACT', 'AT_OWN_PROFILE')


@pytest.fixture(autouse=True)
def _core_only(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    for env in _DECLARED:
        monkeypatch.delenv(env, raising=False)
    if 'social' in {e.name for e in extensions.all_extensions()}:
        pytest.skip('autonomous_trust.social is on the path')


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


def test_identity_registers_no_social_verb():
    proc = _identity_process()
    assert 'social' not in proc._extensions
    assert not hasattr(proc, 'social')
    assert not set(SOCIAL_STRINGS) & set(proc.protocol.handlers)


def test_no_block_hook_and_the_tier_is_unclamped():
    import threading
    from autonomous_trust.core._python.extensions import identity_hooks
    proc = _identity_process()
    proc.lock = threading.Lock()
    assert not any(h.is_blocked_locked for h in identity_hooks(proc))
    peer = Identity.initialize('bob@ex', 'bob@ex', '10.0.0.2')
    proc.get_peer_tier(peer.uuid)   # asks no hook, raises nothing


@pytest.mark.parametrize('env', _DECLARED)
def test_a_social_declaration_is_refused(monkeypatch, env):
    monkeypatch.setenv(env, '{"display_name": "x"}' if env == 'AT_OWN_PROFILE'
                       else '9q8yy')
    with pytest.raises(extensions.ExtensionMissingError, match=env):
        extensions.check_env()


def test_the_node_itself_refuses(monkeypatch):
    """Through AutonomousTrust's own start (after oracles.check_env)."""
    from autonomous_trust.core.automate import AutonomousTrust
    monkeypatch.setenv('AT_OWN_GEOHASH', '9q8yy')
    with pytest.raises(extensions.ExtensionMissingError):
        AutonomousTrust(multiproc=False, silent=True,
                        logfile=Configuration.log_stdout).cleanup()


def test_an_empty_declaration_is_no_declaration(monkeypatch):
    monkeypatch.setenv('AT_OWN_PROFILE', '')
    extensions.check_env()
