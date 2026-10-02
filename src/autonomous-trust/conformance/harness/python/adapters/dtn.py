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
"""DTN adapter (kind: scenario, protocol: dtn).

Each scenario names an `op` under `fixtures.dtn` and runs the DTN transport's
addressing (autonomous_trust.dtn.eid) or the hybrid transport's routing
(core.network.hybrid.hybrid_route), then asserts `expected_state.host`. Every
op is a pure function, so both runtimes must produce the same strings:

  node_eid       uuid                        -> eid
  group_eid      group_hash_hex              -> eid | error
  endpoints      node_uuid, group_uuid       -> endpoints [[eid, service] x3], group_joined
  broadcast_eid  channel, group_uuid         -> eid | error
  demux          service                     -> channel (peer|broadcast|group|none)
  peer_eid       target, peers [{address, uuid}] -> eid | error
  route          inners [...], target        -> leg

Mirrors the C adapter (src/c/extensions/dtn/conformance/dtn_adapter.c); the two
are diffed by case_id status. Without the DTN extension this adapter is absent
and the protocol skips, as C's does without libat_dtn.
"""
from pathlib import Path

from ...common.scenario_loader import Case

from autonomous_trust.dtn import eid as _eid
from autonomous_trust.core.network.hybrid import HybridConfig, HybridInner, hybrid_route

_CHANNELS = {'peer': _eid.CHAN_PEER, 'broadcast': _eid.CHAN_BROADCAST, 'group': _eid.CHAN_GROUP}
_NAMES = {v: k for k, v in _CHANNELS.items()}


def _expect(exp: dict, fn):
    """Run ``fn``; when ``exp`` says ``error: true`` it must refuse, otherwise
    its result is returned for the caller to compare."""
    try:
        got = fn()
    except _eid.EIDError:
        assert exp.get('error') is True, 'refused, but the scenario expects a value'
        return None
    assert exp.get('error') is not True, 'expected a refusal, got %r' % (got,)
    return got


class DtnAdapter:
    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    def run_wire_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('dtn adapter handles kind:scenario only')

    def run_crypto_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('dtn adapter handles kind:scenario only')

    def run_agreement_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('dtn adapter handles kind:scenario only')

    def run_negative(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('dtn adapter handles kind:scenario only')

    def run_scenario(self, case: Case) -> None:
        spec = case.data
        fx = (spec.get('fixtures') or {}).get('dtn')
        assert isinstance(fx, dict), 'missing fixtures.dtn'
        exp = (spec.get('expected_state') or {}).get('host') or {}
        op = fx.get('op')
        handler = getattr(self, '_op_' + str(op), None)
        assert handler is not None, 'unknown dtn op %r' % op
        handler(fx, exp)

    @staticmethod
    def _op_node_eid(fx, exp):
        got = _expect(exp, lambda: _eid.eid_from_uuid(fx['uuid']))
        if got is not None:
            assert got == exp['eid'], 'node eid %s, want %s' % (got, exp['eid'])

    @staticmethod
    def _op_group_eid(fx, exp):
        got = _expect(exp, lambda: _eid.eid_for_group(bytes.fromhex(fx['group_hash_hex'])))
        if got is not None:
            assert got == exp['eid'], 'group eid %s, want %s' % (got, exp['eid'])

    @staticmethod
    def _op_endpoints(fx, exp):
        got = _eid.endpoints(fx.get('node_uuid'), fx.get('group_uuid'))
        assert [list(e) for e in got] == exp['endpoints'], 'endpoints %r' % (got,)
        joined = _eid.group_hash(fx.get('group_uuid'))[1]
        assert joined == exp['group_joined'], 'group_joined %s' % joined

    @staticmethod
    def _op_broadcast_eid(fx, exp):
        got = _expect(exp, lambda: _eid.broadcast_eid(_CHANNELS[fx['channel']],
                                                      fx.get('group_uuid')))
        if got is not None:
            assert got == exp['eid'], 'broadcast eid %s, want %s' % (got, exp['eid'])

    @staticmethod
    def _op_demux(fx, exp):
        ch = _eid.service_to_channel(fx.get('service'))
        got = _NAMES.get(ch, 'none')
        assert got == exp['channel'], 'service %r -> %s, want %s' % (fx.get('service'), got,
                                                                     exp['channel'])
        if ch is not None:
            assert _eid.channel_suffix(ch) == fx['service']

    @staticmethod
    def _op_peer_eid(fx, exp):
        # Exact address match, first listed wins (C walks its peer array).
        peers = fx.get('peers') or []

        def lookup(address):
            for peer in peers:
                if peer['address'] == address:
                    return peer['uuid']
            return None
        got = _expect(exp, lambda: _eid.peer_eid(fx['target'], lookup))
        if got is not None:
            assert got == exp['eid'], 'peer eid %s, want %s' % (got, exp['eid'])

    @staticmethod
    def _op_route(fx, exp):
        cfg = HybridConfig(inners=[HybridInner(kind=i['kind'], match_cidr=i.get('match_cidr', ''),
                                               match_eid=i.get('match_eid', False),
                                               is_default=i.get('is_default', False))
                                   for i in fx['inners']])
        got = hybrid_route(cfg, fx['target'])
        assert got == exp['leg'], 'route %r -> %d, want %d' % (fx['target'], got, exp['leg'])
