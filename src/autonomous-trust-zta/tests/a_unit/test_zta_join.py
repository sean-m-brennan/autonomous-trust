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
"""The ZTA half of a targeted join (doc/architecture/gateway-reputation-tree.md):
a requester must have proved an anchor we share. Pinned against
``admission.join_refused`` itself since FEATURE_SPLIT_PLAN Phase 6, when the
rule left the core's ``IdentityProcess._join_authorized`` (whose rank gate the
core's test_cross_group_join.py still pins)."""
import logging
from types import SimpleNamespace

from autonomous_trust.zta import admission
from autonomous_trust.zta.zta_policy import ZtaPolicy


def _proc(enforcing=True, own_anchors=('agency-a',)):
    proc = SimpleNamespace(configs={}, logger=logging.getLogger('test.zta.join'))
    admission.init_state(proc)
    proc._zta_policy_cache = ZtaPolicy(enabled=enforcing, require_at_admission=enforcing,
                                       verifier_type='null')
    proc._own_anchor_cache = set(own_anchors)
    return proc


def _requester(anchors=('agency-a',)):
    return SimpleNamespace(uuid='joiner-uuid', zta_anchors=list(anchors))


def test_a_shared_anchor_is_not_refused():
    assert not admission.join_refused(_proc(), _requester())


def test_a_foreign_anchor_is_refused():
    """A peer holding only another agency's credential is not ours to admit."""
    assert admission.join_refused(_proc(), _requester(anchors=('agency-b',)))
    assert admission.join_refused(_proc(), _requester(anchors=()))


def test_inert_without_enforcement():
    """Refusing everyone in a non-ZTA deployment would break joins rather than
    protect anything."""
    assert not admission.join_refused(_proc(enforcing=False), _requester(anchors=('agency-b',)))


def test_inert_when_we_hold_no_anchors():
    assert not admission.join_refused(_proc(own_anchors=()), _requester(anchors=()))
