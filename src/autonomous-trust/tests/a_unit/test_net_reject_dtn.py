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
"""The blacklist keys on an address with its CIDR suffix stripped. A DTN
endpoint ID (dtn:/ipn:) keeps its slashes: they are part of the address.
Cutting at the first one turns every EID into ``dtn:``, so excluding one DTN
peer would drop traffic from all of them, and readmitting one would readmit
all. Twin of C net_reject_dtn_test.c."""
from types import SimpleNamespace
from unittest.mock import MagicMock

from autonomous_trust.core.network.netprocess import NetworkProcess

DTN_A = 'dtn://node-a/at'
DTN_B = 'dtn://node-b/at'
IPN_A = 'ipn:7.1'
IPN_B = 'ipn:9.1'


def _bare_netproc():
    """A NetworkProcess with only the attributes the gate methods touch,
    built without the heavy multiprocessing __init__."""
    np = NetworkProcess.__new__(NetworkProcess)
    np._rejected_addresses = set()
    np.acceptance = None
    np.protocol = MagicMock()
    np.logger = MagicMock()
    return np


def test_norm_addr_keeps_a_dtn_eid_whole():
    assert NetworkProcess._norm_addr(DTN_A) == DTN_A
    assert NetworkProcess._norm_addr(IPN_A) == IPN_A


def test_excluding_one_dtn_peer_leaves_another_alone():
    np = _bare_netproc()
    np.handle_exclude({}, SimpleNamespace(obj=DTN_A))
    assert np.reject_message(DTN_A) is True
    assert np.reject_message(DTN_B) is False
    assert np.reject_message('dtn:') is False


def test_readmitting_one_dtn_peer_leaves_another_excluded():
    np = _bare_netproc()
    np.handle_exclude({}, SimpleNamespace(obj=DTN_A))
    np.handle_exclude({}, SimpleNamespace(obj=DTN_B))
    np.handle_readmit({}, SimpleNamespace(obj=DTN_A))
    assert np.reject_message(DTN_A) is False
    assert np.reject_message(DTN_B) is True


def test_excluding_one_ipn_peer_leaves_another_alone():
    np = _bare_netproc()
    np.blacklist_address(IPN_A)
    assert np.reject_message(IPN_A) is True
    assert np.reject_message(IPN_B) is False


def test_blacklisting_one_dtn_peer_leaves_another_alone():
    np = _bare_netproc()
    np.blacklist_address(DTN_A)
    assert np.reject_message(DTN_A) is True
    assert np.reject_message(DTN_B) is False


def test_an_ip_exclusion_still_strips_the_cidr_suffix():
    np = _bare_netproc()
    np.blacklist_address('10.0.0.1/24')
    assert np.reject_message('10.0.0.1') is True
    assert np.reject_message('10.0.0.1/16') is True
    assert np.reject_message('10.0.0.2') is False
    np.handle_readmit({}, SimpleNamespace(obj='10.0.0.1'))
    assert np.reject_message('10.0.0.1/24') is False
