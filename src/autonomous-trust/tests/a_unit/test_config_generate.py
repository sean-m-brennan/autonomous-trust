# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import os
import re

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity
from autonomous_trust.core.system import core_system, agreement_impl

from .. import INSIDE_DOCKER


cidr_regex = r'(?:/\d\d?)'
ipv4_regex = r'(\d{1,3}\.){3}\d{1,3}'
ipv6_regex = r'([0-9a-fA-F]{1,4}:?|:)+'
mac_regex = r'([0-9A-Fa-f]{2}:){5}(?:[0-9A-Fa-f]{2})'
hex_seed_regex = r'([0-9A-Fa-f]{86}==)'


def test_generate_identity(setup_teardown):
    net, ident, subsys = generate_identity(os.environ[Configuration.ROOT_VARIABLE_NAME], True)

    ipv6_cidr_regex = ipv6_regex + cidr_regex
    if INSIDE_DOCKER:
        ipv6_cidr_regex = 'null'  # unless IPV6 is enabled in docker

    expected_net = '!Cfg:autonomous_trust.core.network.network.Network' + \
                   ' _ip4_cidr: ' + ipv4_regex + cidr_regex + \
                   ' _ip6_cidr: ' + ipv6_cidr_regex + ' _mac_address: ' + mac_regex + \
                   ' _mcast4_addr: ' + ipv4_regex + ' _mcast6_addr: ' + ipv6_regex + ' _port: null'
    actual_net = re.sub(' +', ' ', net.to_yaml_string().strip().replace('\n', ' '))
    assert re.match(expected_net, actual_net) is not None  # FIXME is None

    expected_ident = '!Cfg:autonomous_trust.core.identity.identity.Identity' + \
                     ' _block_impl: ' + agreement_impl + \
                     ' _encryptor: !Cfg:autonomous_trust.core.identity.encrypt.Encryptor' + \
                     ' hex_seed: !!binary | ' + hex_seed_regex + ' public_only: false' + \
                     r' _fullname: ([^@]+@[^@]+\.[^@]+)' + r' _nickname: ([a-z]+)' + \
                     ' _public_only: false' + ' _rank: 0' + \
                     ' _signature: !Cfg:autonomous_trust.core.identity.sign.Signature' + \
                     ' hex_seed: !!binary | ' + hex_seed_regex + ' public_only: false' + \
                     ' _uuid: ' + ' address: ' + ipv4_regex + ' petname: me'
    assert re.match(expected_ident, re.sub(' +', ' ', ident.to_yaml_string().replace('\n', ' '))) is not None

    expected_subsys = '!!omap [' + ', '.join(['{%s: %s}' % (key, value) for key, value in core_system.items()]) + ']'
    assert subsys.to_yaml_string().replace('\n', '').replace('  ', ' ') == expected_subsys
