# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

import json
import os

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.configuration import config_json_decoder
from autonomous_trust.core.config.generate import generate_identity
from autonomous_trust.core.system import core_system

from .. import INSIDE_DOCKER


def test_generate_identity(setup_teardown):
    net, ident, subsys = generate_identity(os.environ[Configuration.ROOT_VARIABLE_NAME], True)

    # Verify network config round-trips through JSON
    net_json = net.to_json_string()
    net_data = json.loads(net_json, object_hook=config_json_decoder)
    assert net_data.__class__.__name__ == 'Network'
    assert hasattr(net_data, '_ip4_cidr')
    assert hasattr(net_data, '_mac_address')

    # Verify identity config round-trips through JSON
    ident_json = ident.to_json_string()
    ident_data = json.loads(ident_json, object_hook=config_json_decoder)
    assert ident_data.__class__.__name__ == 'Identity'
    assert hasattr(ident_data, '_fullname')
    assert hasattr(ident_data, '_nickname')
    assert hasattr(ident_data, '_signature')
    assert hasattr(ident_data, '_encryptor')

    # Verify subsystems config round-trips through JSON
    subsys_json = subsys.to_json_string()
    subsys_data = json.loads(subsys_json)
    expected = dict(core_system)
    assert subsys_data == expected
