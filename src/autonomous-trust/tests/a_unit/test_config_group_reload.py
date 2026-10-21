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
"""A restarted node reads its saved group back as a Group.

identity writes group.cfg.json as ``(Group, history)``; load_configs used to
hand the pair on, so every process's ``protocol.group`` became a list after a
restart and reputation failed each proposal on ``'list' object has no
attribute 'uuid'``.
"""
import json
import os
from uuid import uuid4

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.configuration import ConfigJSONEncoder
from autonomous_trust.core._python.config.discover import load_configs
from autonomous_trust.core.identity import Group
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.protocol import Protocol
from autonomous_trust.core.system import CfgIds


@pytest.fixture
def cfg_dir(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    d = Configuration.get_cfg_dir()
    os.makedirs(d, exist_ok=True)
    return d


def _group():
    return Group(uuid4(), {str(uuid4()): '10.0.0.1'}, 'g',
                 Encryptor(b'ab' * 32, public_only=False))


def _path(cfg_dir):
    return os.path.join(cfg_dir, CfgIds.group + Configuration.file_ext)


def test_the_saved_group_and_history_pair_loads_as_the_group(cfg_dir):
    grp = _group()
    # Exactly as IdentityProcess._remember_activity writes it.
    with open(_path(cfg_dir), 'w') as fh:
        json.dump((grp, {'history': []}), fh, cls=ConfigJSONEncoder, indent=2)
    loaded = load_configs()[CfgIds.group]
    assert isinstance(loaded, Group)
    assert str(loaded.uuid) == str(grp.uuid)
    # ...and so every process's protocol holds a Group, not a list.
    import logging
    assert isinstance(Protocol('reputation', logging.getLogger('t'),
                               load_configs()).group, Group)


def test_a_bare_group_file_still_loads(cfg_dir):
    grp = _group()
    grp.to_file(_path(cfg_dir))
    loaded = load_configs()[CfgIds.group]
    assert isinstance(loaded, Group) and str(loaded.uuid) == str(grp.uuid)
