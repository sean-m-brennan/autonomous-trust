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
from queue import Queue
import pytest
from autonomous_trust.inspector.viz import server
from .. import INSIDE_DOCKER


@pytest.mark.skipif(INSIDE_DOCKER, reason='Inside docker (not valid)')
@pytest.mark.asyncio
async def test_presentation():
    pages_list = ['/']  # FIXME
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
    pres_dir = os.path.join(base_dir, 'doc', 'presentation')
    app = server.VizServer(pres_dir, 8998, False, 12).app
    for page in pages_list:
        response = await app.test_client().get(page)
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_simulation():
    sim_dir = os.path.abspath(os.path.dirname(server.__file__))
    app = server.VizServer(sim_dir, 8998, False, 12).app
    response = await app.test_client().get('/')
    assert response.status_code == 200
    ws_client = app.test_client().websocket('/ws')
    await ws_client.send('test')
    # response = await ws_client.receive_json()
    await ws_client.send('done')
    # FIXME check json


@pytest.mark.asyncio
async def test_live_interface():
    sim_dir = os.path.abspath(os.path.dirname(server.__file__))
    data_q = Queue()
    app = server.VizServer(sim_dir, 8998, False, data_q=data_q).app
    # FIXME put data in q
    response = await app.test_client().get('/')
    assert response.status_code == 200
    ws_client = app.test_client().websocket('/ws')
    await ws_client.send('test')
    # response = await ws_client.receive_json()
    await ws_client.send('done')
    # FIXME check json
