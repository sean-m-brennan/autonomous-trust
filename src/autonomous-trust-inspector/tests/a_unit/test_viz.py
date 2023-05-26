import os
from queue import Queue
import pytest
from autonomous_trust.inspector.viz import server

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))


@pytest.mark.asyncio
async def test_presentation():
    pages_list = ['/']  # FIXME
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
