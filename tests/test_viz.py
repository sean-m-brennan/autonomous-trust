import os

from autonomous_trust.viz import server


async def test_presentation():
    pages_list = ['/']  # FIXME
    pres_dir = os.path.abspath(os.path.join(os.path.dirname(server.__file__), '..', '..', 'doc', 'presentation'))
    app = server.VizServer(pres_dir, 8998, False, 12).app
    for page in pages_list:
        response = await app.test_client().get(page)
        assert response.status_code == 200


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
