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

"""A RUNNING inspector, over the network it actually serves (ISSUES §4.4 I21).

The integration suite drives the same pipeline in-process, which covers every
contract between our own modules and nothing about deployment: whether the
process binds the port it was told to, whether an ASGI server (rather than the
test client) carries a websocket frame intact, whether the page's own assets
resolve. Those only fail where a real one runs.

Skipped unless ``AT_INSPECTOR_URL`` names a live inspector, mirroring the core
suite's `c_system/test_ping_at.py`, which skips unless its `docker_ips` file
exists. Point it at a running instance:

    AT_INSPECTOR_URL=http://localhost:8000 pytest tests/c_system

A skipped system test is not a passing one — this file makes a claim only when
something is actually running.
"""

import asyncio
import json
import os

import pytest

INSPECTOR_URL = os.environ.get('AT_INSPECTOR_URL', '').rstrip('/')

pytestmark = pytest.mark.skipif(
    not INSPECTOR_URL,
    reason='AT_INSPECTOR_URL not set (needs a running inspector)')

RECV_TIMEOUT = 30.0


def _ws_url():
    """The same origin as the page, ws(s) in place of http(s) — the URL the
    browser's own client derives."""
    if INSPECTOR_URL.startswith('https://'):
        return 'wss://' + INSPECTOR_URL[len('https://'):] + '/ws'
    return 'ws://' + INSPECTOR_URL[len('http://'):] + '/ws'


def test_page_is_served():
    """The page loads at all. First because every other failure here reads the
    same way from a browser, and this distinguishes 'not running' from
    'running and broken'."""
    import urllib.request
    with urllib.request.urlopen(INSPECTOR_URL + '/', timeout=15) as resp:
        assert resp.status == 200
        body = resp.read().decode('utf-8', 'replace')
    assert '<' in body, 'served something that is not a document'


@pytest.mark.asyncio
async def test_websocket_streams_graph_frames():
    """A real websocket, over a real server, carrying real frames.

    Asserts the wire contract a browser depends on — parseable JSON, `links`
    rather than networkx's `edges`, and an opening frame that carries the whole
    graph — because an ASGI server and Quart's test client are not the same
    transport, and a frame that survives one can fail the other.
    """
    websockets = pytest.importorskip('websockets')
    from websockets.asyncio.client import connect

    async with connect(_ws_url()) as ws:
        raw = await asyncio.wait_for(ws.recv(), timeout=RECV_TIMEOUT)
        frame = json.loads(raw)

    assert isinstance(frame, dict)
    for key in ('nodes', 'links', 'groups'):
        assert key in frame, f'missing {key!r}; got {sorted(frame)}'
    assert 'edges' not in frame, 'networkx edge key leaked past the rename'
    # A live inspector connects with no handshake and opens with the whole
    # graph; a simulation would still be waiting for a selection message.
    assert frame.get('type') == 'new', frame.get('type')


@pytest.mark.asyncio
async def test_websocket_keeps_streaming():
    """More than one frame.

    A server that emits its opening graph and then stops looks identical to a
    healthy one for exactly as long as somebody watches the first screenful,
    which is how a stalled render loop reaches a demo unnoticed.
    """
    websockets = pytest.importorskip('websockets')
    from websockets.asyncio.client import connect

    frames = []
    async with connect(_ws_url()) as ws:
        for _ in range(2):
            raw = await asyncio.wait_for(ws.recv(), timeout=RECV_TIMEOUT)
            frames.append(json.loads(raw))

    assert len(frames) == 2
    assert frames[1].get('type') in ('add', 'remove', 'meta'), frames[1].get('type')
