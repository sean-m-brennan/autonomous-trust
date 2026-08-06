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
import json
import logging
from unittest.mock import MagicMock, patch

import pytest

try:
    from autonomous_trust.inspector.dash_components.core import (
        IconSize, make_icon, DashComponent, DashControl, WSClient,
    )
    has_dash = True
except (ImportError, ModuleNotFoundError) as _e:
    has_dash = False

pytestmark = [
    pytest.mark.skipif(not has_dash, reason='dash_components dependencies not available'),
    pytest.mark.filterwarnings('ignore::RuntimeWarning'),
]


class TestIconSize:
    def test_values(self):
        assert IconSize.SMALL is not None
        assert IconSize.MEDIUM is not None
        assert IconSize.LARGE is not None


class TestMakeIcon:
    def test_icon_only(self):
        result = make_icon('mdi:home')
        assert len(result) == 1

    def test_icon_with_text(self):
        result = make_icon('mdi:home', text='Home')
        assert len(result) == 3

    def test_icon_small(self):
        result = make_icon('mdi:home', size=IconSize.SMALL)
        assert len(result) == 1

    def test_icon_large(self):
        result = make_icon('mdi:home', size=IconSize.LARGE)
        assert len(result) == 1

    def test_icon_with_color(self):
        result = make_icon('mdi:home', color='red')
        assert len(result) == 1

    def test_icon_with_text_small(self):
        result = make_icon('mdi:home', text='Test', size=IconSize.SMALL)
        assert len(result) == 3

    def test_icon_with_text_large(self):
        result = make_icon('mdi:home', text='Test', size=IconSize.LARGE)
        assert len(result) == 3


class TestDashComponent:
    def test_uses_react(self):
        assert DashComponent.uses_react is True

    def test_div_raises(self):
        comp = DashComponent(MagicMock())
        with pytest.raises(NotImplementedError):
            comp.div()


class TestWSClient:
    def test_creation(self):
        sock = MagicMock()
        sock.remote_address = ('192.168.1.1', 5005)
        client = WSClient(sock)
        assert client.address == '192.168.1.1'
        assert client.socket is sock


class TestDashControl:
    def _make_ctl(self, **kwargs):
        with patch('autonomous_trust.inspector.dash_components.core.get_ip_addr', return_value='127.0.0.1'):
            return DashControl('test', 'Test App', host='127.0.0.1', **kwargs)

    def test_creation(self):
        ctl = self._make_ctl()
        assert ctl.server_address == ('127.0.0.1', 8050)
        assert ctl.verbose is False
        assert ctl.active_page is None

    def test_creation_verbose(self):
        ctl = self._make_ctl(verbose=True)
        assert ctl.verbose is True

    def test_creation_with_logger(self):
        logger = logging.getLogger('test_dash')
        ctl = self._make_ctl(logger=logger)
        assert ctl.inherited_logger is logger

    def test_ws_url(self):
        ctl = self._make_ctl()
        url = ctl.ws_url('graph')
        assert url == 'ws://127.0.0.1:5005/graph'

    def test_ws_url_with_params(self):
        ctl = self._make_ctl()
        url = ctl.ws_url('graph', params=['foo', 42])
        assert url == 'ws://127.0.0.1:5005/graph/foo/42'

    def test_ws_url_empty_params(self):
        ctl = self._make_ctl()
        url = ctl.ws_url('graph', params=[])
        assert url == 'ws://127.0.0.1:5005/graph'

    def test_emit_json(self):
        ctl = self._make_ctl()
        ctl.emit('test_event', {'key': 'value'})
        msg = ctl.ws_send_queue.get_nowait()
        parsed = json.loads(msg)
        assert parsed['event'] == 'test_event'
        assert parsed['data'] == {'key': 'value'}

    def test_emit_string_data(self):
        ctl = self._make_ctl()
        ctl.emit('test_event', 'hello')
        msg = ctl.ws_send_queue.get_nowait()
        parsed = json.loads(msg)
        assert parsed['data'] == 'hello'

    def test_halt(self):
        ctl = self._make_ctl()
        ctl.ws_stop = MagicMock()
        ctl.halt()
        ctl.ws_stop.cancel.assert_called_once()

    def test_halt_no_stop(self):
        ctl = self._make_ctl()
        ctl.ws_stop = None
        ctl.halt()

    def test_convert_sub_comp_string(self):
        ctl = self._make_ctl()
        assert ctl._convert_sub_comp('hello') == 'hello'

    def test_convert_sub_comp_int(self):
        ctl = self._make_ctl()
        assert ctl._convert_sub_comp(42) == 42

    def test_convert_sub_comp_float(self):
        ctl = self._make_ctl()
        assert ctl._convert_sub_comp(3.14) == 3.14

    def test_convert_sub_comp_list(self):
        ctl = self._make_ctl()
        result = ctl._convert_sub_comp(['a', 1, 2.0])
        assert result == ['a', 1, 2.0]

    def test_callback_connect_decorator(self):
        ctl = self._make_ctl()
        @ctl.callback_connect()
        def handler(event, data):
            pass
        assert 'connect' in ctl.websocket_handlers
        assert 'disconnect' in ctl.websocket_handlers

    def test_websocket_handlers_initially_empty(self):
        ctl = self._make_ctl()
        assert ctl.websocket_handlers == {}

    def test_clients_initially_empty(self):
        ctl = self._make_ctl()
        assert ctl.clients == []

    def test_creation_with_pages_dir(self, tmp_path):
        ctl = self._make_ctl(pages_dir=str(tmp_path))
        assert ctl.app is not None

    def test_creation_proxied(self):
        ctl = self._make_ctl(proxied=True)
        assert ctl.app is not None

    def test_push_mods(self):
        ctl = self._make_ctl()
        ctl.push_mods({'comp1': {'children': 'hello'}})
        msg = ctl.ws_send_queue.get_nowait()
        import json
        parsed = json.loads(msg)
        assert parsed['event'] == 'modify'
        assert isinstance(parsed['data'], list)
        assert parsed['data'][0]['id'] == 'comp1'
        assert parsed['data'][0]['property'] == 'children'

    def test_push_mods_multiple(self):
        ctl = self._make_ctl()
        ctl.push_mods({'c1': {'p1': 'v1', 'p2': 'v2'}})
        msg = ctl.ws_send_queue.get_nowait()
        import json
        parsed = json.loads(msg)
        assert len(parsed['data']) == 2

    def test_emit_binary(self):
        ctl = self._make_ctl()
        ctl.emit('video', {'id': 'feed', 'data': b'\x00\x01\x02'}, binary=True)
        msg = ctl.ws_send_queue.get_nowait()
        assert isinstance(msg, bytes)

    def test_serve_websockets(self):
        ctl = self._make_ctl()
        ctl.serve_websockets()
        assert ctl.ws_loop.is_running()
        ctl.halt()

    def test_convert_sub_comp_none(self):
        ctl = self._make_ctl()
        assert ctl._convert_sub_comp(None) is None

    def test_convert_sub_comp_nested_list(self):
        ctl = self._make_ctl()
        result = ctl._convert_sub_comp([['a', 'b'], 'c'])
        assert result == [['a', 'b'], 'c']

    def test_clientside_callback(self):
        ctl = self._make_ctl()
        # Just verify it delegates to app
        assert hasattr(ctl, 'clientside_callback')

    def test_callback_shared_decorator(self):
        from dash_extensions.enrich import Output, Input
        ctl = self._make_ctl()
        out = Output('comp', 'children')
        inp = Input('btn', 'n_clicks')

        @ctl.callback_shared(out, inp)
        def handler():
            return 'result'

        assert 'btn_n_clicks' in ctl.websocket_handlers

    def test_callback_shared_list_input(self):
        from dash_extensions.enrich import Output, Input
        ctl = self._make_ctl()
        out = Output('comp', 'children')
        inp1 = Input('btn1', 'n_clicks')
        inp2 = Input('btn2', 'n_clicks')

        @ctl.callback_shared(out, [inp1, inp2])
        def handler():
            return 'result'

        assert 'btn1_n_clicks' in ctl.websocket_handlers
        assert 'btn2_n_clicks' in ctl.websocket_handlers
