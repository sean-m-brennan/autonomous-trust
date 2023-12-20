import asyncio
import base64
import json
import logging
import os.path
import socket
import threading
from collections import defaultdict
from enum import Enum, auto
from queue import Queue, Empty
from typing import Callable, Union, Optional

import flask
import dash
from dash.development.base_component import Component
from dash_extensions.enrich import DashProxy, html
from dash_iconify import DashIconify
from plotly.basedatatypes import BaseFigure, BasePlotlyType
from websockets.legacy.server import serve as websocket_serve
from websockets.legacy.server import WebSocketServerProtocol

from .async_update import bin_data_pb2 as BinaryData

# for imports:
from dash import Patch  # noqa
from dash_extensions.enrich import Output, Input, State, ALL, MATCH  # noqa
from dash_extensions.enrich import dcc, ctx  # noqa
from dash_extensions import WebSocket  # noqa


class IconSize(Enum):
    SMALL = auto()
    MEDIUM = auto()
    LARGE = auto()


def make_icon(icon_name: str, text: str = None, color: str = None, size: IconSize = IconSize.MEDIUM):
    # font_size_elt = 'font-size'
    font_size_elt = 'fontSize'
    if size == IconSize.SMALL:
        height = 30
        font_size = 8
    elif size == IconSize.MEDIUM:
        height = 40
        font_size = 10
    else:
        height = 50
        font_size = 12
    width = height
    if text is not None:
        width += font_size + 2
    if text is None:
        return [DashIconify(icon=icon_name, color=color, height=height, width=width)]
    return [DashIconify(icon=icon_name, color=color, height=height, width=width),
            html.Br(), html.Div(text, style={font_size_elt: font_size})]


class DashComponent(object):
    uses_react = True

    def __init__(self, app: dash.Dash):
        self.app = app  # for callbacks
        self.server = self.app.server  # for URL registration

    def div(self, *args, **kwargs) -> html.Div:
        raise NotImplementedError


def get_ip_addr():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


class WSClient(object):
    def __init__(self, sock):  # FIXME get other client info
        self.socket: WebSocketServerProtocol = sock
        self.address = sock.remote_address[0]


class DashControl(object):
    ws_port = 5005
    legacy = True

    def __init__(self, name: str, title: str, host: str = '0.0.0.0', port: int = 8050,
                 stylesheets: list[str] = None, pages_dir: str = None, logger: logging.Logger = None,
                 verbose: bool = False, proxied: bool = False):
        if stylesheets is None:
            stylesheets = []
        pages = False
        if pages_dir is not None:
            pages = True
        if host == '0.0.0.0':
            host = get_ip_addr()
        self.server_address = host, port

        if not verbose:
            logging.getLogger('werkzeug').setLevel(logging.WARNING)  # reduce useless callback noise from Flask
            logging.getLogger('websockets').setLevel(logging.WARNING)
        self.verbose = verbose
        self.inherited_logger = logger

        external_scripts = [
            "https://code.jquery.com/jquery-3.6.0.min.js",
            "https://cdn.plot.ly/plotly-latest.min.js"
        ]

        self.ws_loop = asyncio.new_event_loop()
        self.ws_stop: Optional[asyncio.Future] = None
        self.ws_send_queue = Queue()
        self.websocket_handlers: dict[str, list[Callable]] = {}
        self.clients: list[WSClient] = []
        self._client_dir: dict[WebSocketServerProtocol, WSClient] = {}

        self.server = flask.Flask(name)
        dash_class = dash.Dash
        if proxied:
            dash_class = DashProxy
        kwargs = {}
        if pages:
            kwargs['suppress_callback_exceptions'] = True
        self.app = dash_class(name, server=self.server, title=title, update_title=None,
                              assets_folder=os.path.join(os.path.dirname(__file__), 'assets'),
                              external_stylesheets=stylesheets, external_scripts=external_scripts,
                              use_pages=pages, pages_folder=pages_dir, **kwargs
                              )

        self.server.logger.log_level = logging.INFO
        self.app.logger.log_level = logging.INFO
        if verbose:
            self.server.logger.log_level = logging.DEBUG
            self.app.logger.log_level = logging.DEBUG
        if self.inherited_logger is not None:
            for handler in self.inherited_logger.handlers:
                self.app.logger.addHandler(handler)
                self.server.logger.addHandler(handler)
        self.app.use_reloader = False
        self.active_page = None

    def ws_url(self, component_name: str, params: list = None):
        param_str = ''
        if params is not None and len(params) > 0:
            param_str = '/' + '/'.join(map(str, params))
        return 'ws://%s:%d/%s%s' % (self.server_address[0], self.ws_port, component_name, param_str)

    def _websocket_event_loop(self):
        asyncio.set_event_loop(self.ws_loop)
        self.ws_loop.run_forever()

    async def _websocket_service(self):
        self.ws_stop = asyncio.Future()
        logger = logging.Logger(__name__ + '_websockets')
        logger.log_level = logging.INFO
        if self.verbose:
            logger.log_level = logging.DEBUG
        #if self.inherited_logger is not None:
        #    for handler in self.inherited_logger.handlers:
        #      logger.addHandler(handler)
        async with websocket_serve(self._websocket_handler, self.server_address[0], self.ws_port,
                                   loop=self.ws_loop, logger=logger, compression=None):
            print(' * Serving websockets at ws://%s:%d' % (self.server_address[0], self.ws_port))
            await self.ws_stop

    async def _websocket_handler(self, websocket: WebSocketServerProtocol, path: str):
        async for message in websocket:
            if message == 'connect':
                client = WSClient(websocket)
                self.clients.append(client)
                self._client_dir[websocket] = client
            elif message == 'disconnect':
                client = self._client_dir[websocket]
                self.clients.remove(client)
                del self._client_dir[websocket]
            event = message
            data = None
            try:
                json_obj = json.loads(message)
                event = json_obj.message
                data = json_obj.data
            except json.decoder.JSONDecodeError:
                pass
            if event in self.websocket_handlers:
                for func in self.websocket_handlers[event]:
                    func(data)

    async def _websocket_sender(self):
        while not self.ws_stop.cancelled():
            try:
                while True:
                    message = self.ws_send_queue.get_nowait()
                    for client in self.clients:
                        await client.socket.send(message)
            except Empty:
                pass
            await asyncio.sleep(0.1)

    def serve_websockets(self):
        threading.Thread(target=self._websocket_event_loop, daemon=True).start()
        asyncio.run_coroutine_threadsafe(self._websocket_service(), self.ws_loop)
        asyncio.run_coroutine_threadsafe(self._websocket_sender(), self.ws_loop)

    def halt(self):
        self.ws_loop.call_soon_threadsafe(self.ws_loop.stop)
        if self.ws_stop is not None:
            self.ws_stop.cancel()

    def callback(self, *args, **kwargs) -> Callable:
        """Pass-through decorator for callback handler definitions - pull from server"""
        return self.app.callback(*args, **kwargs)

    def callback_shared(self, *args) -> Callable:
        """Decorator for shared callback handler - pull from server, push out to all browsers"""
        def decorator(funct):
            def add_mod(output, ret_val, mods):
                mod_dict = defaultdict()
                mod_dict[output.component_id][output.component_property] = ret_val
                mods.append(mod_dict)

            def reg_input(inpt, fun):
                msg = inpt.component_id + '_' + inpt.component_property
                if msg not in self.websocket_handlers:
                    self.websocket_handlers[msg] = []
                self.websocket_handlers[msg].append(fun)

            def wrapper():
                ret_val = funct()
                mods = []
                if isinstance(args[0], Output):
                    add_mod(args[0], ret_val, mods)
                elif isinstance(args[0], (list, tuple)):
                    if not isinstance(ret_val, (list, tuple)) or len(ret_val) != len(args[0]):
                        raise RuntimeError('Non-matching ')  # FIXME err msg
                    for idx, output in enumerate(args[0]):
                        if isinstance(output, Output):
                            add_mod(output, ret_val[idx], mods)
                        else:
                            raise RuntimeError('Invalid ')  # FIXME err msg
                else:
                    raise RuntimeError('Invalid ')  # FIXME err msg
                for mod in mods:
                    self.push_mods(mod)
                return ret_val

            if isinstance(args[1], Input):
                reg_input(args[1], wrapper)
            elif isinstance(args[1], (list, tuple)):
                for inpt in args[1]:
                    reg_input(inpt, wrapper)
        return decorator

    def callback_connect(self) -> Callable:
        """Decorator for connection callback handler - push from browser"""
        def decorator(funct):
            if 'connect' not in self.websocket_handlers:
                self.websocket_handlers['connect'] = []
            self.websocket_handlers['connect'].append(lambda x: funct('connect', x))
            if 'disconnect' not in self.websocket_handlers:
                self.websocket_handlers['disconnect'] = []
            self.websocket_handlers['disconnect'].append(lambda x: funct('disconnect', x))
        return decorator

    def clientside_callback(self, clientside_function, *args, **kwargs):
        return self.app.clientside_callback(clientside_function, *args, **kwargs)

    ComponentLike = Union[Component, str, int, float]

    PlotlyTypes = (Component, BaseFigure, BasePlotlyType)

    def _convert_sub_comp(self, value: ComponentLike) -> Optional[Union[dict, list, str, int, float]]:
        if isinstance(value, list):
            sub_list = []
            for sub in value:
                sub_list.append(self._convert_sub_comp(sub))
            return sub_list
        elif isinstance(value, self.PlotlyTypes):
            obj = value.to_plotly_json()
            if 'props' in obj:
                if 'children' in obj['props']:
                    obj['props']['children'] = self._convert_sub_comp(obj['props']['children'])
                elif 'figure' in obj['props']:
                    obj['props']['figure'] = self._convert_sub_comp(obj['props']['figure'])
            return obj
        else:
            return value

    def push_mods(self, mods: dict[str, dict[str, Union[ComponentLike, list[ComponentLike]]]]):
        """Asynchronous component updating; requires AsyncUpdate in the layout"""
        props = list()
        for ident in mods.keys():
            for prop_id in mods[ident].keys():
                prop = defaultdict()
                prop['id'] = ident
                prop['property'] = prop_id
                prop['value'] = self._convert_sub_comp(mods[ident][prop_id])
                props.append(prop)
        self.emit('modify', props)

    def emit(self, event: str, data: Union[str, bytes, list, dict] = None, binary: bool = False):
        """Websocket comm to server"""
        if binary:
            bdmsg = BinaryData.BinaryDataMsg()
            bdmsg.event = event
            bdmsg.elt_id = data['id']
            bdmsg.size = len(data['data'])
            print('Msg ', bdmsg)
            bdmsg.data = data['data']
            message: bytes = bdmsg.SerializeToString()
            #print('Enc ', enc[:40])
            #message = base64.b64encode(enc)
            print('B64 ', message[:40])
        else:
            message: str = json.dumps(dict(event=event, data=data))
        self.ws_send_queue.put(message)

    def run(self, host: str, port: int, **kwargs):
        kwargs['use_reloader'] = False  # *never* allow reloader (causes subtle bugs)
        # FIXME Ctl-C handler to call self.halt
        self.serve_websockets()
        self.app.run(host, port, **kwargs)
