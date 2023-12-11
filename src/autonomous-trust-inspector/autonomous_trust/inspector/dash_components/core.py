import asyncio
import json
import logging
import os.path
import socket
import threading
from enum import Enum, auto
from queue import Queue, Empty
from typing import Callable, Union, Optional

import flask
import dash
from dash_extensions.enrich import DashProxy, html
from dash_iconify import DashIconify
from websockets.legacy.server import serve as websocket_serve
from websockets.legacy.server import WebSocketServerProtocol


# for imports:
from dash_extensions.enrich import dcc, Output, Input, ctx  # noqa
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

    def __init__(self, app: dash.Dash, server: flask.Flask = None):
        self.app = app  # for callbacks
        self.server = server  # for URL registration
        if server is None:
            self.server = self.app.server

    def div(self, *args, **kwargs) -> html.Div:
        raise NotImplementedError


def get_ip_addr():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


class DashControl(object):
    ws_port = 5005

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
        self.ws_clients: list[WebSocketServerProtocol] = []

        self.server = flask.Flask(name)
        dash_class = dash.Dash
        if proxied:
            dash_class = DashProxy
        self.app = dash_class(name, server=self.server, title=title, update_title=None,
                              assets_folder=os.path.join(os.path.dirname(__file__), 'assets'),
                              external_stylesheets=stylesheets, external_scripts=external_scripts,
                              use_pages=pages, pages_folder=pages_dir,
                              prevent_initial_callbacks=True, suppress_callback_exceptions=True)

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
                                   loop=self.ws_loop, logger=logger):
            print(' * Serving websockets at ws://%s:%d' % (self.server_address[0], self.ws_port))
            await self.ws_stop

    async def _websocket_handler(self, websocket: WebSocketServerProtocol, path: str):
        async for message in websocket:
            if message == 'connect':
                self.ws_clients.append(websocket)
            elif message == 'disconnect':
                self.ws_clients.remove(websocket)
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
                    for client in self.ws_clients:
                        await client.send(message)
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

    def clientside_callback(self, clientside_function, *args, **kwargs):
        return self.app.clientside_callback(clientside_function, *args, **kwargs)

    def on(self, message: str, namespace: str = None):
        """Decorator for websocket event handler definitions - push from browser"""
        def decorator(funct):
            if message not in self.websocket_handlers:
                self.websocket_handlers[message] = []
            self.websocket_handlers[message].append(funct)
        return decorator

    def emit(self, event: str, data: Union[str, bytes, list, dict] = None):
        message = json.dumps(dict(event=event, data=data))
        self.ws_send_queue.put(message)

    def run(self, host: str, port: int, **kwargs):
        kwargs['use_reloader'] = False  # *never* allow reloader (causes subtle bugs)
        # FIXME Ctl-C handler to call self.halt
        self.serve_websockets()
        self.app.run(host, port, **kwargs)
