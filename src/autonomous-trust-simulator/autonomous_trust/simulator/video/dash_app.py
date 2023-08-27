import asyncio
import base64
import dash
import cv2
import dash_html_components as html
import threading

from dash.dependencies import Output, Input
from quart import Quart, websocket
from dash_extensions import WebSocket

from client import Video


server = Quart(__name__)


@server.websocket("/stream")
async def stream():
    vid = Video(size=800, server_ip='127.0.1.1')
    while True:
        frame, pause = vid.get_frame()
        await websocket.send(f"data:image/jpeg;base64, {base64.b64encode(frame).decode()}")
        if pause is not None:
            await asyncio.sleep(pause)


# Create small Dash application for UI.
app = dash.Dash(__name__)
app.layout = html.Div([
    html.Img(style={'width': '40%', 'padding': 10}, id="video"),
    WebSocket(url=f"ws://127.0.0.1:5000/stream", id="ws")
])
# Copy data from websocket to Img element.
app.clientside_callback("function(m){return m? m.data : '';}", Output(f"video", "src"), Input(f"ws", "message"))

if __name__ == '__main__':
    threading.Thread(target=app.run_server).start()
    server.run()
