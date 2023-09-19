from enum import Enum, auto

from dash import html, Dash
from dash_iconify import DashIconify
from flask import Flask


class IconSize(Enum):
    SMALL = auto()
    MEDIUM = auto()
    LARGE = auto()


def make_icon(icon_name: str, text: str = None, color: str = None, size: IconSize = IconSize.MEDIUM):
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
            html.Br(), html.Div(text, style={'font-size': font_size})]


class DashComponent(object):
    def __init__(self, app: Dash, server: Flask = None):
        self.app = app  # for callbacks
        self.server = server  # for URL registration
        if server is None:
            self.server = self.app.server

    def div(self, *args, **kwargs) -> html.Div:
        raise NotImplementedError
