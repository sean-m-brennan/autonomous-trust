import os
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from autonomous_trust.inspector.viz.middleware import SassASGIMiddleware, _sass_available

pytestmark = pytest.mark.skipif(not _sass_available,
                                reason="libsass not available (pip install libsass)")


class TestSassASGIMiddleware:
    def _make_middleware(self):
        app = MagicMock()
        app.logger = MagicMock()
        app.asgi_app = AsyncMock()
        manifests = {}
        mw = SassASGIMiddleware(app, manifests)
        return mw

    def test_creation(self):
        mw = self._make_middleware()
        assert mw.logger is not None

    @pytest.mark.asyncio
    async def test_call_non_css(self):
        mw = self._make_middleware()
        scope = {'path': '/index.html'}
        recv = AsyncMock()
        send = AsyncMock()
        await mw(scope, recv, send)
        mw.app.assert_called_once_with(scope, recv, send)

    @pytest.mark.asyncio
    async def test_call_css_no_matching_prefix(self):
        app = MagicMock()
        app.logger = MagicMock()
        inner = AsyncMock()
        app.asgi_app = inner
        manifests = {'test': ('/tmp/scss', '/tmp/css', '/css', True)}
        mw = SassASGIMiddleware(app, manifests)
        scope = {'path': '/other/style.css'}
        recv = AsyncMock()
        send = AsyncMock()
        await mw(scope, recv, send)

    @pytest.mark.asyncio
    async def test_call_css_matching_prefix_no_sass_file(self, tmp_path):
        scss_dir = tmp_path / 'scss'
        css_dir = tmp_path / 'css'
        scss_dir.mkdir()
        css_dir.mkdir()

        app = MagicMock()
        app.logger = MagicMock()
        inner = AsyncMock()
        app.asgi_app = inner
        manifests = {'test': (str(scss_dir), str(css_dir), '/css', True)}
        mw = SassASGIMiddleware(app, manifests)
        scope = {'path': '/css/style.css'}
        recv = AsyncMock()
        send = AsyncMock()
        await mw(scope, recv, send)

    @pytest.mark.asyncio
    async def test_call_no_path_in_scope(self):
        mw = self._make_middleware()
        scope = {}
        recv = AsyncMock()
        send = AsyncMock()
        await mw(scope, recv, send)
        mw.app.assert_called_once()
