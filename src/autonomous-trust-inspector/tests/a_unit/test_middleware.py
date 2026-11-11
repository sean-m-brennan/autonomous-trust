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

    @pytest.mark.asyncio
    async def test_call_css_compiles_scss_with_source_map(self, tmp_path):
        # libsass returns (css, map) when a source map is requested; both
        # must be written out as text, and the request passed through.
        scss_dir = tmp_path / 'scss'
        css_dir = tmp_path / 'css'
        scss_dir.mkdir()
        (scss_dir / 'style.scss').write_text('$c: #123456;\nbody { color: $c; }\n')

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

        css = (css_dir / 'style.css').read_text()
        assert '#123456' in css
        assert 'sourceMappingURL=style.css.map' in css
        assert '"sources"' in (css_dir / 'style.css.map').read_text()
        inner.assert_called_once_with(scope, recv, send)
