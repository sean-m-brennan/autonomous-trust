# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

try:
    import sass
    _sass_available = True
except ImportError:
    _sass_available = False


class SassASGIMiddleware:
    """ASGI middleware that compiles SCSS to CSS on the fly using libsass.

    Args:
        app: The Quart/ASGI application.
        manifests: Dict mapping name to (scss_dir, css_dir, url_prefix, strip_ext).
    """

    def __init__(self, app, manifests, package_dir=None, error_status='200 OK'):
        if not _sass_available:
            raise ImportError("sass module is required for SassASGIMiddleware (pip install libsass)")
        self.app = app.asgi_app
        self.logger = app.logger
        self.paths = []
        for name, manifest in manifests.items():
            scss_dir, css_dir, url_prefix, strip_ext = manifest
            self.paths.append((url_prefix, scss_dir, css_dir, strip_ext))

    async def __call__(self, scope, recv, send):
        path = scope.get('path', '/')
        if path.endswith('.css'):
            for url_prefix, scss_dir, css_dir, strip_ext in self.paths:
                if not path.startswith(url_prefix):
                    continue
                css_filename = path[len(url_prefix):]
                if css_filename.startswith('/'):
                    css_filename = css_filename[1:]
                # Derive the .scss source filename from the .css request
                sass_filename = css_filename[:-4] + '.scss'
                sass_path = os.path.join(scss_dir, sass_filename)
                if not os.path.exists(sass_path):
                    continue
                css_path = os.path.join(css_dir, css_filename)
                try:
                    self.logger.info(f'Compile {sass_path}')
                    result = sass.compile(
                        filename=sass_path,
                        output_style='nested',
                        source_map_filename=css_path + '.map',
                    )
                    os.makedirs(os.path.dirname(css_path), exist_ok=True)
                    with open(css_path, 'w') as f:
                        f.write(result)
                except (IOError, OSError) as err:
                    self.logger.error(str(err))
                    break
                except sass.CompileError as err:
                    self.logger.error(str(err))
                    if os.path.exists(css_path):
                        os.remove(css_path)
        return await self.app(scope, recv, send)
