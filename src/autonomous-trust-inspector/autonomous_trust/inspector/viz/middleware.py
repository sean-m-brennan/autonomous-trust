# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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
from sassutils.wsgi import SassMiddleware
from sass import CompileError


class SassASGIMiddleware(SassMiddleware):
    def __init__(self, app, manifests, package_dir=None, error_status='200 OK'):
        if package_dir is None:
            package_dir = {}
        self.logger = app.logger  # noqa
        super().__init__(app.asgi_app, manifests, package_dir, error_status)  # noqa

    async def __call__(self, scope, recv, send):  # noqa
        path = scope.get('path', '/')
        if path.endswith('.css'):
            for prefix, package_dir, manifest in self.paths:
                if not path.startswith(prefix):
                    continue
                css_filename = path[len(prefix):]
                sass_filename = manifest.unresolve_filename(package_dir, css_filename)
                src_dir = manifest.sass_path
                if not os.path.isabs(manifest.sass_path):
                    src_dir = os.path.join(package_dir, manifest.sass_path)
                if not os.path.exists(os.path.join(src_dir, sass_filename)):
                    continue
                tgt_dir = manifest.css_path
                if not os.path.isabs(manifest.css_path):
                    tgt_dir = os.path.join(package_dir, manifest.css_path)
                css_path = os.path.join(tgt_dir, css_filename)
                try:
                    self.logger.info('Compile %s' % os.path.join(src_dir, sass_filename))
                    manifest.build_one(os.path.dirname(src_dir), sass_filename, source_map=True)
                except (IOError, OSError) as err:
                    self.logger.error(str(err))
                    break
                except CompileError as err:
                    self.logger.error(str(err))
                    os.remove(css_path)
        return await self.app(scope, recv, send)
