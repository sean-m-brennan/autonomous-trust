#!/bin/bash
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

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
inspector_dir=$(cd $this_dir/../ && pwd)
package_dir=$inspector_dir/autonomous_trust/inspector

#if [[ "$(command -v nvm)" = "" ]]; then
#  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
#  export NVM_DIR="$HOME/.nvm"
#  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" # This loads nvm
#  [ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion
#
#  nvm install node
#  nvm use node
#fi

#if [ ! -e async_update ]; then
#  cd ..
#  cookiecutter gh:plotly/dash-component-boilerplate
#  mv async_update reactjs
# cd reactjs
#fi

if [[ "$*" = *"clean"* ]]; then
  rm -rf package-lock.json node_modules deps inst man R \
    async_update/*.js async_update/*.map async_update/*.json \
    async_update/_imports_.py async_update/[A-Z]*.py async_update/bin_data_pb2.py
  exit 0
fi
devel=false
if [[ "$*" = *"dev"* ]]; then
  devel=true
fi

npm install
if $devel; then
  npm run build:dev
else
  npm run build
fi

cd $this_dir/async_update
protoc -I=. --python_out=./ ./bin_data.proto

# Expose the built async_update Dash component package where the inspector
# imports it (dash_components/async_update; see core.py "from .async_update
# import bin_data_pb2"). The package's __init__.py serves its own JS bundle via
# _js_dist, so the JS does NOT need to live under the Dash assets_folder -- the
# whole package directory is what must be reachable.
#   -n: do not dereference an existing async_update symlink, otherwise the new
#       link would be created *inside* the previous target (nesting it). This is
#       what silently corrupted earlier runs.
cd "$package_dir/dash_components"
ln -sfn ../../../reactjs/async_update async_update

# core.py points Dash at dash_components/assets for app-level static assets
# (CSS/images). It is gitignored and may be empty, but must exist so Dash's
# assets_folder resolves cleanly.
mkdir -p "$package_dir/dash_components/assets"
#cp -r ../../../reactjs/async_update ./
