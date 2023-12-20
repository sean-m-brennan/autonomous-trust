#!/bin/bash

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

cd $package_dir/dash_components/assets
if $devel; then
  ln -sf ../../../../reactjs/async_update/async_update.dev.js
  ln -sf ../../../../reactjs/async_update/async_update.dev.js.map
else
  ln -sf ../../../../reactjs/async_update/async_update.min.js
  ln -sf ../../../../reactjs/async_update/async_update.min.js.map
fi
cd ..
ln -sf ../../../reactjs/async_update
