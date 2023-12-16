#!/bin/bash

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

npm install
npm run build
