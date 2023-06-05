#!/bin/sh

# install dependencies in filesystem image
export SODIUM_INSTALL=system && \
. fs0/bin/activate && \
fs0/bin/python3 -m ensurepip && \
. piprc && \
fs0/bin/pip3 install -r requirements.txt

# correct import line for custom-built extension
grep -RIl "from nacl\._sodium" fs0/lib/python3.7/site-packages/nacl | \
xargs sed -i 's|from nacl\._sodium|from _sodium|g'
