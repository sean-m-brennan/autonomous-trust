#!/bin/bash

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
src_dirs="${this_dir}/../src/autonomous-trust ${this_dir}/../src/autonomous-trust-inspector"

for dir in $src_dirs; do
    tox --conf $dir/tox.ini
done
