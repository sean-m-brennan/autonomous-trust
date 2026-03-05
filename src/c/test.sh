#!/bin/bash

# Run everything relative to this script
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$here" || exit 1


rm -rf build
cmake -S . -B build
cd build && make && make test
