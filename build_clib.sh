#!/bin/sh

cd src/c || exit 1
rm -rf build
mkdir build
cd build || exit 1
cmake ..
make
