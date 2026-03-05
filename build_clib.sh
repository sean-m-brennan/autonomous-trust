#!/bin/sh

cd src/c || exit 1
rm -rf build
cmake -S . -B build
cd build || exit 1
make
