#!/bin/sh
set -ex

which clang-format || sudo apt install -y clang-format
which cppcheck || sudo apt install -y cppcheck

clang-format --style=file:clang-format.yaml --verbose -i **/*.cpp **/*.h

cppcheck **/*.cpp **/*.h

make

