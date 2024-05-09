#!/bin/sh
set -ex

clang-format --style=file:clang-format.yaml --verbose -i **/*.cpp
clang-format --style=file:clang-format.yaml --verbose -i **/*.h
cppcheck **/*.cpp
cppcheck **/*.h

make

