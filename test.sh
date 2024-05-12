#!/bin/sh
set -ex

rm -f *.dat

which clang-format && clang-format --style=file:clang-format.yaml --verbose -i **/*.cpp **/*.h
which cppcheck && cppcheck **/*.cpp **/*.h

make clean
make

./app -v vault.dat password author
./app -p vault.dat password newpassword
./app -p vault.dat newpassword password
./app -a vault.dat password assets/entry1
./app -a vault.dat password assets/entry2
./app -l vault.dat password
./app -d vault.dat password entry1 5b41362bc82b7f3d56edc5a306db22105707d01ff4819e26faef9724a2d406c9
./app -f vault.dat password entry1
./app -x vault.dat password

./app -v vault2.dat password2 john
./app -a vault2.dat password2 assets/entry1
./app -l vault2.dat password2

./app -c vault2.dat password2 vault3.dat
