#!/bin/bash
set -e

export SDK_PATH=$(dirname $(pwd))

echo "based on make_lib.sh version 20150924"
echo "SDK_PATH:"
echo "$SDK_PATH"
echo ""

if [ -e $SDK_PATH/include/hkc.h ]; then
    mv $SDK_PATH/include/hkc.h $SDK_PATH/include/hkc.h.previous
fi
cd hkc
make clean
make
cp .output/eagle/debug/lib/libhkc.a $SDK_PATH/lib/libhkc.a
xtensa-lx106-elf-strip --strip-unneeded $SDK_PATH/lib/libhkc.a
cp include/hkc.h $SDK_PATH/include/hkc.h

echo ""
echo "########## success ###########"
echo "deployed lib/libhkc.a and include/hkc.h"

cd ..
