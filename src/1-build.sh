#!/bin/bash
echo "start build..."
cd build
echo "current build dir: $(pwd)"
make clean 
cmake .. -DCMAKE_INSTALL_PREFIX=../output
make
make install
echo "end build..."

echo "start copy file..."
#scp $(pwd)/../output/bin/wifiDemo  leagsoft@10.10.22.43:/home/leagsoft/lus/wifi

echo "end copy file..."