#!/bin/bash

# if args are not passed
if [ $# -lt 1 ]; then
    echo "Usage: ./build-modules.sh <module1.o> <module2.o> ..."
    exit 1
fi

sudo apt install build-essential kmod linux-headers-`uname -r`

# 
# modules
#
echo "[+] Building modules... Make Sure you have placed your modules in the modules directory"
args=($@)
make -C linux-$() -j$(nproc) modules
cd modules
echo "" > Makefile
echo "obj-m =${args[*]}" >> Makefile
cat .Make >> Makefile
make -j$(nproc)
cd ..

echo "[*] cleaning up..."
rm -rf modules/.*.cmd
rm -rf modules/*.mod*
rm -rf modules/*.o
rm -rf modules/*.symvers
rm -rf modules/*.order 
 
echo "[+] Done..."