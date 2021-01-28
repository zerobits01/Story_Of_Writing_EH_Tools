#!/usr/bin/env bash

# This script was written for and works on Mac OS X
# I have to use sudo to run arping on Mac OS X
# I believe the options for arping on linux are a little different. I believe you use -D for duplicate IP detection instead of -d but that's from memory and you should check.

echo "Starting duplicate IP detection with sudo arping!"
for i in {100..254};
do
sudo arping -q -d -c 2 192.168.1.$i; [ $? -ne 0 ] && echo "192.168.1.$i duplicate"; 
done
