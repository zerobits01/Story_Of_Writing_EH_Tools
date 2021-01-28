#!/bin/bash

IPS1=`ip a | grep inet | grep -v inet6 | grep -v 127.0.0.1 | grep wlan0 | awk '{print $2}' | cut -d '/' -f1`
OUTPUT="/tmp/duplicate_ip"

rm -f $OUTPUT

for i in $IPS1;
        do
                arping -q -D -I wlan0 -c 2 $i
                echo wlan0 $i $? >> $OUTPUT
        done

DUPIP=`awk '$3 == "1" { print $0 }' $OUTPUT`

if [ -z "$DUPIP" ]
then
        echo OK: No duplicate IP found
        exit 0
else
        echo CRITICAL: Duplicate IP found: $DUPIP
        exit 2
fi

# arping -c 1 $DUPIP

# sudo arping -c 5 192.168.1.128
