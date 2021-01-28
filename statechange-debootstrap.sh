#!/bin/sh

# example script for creating a VM or container image with debootstrap
#
# run with:
#
# $ sudo ./build/mindcastle debian.swap ./statechange-debootstrap.sh

echo $0 PID=$PID UUID=$UUID $1
MNT=/tmp/mnt-$UUID

case "$1" in

create)
    mkfs.xfs $DEVICE && exec $0 open
    ;;

open)
    (mkdir -p $MNT && mount -oexec,dev,discard $DEVICE $MNT) || (rm -rf $MNT; kill -2 $PID)
    #debootstrap --arch=arm64 stable $MNT
    debootstrap stable $MNT
    kill -1 $PID
    ;;

close)
    umount $MNT && rm -rf $MNT && kill -2 $PID
    ;;

esac
