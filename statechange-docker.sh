#!/bin/sh

MNT=/tmp/mnt-$UUID

case "$1" in

create)
    mkfs.xfs $DEVICE && exec $0 open
    ;;

open)
    mkfs.xfs $DEVICE 2> /dev/null # will fail if already formatted
    mkdir -p $MNT &&
    mount -oexec,dev,discard $DEVICE $MNT &&
    rsync --chown=root:root -av --delete tmp/ $MNT
    kill -1 $PID
    ;;

close)
    echo unmounting $MNT
    umount -f $MNT && rm -rf $MNT
    kill -2 $PID
    ;;

esac
