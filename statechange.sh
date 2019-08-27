#!/bin/sh

# This script is triggered after device create, open, and before close.
# It interacts with the nbd.c server by means of signals:
#  signal 1 (SIGHUP) : trigger close
#  signal 2 (SIGINT) : trigger clean exit
#
# If you need to create open a device, then load some files into it, and
# then flush and close, you can put this functionality in the open) handler,
# and finalize by sending SIGHUP to $PID.

echo $0 DEVICE=$DEVICE PID=$PID UUID=$UUID $1
MNT=/tmp/mnt-$UUID

case "$1" in

create)
    mkfs.xfs $DEVICE && exec $0 open
    ;;

open)
    (mkdir -p $MNT && mount -osync $DEVICE $MNT) || (rm -rf $MNT; kill -2 $PID)
    ;;

close)
    umount $MNT && rm -rf $MNT && kill -2 $PID
    ;;

esac
