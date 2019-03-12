#!/bin/bash

# example script that builds a docker container and exports its contents
# to a mindcastle block device, and then exports the contents of that block
# device to an object store like S3.

sudo echo building docker container || exit 1

SWAP=tmp.swap

sudo rm -rf tmp ; mkdir tmp # dir that we export container to

echo building with revisions $ONEROOTREVISION
docker rm mycontainer
docker build -t mycontainer || exit 1
echo run docker container to ready for export...
docker run --name mycontainer mycontainer /bin/true || exit 1
echo export docker container to tmp dir...
docker export mycontainer | (cd tmp; sudo tar x)
echo rm docker container
docker rm mycontainer

# now start oneroot to make rsync from tmp happen

sudo $HOME/dev/oneroot/build/oneroot $SWAP ./statechange-docker.sh || exit 1

sudo rm -rf tmp

# source the .swap file to get the UUID
source ./$SWAP || exit 1

# create mycontainer.swap with a fallback link to cloud location
SERVER=swapdata-$uuid.s3-eu-west-1.amazonaws.com
cat $SWAP >target.swap
echo cache=cache >>target.swap
echo fallback=http://$SERVER >>mycontainer.swap

# finally copy the new state to the object store in the cloud
rclone -v sync swapdata-$uuid/ s3:swapdata-$uuid
