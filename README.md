# Welcome to Mindcastle.io

This repository contains the Mindcastle.io (formerly mindcastle) distributed block
device, whose aim is to eventually become the 'git for storage'. It is
currently mostly useful for local use, and for creating locally writable mounts that
can be exported simply by placing the chunked files it creates on an HTTP
somewhere, for instance on S3 or Google Storage. It supports fetching remote
objects on demand, but currently you have to push them to the cloud or your own
HTTP server, e.g, using a tool like rclone or rsync. The block devices operates
over a compressed and encrypted database-like structure, somewhat similar to
LevelDB or RocksDB, but optimized for block storage. The code was forked from
Bromium's internal ".swap" storage engine, which is the storage component of
that company's ground-breaking micro-virtualization security technology, and
has (anecdotally) been used to launch more VMs than Amazon AWS. Today, development
is sponsored by Vertigo.ai, and the main developer is Jacob Gorm Hansen, who also
led the work at Bromium.

## Building

To build on debian/ubuntu, you need to install:

* cmake
* ninja-build
* liblz4-dev
* libcurl4-gnutls-dev (or other libcurl-dev package)
* uuid-dev
* libssl-dev

And to run well you should have an entropy gathering service like rng-tools
or haveged installed and running.

To run with the example scripts you also need to install:
* xfsprogs

Then you can build with:

```bash
make
```
All that make does here is act as a think wrapper around the usual cmake and ninja dance, 
so feel free to use that instead if you prefer.

## Running

You can run mindcastle's NBD backend with (must be root, prefix with sudo as necessary):

```bash
modprobe nbd
build/mindcastle mydisk.swap ./statechange.sh
```

mindcastle implements a user-space block device on top of Linux' nbd module.  The
mydisk.swap file is a tiny meta-data text file that will be created if not
there already. The actual disk contents will go inside a directory called
swapdata-UUID, where UUID gets randomly generated. As long as mindcastle is
running, you now have an empty block device that you can format and use
as any other block device. (To not have to do this manually each time, the
script "statechange.sh" takes care to do this automically, you can edit the
script to choose the type of filesystem or perform automated tasks on, e.g,
automatically syncing files to the file system and then unmounting it when done.)

Please note the it needs to be resolvable in your $PATH, which is why it is
shown prefixed with ./ above.

If you peek inside swapdata-UUID, you will see a lot of regularly-sized files.
The file names are derived from the sha512 hashes (but shortened to 256 bits
for your sanity) of the file contents, as you can verify by running the
'sha512' tool against one of them (the hashes get truncated at 256 bits when
used for filenames). If you wanted to publish it on an HTTP server, say running
out of /srv/http, you would do something line this (assuming the HTTP server
serves files out /srv/http and there is a http user on the system that the
server is running as):

```bash
cp -r swapdata-UUID /srv/http
chown -R http /srv/http/swapdata-UUID 
```

Then, to be able to mount HTTP-repo from another host, you would copy and edit
mydisk.swap to look something like this:

```
uuid=cc3e3ede-9e75-4b41-8405-8f9f1c6b8473
size=104857600
key=cbb912b197d406ec178aa1c4ac3366c2c8652f169430e64d3393b2ba428fd52c
snapshot=ce7804a3803912e552a83280d3a6191c4d44f5c5c88c30a062845c2222a8c5a3:327680
snaphash=6a0574d06f0e6f967635b0e0737f9c88

fallback=http://myhostname/swapdata-cc3e3ede-9e75-4b41-8405-8f9f1c6b8473
```

Here, we added the `fallback=` line to point to the location of the HTTP
server acting as the storage backend.

Then, on the client machine, you could connect the block device with:

```bash
build/mindcastle mydisk.swap ./statechange.sh
```

Where "./statechange.sh" is the path to the default statechange script, which will
format the volume if necessary, and mount and later unmount it under
/tmp/mnt-UUID. The script interacts with the mindcastle process using signals,
and the user can do this too. For example, to trigger a clean unmount and
shutdown, just do a

```bash
kill -1 PID
```

Where PID is that of the first mindcastle process, you should see this logged
by the script on startup. See the statechange.sh script comments for more
details.

## Using with docker

We normally use mindcastle as for broadcasting VMs or container images authored
using docker. Please see the example script dockerexport.sh and the
statechange-docker.sh script that we use as a template when building and
exporting a docker image to mindcastle.
