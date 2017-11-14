sudo apt-get -y install cmake ninja-build liblz4-dev libb2-dev  libcurl4-gnutls-dev uuid-dev
https://storage.googleapis.com/coqni/top.lvl

mkdir -p dev &&\
cd dev &&\
git clone https://jacobgorm@bitbucket.org/jacobgorm/oneroot.git &&\
cd oneroot && \
make

mkdir -p swapdata-2cde296d-1900-45e3-857d-0a3cfb42ae87
(cd swapdata-2cde296d-1900-45e3-857d-0a3cfb42ae87; wget https://storage.googleapis.com/coqni/top.lvl)

echo >foo.swap 'uuid=2cde296d-1900-45e3-857d-0a3cfb42ae87'
echo >>foo.swap 'size=104857600'
echo >>foo.swap 'fallback=https://s3-eu-west-1.amazonaws.com/coqni'
echo >>foo.swap 'fallback=https://storage.googleapis.com/coqni'

sudo modprobe nbd
sudo ./build/oneroot foo.swap
