PYKV?=OFF

all: build/build.ninja
	ninja -C build &&\
	ln -f -s build/mindcastle oneroot
	ln -f -s build/mindcastle mindcastle

install: build/build.ninja
	ninja -C build install

build/build.ninja:
	(mkdir -p build && cd build && cmake -G Ninja -D BUILD_PYKV=$(PYKV) ..)

clean:
	ninja -C build clean

distclean:
	rm -rf build tags oneroot mindcastle

tags:
	ctags -R *
