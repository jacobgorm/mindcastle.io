all: build/build.ninja
	ninja -C build &&\
	ln -f -s build/oneroot oneroot

build/build.ninja:
	(mkdir -p build && cd build && cmake -G Ninja ..)

clean:
	ninja -C build clean

distclean:
	rm -rf build tags oneroot

tags:
	ctags -R *
