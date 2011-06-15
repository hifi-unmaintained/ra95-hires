CC=i586-mingw32msvc-gcc
CFLAGS=-O2 -s -Wall -D_DEBUG
WINDRES=i586-mingw32msvc-windres
REV=$(shell sh -c 'git rev-parse --short @{0}')

all: launcher

launcher: src/launcher.c
	$(CC) $(CFLAGS) -mwindows -Wl,--enable-stdcall-fixup -s -o ra95-hires.exe src/launcher.c

clean:
	rm -f ra95-hires.exe
