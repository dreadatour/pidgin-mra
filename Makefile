LINUX32_COMPILER = gcc

LIBPURPLE_CFLAGS = -I/usr/include/libpurple -DPURPLE_PLUGINS -DENABLE_NLS
GLIB_CFLAGS = -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include

#Standard stuff here
MRA_SOURCES =     \
    src/mra_net.c \
    src/libmra.c

all:	release

install:
	cp libmra.so /usr/lib/purple-2/
	cp img/mra16.png /usr/share/pixmaps/pidgin/protocols/16/mra.png
	cp img/mra22.png /usr/share/pixmaps/pidgin/protocols/22/mra.png
	cp img/mra48.png /usr/share/pixmaps/pidgin/protocols/48/mra.png

uninstall:
	rm -f /usr/lib/purple-2/libmra.so
	rm -f /usr/share/pixmaps/pidgin/protocols/16/mra.png
	rm -f /usr/share/pixmaps/pidgin/protocols/22/mra.png
	rm -f /usr/share/pixmaps/pidgin/protocols/48/mra.png

clean:
	rm -f libmra.so

libmra.so:	src/libmra.c
	${LINUX32_COMPILER} ${LIBPURPLE_CFLAGS} -Wall -Wextra -pthread ${GLIB_CFLAGS} -I. -g -O2 -pipe ${MRA_SOURCES} -o libmra.so -shared -fPIC -DPIC

release:	libmra.so

