LIBDIR ?= /usr/lib
DATADIR ?= /usr/share
LINUX_COMPILER = gcc

LIBPURPLE_CFLAGS = -I/usr/include/libpurple -DPURPLE_PLUGINS -DENABLE_NLS
GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0)

#Standard stuff here
MRA_SOURCES =     \
    src/mra_net.c \
    src/libmra.c

all:	release

ifdef DESTDIR

install:
	install -d -m 0755    ${DESTDIR}${LIBDIR}/purple-2/
	install -d -m 0755    ${DESTDIR}${DATADIR}/pixmaps/pidgin/protocols/16/
	install -d -m 0755    ${DESTDIR}${DATADIR}/pixmaps/pidgin/protocols/22/
	install -d -m 0755    ${DESTDIR}${DATADIR}/pixmaps/pidgin/protocols/48/
	install libmra.so     ${DESTDIR}${LIBDIR}/purple-2/
	install img/mra16.png ${DESTDIR}${DATADIR}/pixmaps/pidgin/protocols/16/mra.png
	install img/mra22.png ${DESTDIR}${DATADIR}/pixmaps/pidgin/protocols/22/mra.png
	install img/mra48.png ${DESTDIR}${DATADIR}/pixmaps/pidgin/protocols/48/mra.png

uninstall:
	rm -f ${DESTDIR}${LIBDIR}/purple-2/libmra.so
	rm -f ${DESTDIR}${DATADIR}/pixmaps/pidgin/protocols/16/mra.png
	rm -f ${DESTDIR}${DATADIR}/pixmaps/pidgin/protocols/22/mra.png
	rm -f ${DESTDIR}${DATADIR}/pixmaps/pidgin/protocols/48/mra.png

else

install:
	install libmra.so     ${LIBDIR}/purple-2/
	install img/mra16.png ${DATADIR}/pixmaps/pidgin/protocols/16/mra.png
	install img/mra22.png ${DATADIR}/pixmaps/pidgin/protocols/22/mra.png
	install img/mra48.png ${DATADIR}/pixmaps/pidgin/protocols/48/mra.png

uninstall:
	rm -f ${LIBDIR}/purple-2/libmra.so
	rm -f ${DATADIR}/pixmaps/pidgin/protocols/16/mra.png
	rm -f ${DATADIR}/pixmaps/pidgin/protocols/22/mra.png
	rm -f ${DATADIR}/pixmaps/pidgin/protocols/48/mra.png

endif

clean:
	rm -f libmra.so

libmra.so:	${MRA_SOURCES}
	${LINUX_COMPILER} ${LIBPURPLE_CFLAGS} -Wall -Wextra -pthread ${GLIB_CFLAGS} -I. -g3 -O2 -pipe ${MRA_SOURCES} -o libmra.so -shared -fPIC -DPIC

release:	libmra.so

