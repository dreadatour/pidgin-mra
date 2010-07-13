LINUX32_COMPILER = gcc

LIBPURPLE_CFLAGS = -I/usr/include/libpurple -DPURPLE_PLUGINS -DENABLE_NLS
GLIB_CFLAGS = -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include

#Standard stuff here
MRA_SOURCES =     \
    src/mra_net.c \
    src/libmra.c

all:	release

ifdef DESTDIR

install:
	install -d -m 0755    ${DESTDIR}/usr/local/lib/purple-2/
	install -d -m 0755    ${DESTDIR}/usr/local/share/pixmaps/pidgin/protocols/16/
	install -d -m 0755    ${DESTDIR}/usr/local/share/pixmaps/pidgin/protocols/22/
	install -d -m 0755    ${DESTDIR}/usr/local/share/pixmaps/pidgin/protocols/48/
	install libmra.so     ${DESTDIR}/usr/local/lib/purple-2/
	install img/mra16.png ${DESTDIR}/usr/local/share/pixmaps/pidgin/protocols/16/mra.png
	install img/mra22.png ${DESTDIR}/usr/local/share/pixmaps/pidgin/protocols/22/mra.png
	install img/mra48.png ${DESTDIR}/usr/local/share/pixmaps/pidgin/protocols/48/mra.png

uninstall:
	rm -f ${DESTDIR}/usr/local/lib/purple-2/libmra.so
	rm -f ${DESTDIR}/usr/local/share/pixmaps/pidgin/protocols/16/mra.png
	rm -f ${DESTDIR}/usr/local/share/pixmaps/pidgin/protocols/22/mra.png
	rm -f ${DESTDIR}/usr/local/share/pixmaps/pidgin/protocols/48/mra.png

else

install:
	install libmra.so     /usr/local/lib/purple-2/
	install img/mra16.png /usr/local/share/pixmaps/pidgin/protocols/16/mra.png
	install img/mra22.png /usr/local/share/pixmaps/pidgin/protocols/22/mra.png
	install img/mra48.png /usr/local/share/pixmaps/pidgin/protocols/48/mra.png

uninstall:
	rm -f /usr/local/lib/purple-2/libmra.so
	rm -f /usr/local/share/pixmaps/pidgin/protocols/16/mra.png
	rm -f /usr/local/share/pixmaps/pidgin/protocols/22/mra.png
	rm -f /usr/local/share/pixmaps/pidgin/protocols/48/mra.png

endif

clean:
	rm -f libmra.so

libmra.so:	${MRA_SOURCES}
	${LINUX32_COMPILER} ${LIBPURPLE_CFLAGS} -Wall -Wextra -pthread ${GLIB_CFLAGS} -I. -g3 -O2 -pipe ${MRA_SOURCES} -o libmra.so -shared -fPIC -DPIC

release:	libmra.so

