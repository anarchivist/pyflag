bin_PROGRAMS		= pcaptool

pcaptool_SOURCES	= pcaptool.c
pcaptool_LDFLAGS	= /usr/lib/libpcap.a

pkgpython_PYTHON 	= dissect.py
pkgpyexec_LTLIBRARIES 	= _dissect.la

noinst_LTLIBRARIES	= libnetwork.la
libnetwork_la_SOURCES	= network.c network.h
libnetwork_la_CFLAGS 	= -I$(top_srcdir)/src/include

#nodist__dissect_la_SOURCES = init.h
_dissect_la_SOURCES 	= dissect.c init.h \
			../include/class.h ../include/list.h ../include/misc.h \
			../include/packet.h ../include/stringio.h ../include/struct.h \
			../include/talloc.h
_dissect_la_CPPFLAGS 	= $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
_dissect_la_LDFLAGS 	= -module
_dissect_la_LIBADD	= ../lib/liboo.la libnetwork.la

# this is pretty nasty
init.h:	init.c
	nm --defined-only ../lib/.libs/liboo.a .libs/libnetwork.a | grep __MODULE_INIT | awk '{ print "extern void "$$3"();" }' > init.h

init.c:
	nm --defined-only ../lib/.libs/liboo.a .libs/libnetwork.a | grep __MODULE_INIT | awk '{ print $$3"();" }' > init.c

clean-local:
	-rm -rf init.c init.h
