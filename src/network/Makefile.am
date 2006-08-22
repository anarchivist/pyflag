bin_PROGRAMS		= pcaptool

pcaptool_SOURCES	= pcaptool.c
pcaptool_LDFLAGS	= /usr/lib/libpcap.a
pcaptool_LDADD		= ../lib/libiosubsys/libiosubsys.la ../lib/libiosubsys/libio_hooker.la

pkgpython_PYTHON 	= dissect.py
pkgpyexec_LTLIBRARIES 	= _dissect.la reassembler.la

noinst_LTLIBRARIES	= libnetwork.la libtcp.la
libnetwork_la_SOURCES	= network.c
libnetwork_la_CFLAGS 	= -I$(top_srcdir)/src/include -D__DEBUG__
libnetwork_la_LIBADD	= ../lib/liboo.la

_dissect_la_SOURCES 	= dissect.c
_dissect_la_CPPFLAGS 	= $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include -D__DEBUG__
_dissect_la_LDFLAGS 	= -module
_dissect_la_LIBADD	= libnetwork.la

reassembler_la_SOURCES = reassembler.c
reassembler_la_CPPFLAGS= $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include -D__DEBUG__
reassembler_la_LDFLAGS = -module
reassembler_la_LIBADD  = libtcp.la libnetwork.la

libtcp_la_SOURCES	= tcp.c
libtcp_la_CPPFLAGS	= -D__DEBUG__
#libtcp_la_LIBADD	= libnetwork.la

noinst_HEADERS		= network.h tcp.h

dissect.c: init.h

define build-init-deps
	$(LIBTOOL) --mode=link --tag=CC gcc -o libinit.la $^
	nm --defined-only .libs/libinit.a | grep __MODULE_INIT | awk '{ print "extern void "$$3"();" }' > init.h	
	nm --defined-only .libs/libinit.a | grep __MODULE_INIT | awk '{ print $$3"();" }' > init.c

endef

init.h: $(_dissect_la_LIBADD)
	$(call build-init-deps,)


clean-local:
	-rm -rf init.c init.h libinit.la
