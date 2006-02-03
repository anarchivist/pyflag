bin_PROGRAMS		= pcaptool

pcaptool_SOURCES	= pcaptool.c
pcaptool_LDFLAGS	= /usr/lib/libpcap.a

pkgpython_PYTHON 	= dissect.py
pkgpyexec_LTLIBRARIES 	= _dissect.la

noinst_LTLIBRARIES	= libnetwork.la
libnetwork_la_SOURCES	= network.c
libnetwork_la_CFLAGS 	= -I$(top_srcdir)/src/include

_dissect_la_SOURCES 	= dissect.c
_dissect_la_CPPFLAGS 	= $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
_dissect_la_LDFLAGS 	= -module
_dissect_la_LIBADD	= ../lib/liboo.la libnetwork.la

include_HEADERS		= network.h

dissect.c: init.h

define build-init-deps
	$(LIBTOOL) --mode=link gcc -o libinit.la $^
	nm --defined-only .libs/libinit.a | grep __MODULE_INIT | awk '{ print "extern void "$$3"();" }' > init.h	
	nm --defined-only .libs/libinit.a | grep __MODULE_INIT | awk '{ print $$3"();" }' > init.c

endef

init.h: $(_dissect_la_LIBADD)
	$(call build-init-deps,)


clean-local:
	-rm -rf init.c init.h libinit.la
