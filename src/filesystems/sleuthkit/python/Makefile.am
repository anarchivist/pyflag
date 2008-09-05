include $(top_srcdir)/config/Makefile.rules

AM_CFLAGS		= -I$(top_srcdir)/src/include -I../sleuthkit-2.52 -include config.h
AM_LDFLAGS		= ../sleuthkit-2.52/tsk/.libs/libtsk-pf.a ../../../lib/.libs/liboo.a

# This is for the sleuthkit python module
noinst_LTLIBRARIES 	= sk.la
nodist_pkgpyexec_PYTHON	= sk$(PYTHON_EXTENSION)
noinst_HEADERS  = $(srcdir)/*.h

sk_la_SOURCES	= sk.c
sk_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
sk_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS)
