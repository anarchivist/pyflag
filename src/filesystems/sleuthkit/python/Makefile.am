AM_CFLAGS		= -I$(top_srcdir)/src/include -I../sleuthkit-2.52 -include config.h

# This is for the sleuthkit python module
pkgpyexec_LTLIBRARIES 	= sk.la
noinst_HEADERS  = $(srcdir)/*.h

sk_la_SOURCES	= sk.c
sk_la_LIBADD	= ../sleuthkit-2.52/tsk/libtsk-pf.la ../../../lib/liboo.la
sk_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
sk_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS)
