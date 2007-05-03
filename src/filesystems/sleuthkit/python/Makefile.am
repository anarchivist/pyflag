AM_CFLAGS		= -I$(srcdir)/../auxtools -I$(srcdir)/../imgtools -I$(srcdir)/../mmtools -I$(srcdir)/../fstools -I$(top_srcdir)/src/include -DLINUX2 -include config.h 

# This is for the sleuthkit python module
pkgpyexec_LTLIBRARIES 	= sk.la
noinst_HEADERS  = $(srcdir)/*.h

sk_la_SOURCES	= sk.c
sk_la_LIBADD	= ../fstools/libfstools.la
sk_la_CPPFLAGS 	= $(PYTHON_CSPEC)
sk_la_LDFLAGS 	= -module $(PYTHON_LSPEC)
