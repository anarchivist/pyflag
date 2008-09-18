AM_CFLAGS		= -include config.h

if HAVE_LIBAFFLIB
# This is for the sleuthkit python module
pkgpyexec_LTLIBRARIES 	= pyaff.la

pyaff_la_SOURCES	= pyaff.c
pyaff_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS) -DLIBAFFLIB_VERSION=@LIBAFFLIB_VERSION@
pyaff_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS) $(LDFLAGS) -L/usr/local/lib/ -lafflib
endif