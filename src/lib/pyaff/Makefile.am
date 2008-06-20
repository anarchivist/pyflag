AM_CFLAGS		= -include config.h

# This is for the sleuthkit python module
pkgpyexec_LTLIBRARIES 	= pyaff.la

pyaff_la_SOURCES	= pyaff.c
pyaff_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
pyaff_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS) -lafflib
