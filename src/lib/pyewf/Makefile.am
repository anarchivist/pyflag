AM_CFLAGS		= -include config.h

# This is for the sleuthkit python module
pkgpyexec_LTLIBRARIES 	= pyewf.la

pyewf_la_SOURCES	= pyewf.c
pyewf_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
pyewf_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS) -lewf
