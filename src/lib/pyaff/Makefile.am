include $(top_srcdir)/config/Makefile.rules

AM_CFLAGS		= -include config.h
AM_LDFLAGS		= -lafflib -lz -lcrypto -lstdc++

if HAVE_LIBAFFLIB
# This is for the sleuthkit python module
noinst_LTLIBRARIES 	= pyaff.la
nodist_pkgpyexec_PYTHON = pyaff$(PYTHON_EXTENSION)

pyaff_la_SOURCES	= pyaff.c
pyaff_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS) -DLIBAFFLIB_VERSION=@LIBAFFLIB_VERSION@
pyaff_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS) $(LDFLAGS) -L/usr/local/lib/ -lafflib
endif