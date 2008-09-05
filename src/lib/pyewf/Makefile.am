include $(top_srcdir)/config/Makefile.rules

AM_CFLAGS		= -include config.h
AM_LDFLAGS		= -lewf -lz

if HAVE_LIBEWF
# This is for the sleuthkit python module
noinst_LTLIBRARIES 	= pyewf.la
nodist_pkgpyexec_PYTHON	= pyewf$(PYTHON_EXTENSION)

pyewf_la_SOURCES	= pyewf.c
pyewf_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
pyewf_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS) -lewf
endif