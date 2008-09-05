include $(top_srcdir)/config/Makefile.rules

if HAVE_WINDOWS
AM_LDFLAGS		= -lmagic -lz -lregex
else
AM_LDFLAGS		= -lmagic -lz
endif

noinst_LTLIBRARIES 	= magic.la
nodist_pkgpyexec_PYTHON	= magic$(PYTHON_EXTENSION)
magic_la_SOURCES	= py_magic.h magic.c
magic_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
magic_la_LDFLAGS 	= -module -lmagic -lz $(PYTHON_LDFLAGS)
