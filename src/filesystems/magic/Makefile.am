include $(top_srcdir)/config/Makefile.rules

AM_LDFLAGS		= -lmagic -lz

noinst_LTLIBRARIES 	= magic.la
pkgpyexec_PYTHON	= magic$(PYTHON_EXTENSION)
magic_la_SOURCES	= py_magic.h magic.c
magic_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
magic_la_LDFLAGS 	= -module -lmagic -lz $(PYTHON_LDFLAGS)
