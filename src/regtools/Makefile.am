include $(top_srcdir)/config/Makefile.rules

if !HAVE_WINDOWS
bin_PROGRAMS	= reglookup
nodist_pkgpyexec_PYTHON = pyregistry$(PYTHON_EXTENSION)
endif

noinst_LTLIBRARIES      = libreg.la pyregistry.la

libreg_la_SOURCES   = lru_cache.c range_list.c regfi.c smb_deps.c void_stack.c
libreg_la_LIBADD  = ../lib/liboo.la -lm

pyregistry_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
pyregistry_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS) -export-symbols-regex initindex
pyregistry_la_LIBADD	= ../lib/liboo.la $(PYTHON_EXTRA_LIBS) libreg.la

reglookup_SOURCES = reglookup.c 
reglookup_LDADD  = ../lib/liboo.la -lm libreg.la

noinst_HEADERS = $(srcdir)/*.h

