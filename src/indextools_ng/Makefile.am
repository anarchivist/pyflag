include $(top_srcdir)/config/Makefile.rules

noinst_LTLIBRARIES 	= index.la
nodist_pkgpyexec_PYTHON	= index$(PYTHON_EXTENSION)

noinst_HEADERS 		= trie.h 

index_la_SOURCES 	= index.c trie.c test.py
index_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
index_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS) -export-symbols-regex initindex
index_la_LIBADD		= ../lib/liboo.la $(PYTHON_EXTRA_LIBS)
