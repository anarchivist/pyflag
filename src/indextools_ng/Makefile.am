##pkgpython_PYTHON	= index.la
pkgpyexec_LTLIBRARIES 	= index.la

noinst_HEADERS = trie.h 

index_la_SOURCES 	= index.c trie.c test.py
index_la_CPPFLAGS 	= $(PYTHON_CSPEC) -I$(top_srcdir)/src/include
index_la_LDFLAGS 	= -module $(PYTHON_LSPEC)
index_la_LIBADD	= ../lib/liboo.la
