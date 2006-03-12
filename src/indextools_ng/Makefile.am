##pkgpython_PYTHON	= index.la
pkgpyexec_LTLIBRARIES 	= index.la

index_la_SOURCES 	= index.c trie.c
index_la_CPPFLAGS 	= $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
index_la_LDFLAGS 	= -module
index_la_LIBADD	= ../lib/liboo.la
