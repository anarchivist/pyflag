BUILT_SOURCES		= $(srcdir)/index_wrap.c
SWIG_SOURCES		= index.i

pkgpython_PYTHON	= index.py
pkgpyexec_LTLIBRARIES 	= _index.la

_index_la_SOURCES 	= $(srcdir)/index_wrap.c $(SWIG_SOURCES) index.c
_index_la_CPPFLAGS 	= $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
_index_la_LDFLAGS 	= -module
_index_la_LIBADD	= ../lib/libexcept.la

$(srcdir)/index_wrap.c: $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ $<

clean-local:
	-rm -rf index.py index_wrap.c
