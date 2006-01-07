BUILT_SOURCES		= $(srcdir)/clamav_wrap.c
SWIG_SOURCES		= clamav.i

nodist_pkgpython_PYTHON	= clamav.py
pkgpyexec_LTLIBRARIES 	= _clamav.la

_clamav_la_SOURCES 	= $(srcdir)/clamav_wrap.c $(SWIG_SOURCES)
_clamav_la_CPPFLAGS 	= $(SWIG_PYTHON_CPPFLAGS)
_clamav_la_CFLAGS	= $(libclamav_CFLAGS)
_clamav_la_LDFLAGS 	= -module $(libclamav_LIBS)

$(srcdir)/clamav_wrap.c: $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ $<

clean-local:
	-rm -rf clamav.py clamav_wrap.c
