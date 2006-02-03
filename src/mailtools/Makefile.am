PSTVER			= libpst-0.5
SUBDIRS			= $(PSTVER)

BUILT_SOURCES		= $(srcdir)/pypst_wrap.c
SWIG_SOURCES		= pypst.i

pkgpython_PYTHON 	= pypst2.py pypst.py
pkgpyexec_LTLIBRARIES 	= _pypst.la

_pypst_la_SOURCES 	= $(srcdir)/pypst_wrap.c $(SWIG_SOURCES)
_pypst_la_CPPFLAGS 	= $(SWIG_PYTHON_CPPFLAGS) -I$(srcdir)/$(PSTVER)
_pypst_la_LDFLAGS 	= -module
_pypst_la_LIBADD	= $(PSTVER)/libpst.la	

$(srcdir)/pypst_wrap.c: $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ $<

#clean-local:
#	-rm -rf pypst.py pypst_wrap.c
