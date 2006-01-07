bin_PROGRAMS		= pcaptool

pcaptool_SOURCES	= pcaptool.c
pcaptool_LDFLAGS	= /usr/lib/libpcap.a


pkgpython_PYTHON 	= dissect.py
pkgpyexec_LTLIBRARIES 	= _dissect.la

_dissect_la_SOURCES 	= dissect.c network.c
_dissect_la_CPPFLAGS 	= $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
_dissect_la_LDFLAGS 	= -module
_dissect_la_LIBADD	= ../lib/liboo.la
