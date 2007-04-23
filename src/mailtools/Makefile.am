pkgpyexec_LTLIBRARIES 	= pst.la
noinst_HEADERS 		= libpst.h

pst_la_SOURCES		= libpst.c pst.c timeconv.c
pst_la_CPPFLAGS 	= $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
pst_la_LDFLAGS 		= -module
pst_la_LIBADD		= ../lib/liboo.la

