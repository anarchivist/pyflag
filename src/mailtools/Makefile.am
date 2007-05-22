pkgpyexec_LTLIBRARIES 	= pst.la
noinst_HEADERS 		= libpst.h libstrfunc.h timeconv.h common.h

pst_la_SOURCES		= libpst.c pst.c timeconv.c libstrfunc.h timeconv.h common.h
pst_la_CPPFLAGS 	= $(PYTHON_CSPEC) -I$(top_srcdir)/src/include
pst_la_LDFLAGS 		= -module $(PYTHON_LSPEC)
pst_la_LIBADD		= ../lib/liboo.la

