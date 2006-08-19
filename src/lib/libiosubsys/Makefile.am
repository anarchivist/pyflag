INCLUDES        	= -I$(top_srcdir)/src/include -include config.h 

noinst_LTLIBRARIES	= libiosubsys.la
noinst_PROGRAMS		= test

# python stuff
pkgpyexec_LTLIBRARIES 	= iosubsys.la

libiosubsys_la_SOURCES     = libiosubsys.c
libiosubsys_la_LIBADD       = ../liboo.la ../libsgz.la ../libexcept.la ../libewf/libewf.la

# python module specifics
iosubsys_la_SOURCES 	= iosubsys.c
iosubsys_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
iosubsys_la_LDFLAGS 	= -module
iosubsys_la_LIBADD	                  = libiosubsys.la 

test_SOURCES		= test.c
test_LDADD		= libiosubsys.la