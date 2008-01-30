INCLUDES        	= -I$(top_srcdir)/src/include -include config.h 

noinst_LTLIBRARIES	= libiosubsys.la
noinst_PROGRAMS		= test
noinst_HEADERS  = $(srcdir)/*.h

#bin_PROGRAMS		= iowrapper
#pkglib_LTLIBRARIES	= libio_hooker.la

#libio_hooker_la_SOURCES = hooker.c
#libio_hooker_la_LDFLAGS	= -ldl
#libio_hooker_la_LIBADD	= libiosubsys.la

#iowrapper_SOURCES	= iowrapper.c 
#iowrapper_CFLAGS	= -DPYFLAG_LIBDIR=\"$(pkglibdir)\"
#iowrapper_LDADD		= libiosubsys.la libio_hooker.la

# python stuff
pkgpyexec_LTLIBRARIES 	= iosubsys.la

libiosubsys_la_SOURCES     = libiosubsys.c
libiosubsys_la_LIBADD      = ../liboo.la ../libsgz.la ../libexcept.la ../libewf/libewf.la

# python module specifics
iosubsys_la_SOURCES 	= iosubsys.c
iosubsys_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
iosubsys_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS)
iosubsys_la_LIBADD      = libiosubsys.la 

test_SOURCES		= test.c
test_LDADD   		= libiosubsys.la
