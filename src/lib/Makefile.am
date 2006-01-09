INCLUDES        	= -I$(top_srcdir)/src/include

# main bin and lib targets
noinst_PROGRAMS		= open
bin_PROGRAMS		= sgzip evtool iowrapper remote_server
#lib_LTLIBRARIES	= libexcept.la libsgz.la libevf.la libio_hooker.la liboo.la libmd5.la

pkglib_LTLIBRARIES	= libio_hooker.la
# convenience libs: just to reduce re-building, could instead install as shared libs by 
# commenting this line out and uncommenting the one above
noinst_LTLIBRARIES	= libexcept.la libsgz.la libevf.la liboo.la libmd5.la libiosubsys.la

# Stuff that should be distributed:
include_HEADERS		= *.h

# python stuff
BUILT_SOURCES		= $(srcdir)/io_wrap.c
SWIG_SOURCES		= io.i
pkgpython_PYTHON	= iosubsys.py
pkgpyexec_LTLIBRARIES 	= _iosubsys.la

# specifics (libs)
libexcept_la_SOURCES 	= except.c

libsgz_la_SOURCES       = sgzlib.c
libsgz_la_LDFLAGS	= -lz

libevf_la_SOURCES       = libevf.c
libevf_la_LDFLAGS	= -lz

libio_hooker_la_SOURCES = hooker.c
libio_hooker_la_LDFLAGS	= -ldl
libio_hooker_la_LIBADD	= libiosubsys.la

liboo_la_SOURCES	= class.c stringio.c struct.c talloc.c packet.c misc.c

libmd5_la_SOURCES	= md5c.c 

# specifics (bins)
sgzip_LDADD             = libsgz.la libexcept.la

evtool_SOURCES		= evtool.c
evtool_LDADD		= libevf.la libsgz.la libmd5.la libexcept.la

iowrapper_SOURCES	= iowrapper.c 
iowrapper_CFLAGS	= -DPYFLAG_LIBDIR=\"$(pkglibdir)\"
iowrapper_LDADD		= libiosubsys.la libio_hooker.la

remote_server_LDADD	= libexcept.la

libiosubsys_la_SOURCES	= iosubsys.c remote_client.c
libiosubsys_la_LIBADD	= libevf.la libsgz.la libmd5.la libexcept.la

# python module specifics
_iosubsys_la_SOURCES 	= $(srcdir)/io_wrap.c $(SWIG_SOURCES)
_iosubsys_la_CPPFLAGS 	= $(SWIG_PYTHON_CPPFLAGS)
_iosubsys_la_LDFLAGS 	= -module
_iosubsys_la_LIBADD	= libiosubsys.la

$(srcdir)/io_wrap.c: $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) -o $@ $<

clean-local:
	-rm -rf iosubsys.py io_wrap.c
