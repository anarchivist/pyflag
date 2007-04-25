SUBDIRS		= . libewf libiosubsys libsgzip

INCLUDES        	= -I$(top_srcdir)/src/include -include config.h 

# main bin and lib targets
#noinst_PROGRAMS		= open
bin_PROGRAMS		= sgzip evtool remote_server
#lib_LTLIBRARIES	= libexcept.la libsgz.la libevf.la libio_hooker.la liboo.la libmd5.la

# convenience libs: just to reduce re-building, could instead install as shared libs by 
# commenting this line out and uncommenting the one above
noinst_LTLIBRARIES	= libexcept.la libsgz.la libevf.la liboo.la libmd5.la

# Stuff that should be distributed:
noinst_HEADERS		= $(srcdir)/*.h

# python stuff
pkgpyexec_LTLIBRARIES 	= pypacket.la

pypacket_la_SOURCES	= pypacket.c
pypacket_la_CPPFLAGS	= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
pypacket_la_LDFLAGS	= -module
pypacket_la_LIBADD	= liboo.la

# specifics (libs)
libexcept_la_SOURCES 	= except.c

libsgz_la_SOURCES       = sgzlib.c
libsgz_la_LDFLAGS	= -lz

# to be deprecated as soon an libewf can recover from errors.
libevf_la_SOURCES       = libevf.c
libevf_la_LDFLAGS	= -lz

liboo_la_SOURCES	= class.c stringio.c struct.c talloc.c packet.c misc.c
liboo_la_CPPFLAGS 	= -DHAVE_VA_COPY

libmd5_la_SOURCES	= md5c.c 

# specifics (bins)
sgzip_LDADD             = libsgz.la libexcept.la

evtool_SOURCES		= evtool.c
evtool_LDADD		= libevf.la libsgz.la libmd5.la libexcept.la

remote_server_LDADD	= libexcept.la

## Deprecated
#libiosubsys_la_SOURCES	= iosubsys.c remote_client.c
#libiosubsys_la_LIBADD	= libevf.la libsgz.la libmd5.la libexcept.la

# python module specifics
#iosubsys_la_SOURCES 	= $(srcdir)/io.c
#iosubsys_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
#iosubsys_la_LDFLAGS 	= -module
#iosubsys_la_LIBADD	= libiosubsys.la
