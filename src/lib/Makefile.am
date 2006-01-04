INCLUDES        	= -I$(top_srcdir)/src/include

# main bin and lib targets
noinst_PROGRAMS		= open
bin_PROGRAMS		= sgzip evtool iowrapper remote_server
lib_LTLIBRARIES		= libio_hooker.la libsgz.la libexcept.la libevf.la

# convenience libs: just to reduce re-building
noinst_LTLIBRARIES	= libmd5.la

# specifics (libs)
libexcept_la_SOURCES 	= except.c except.h

libsgz_la_SOURCES       = sgzlib.c sgzlib.h
libsgz_la_LIBADD	= libexcept.la -lz

libevf_la_SOURCES       = libevf.c libevf.h
libevf_la_LIBADD	= libexcept.la -lz

libio_hooker_la_SOURCES = hooker.c hooker.h
libio_hooker_la_LIBADD	= libexcept.la -ldl

libmd5_la_SOURCES	= md5c.c md5.h

# specifics (bins)
sgzip_LDADD             = libsgz.la

evtool_SOURCES		= evtool.c
evtool_LDADD		= libevf.la libsgz.la libmd5.la

iowrapper_SOURCES	= iowrapper.c iosubsys.c iosubsys.h remote_client.c remote.h
iowrapper_LDADD		= libevf.la libsgz.la libmd5.la libio_hooker.la

remote_server_LDADD	= libexcept.la
