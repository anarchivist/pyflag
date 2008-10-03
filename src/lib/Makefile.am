include $(top_srcdir)/config/Makefile.rules

SUBDIRS		= . pyewf pyaff

INCLUDES        	= -I$(top_srcdir)/src/include -include config.h

# main bin and lib targets
#noinst_PROGRAMS		= open
bin_PROGRAMS		= sgzip evtool

# Stuff that should be distributed:
noinst_HEADERS		= $(srcdir)/*.h

# python stuff
noinst_LTLIBRARIES 	= liboo.la libexcept.la libsgz.la libevf.la libmd5.la pypacket.la pyxpress.la
nodist_pkgpyexec_PYTHON	= pypacket$(PYTHON_EXTENSION) pyxpress$(PYTHON_EXTENSION)

pypacket_la_SOURCES	= pypacket.c
pypacket_la_CPPFLAGS	= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
pypacket_la_LDFLAGS	= -module $(PYTHON_LDFLAGS)
pypacket_la_LIBADD	= liboo.la

pyxpress_la_SOURCES	= pyxpress.c
pyxpress_la_CPPFLAGS	= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
pyxpress_la_LDFLAGS	= -module $(PYTHON_LDFLAGS)

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
#libsha1_la_SOURCES	= sha1.c

# specifics (bins)
sgzip_LDADD             = libsgz.la libexcept.la

evtool_SOURCES		= evtool.c
evtool_LDADD		= libevf.la libsgz.la libmd5.la libexcept.la

#remote_server_LDADD	= libexcept.la
