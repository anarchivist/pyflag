INCLUDES        	= -I$(top_srcdir)/src/include -include config.h 

#bin_PROGRAMS = sgzip
noinst_LTLIBRARIES	= libsgz.la
# Stuff that should be distributed:
noinst_HEADERS		= $(srcdir)/*.h

sgzip_LDADD             = libsgz.la ../liboo.la

libsgz_la_SOURCES	= sgzlib.c
libsgz_la_LDFLAGS	= -lz
