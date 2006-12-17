AM_CFLAGS		= -I$(srcdir)/../auxtools -I$(srcdir)/../imgtools -I$(top_srcdir)/src/include -DLINUX2 -include config.h 

bin_PROGRAMS			= mmls mmstat
noinst_LTLIBRARIES		= libmmtools.la

libmmtools_la_SOURCES	= dos.h gpt.h mac.h mm_tools.h sun.h bsd.h bsd.c \
						  dos.c gpt.c mac.c mm_io.c mm_open.c mm_part.c \
						  mm_types.c sun.c
libmmtools_la_LIBADD	= ../auxtools/libauxtools.la ../imgtools/libimgtools.la ../../../lib/liboo.la -lz -lcrypto

mmstat_SOURCES			=  mmstat.c
mmstat_LDADD			=  libmmtools.la

mmls_SOURCES			= mmls.c
mmls_LDADD				= libmmtools.la
