INCLUDES		= -I$(top_srcdir)/src/include

bin_PROGRAMS		= sgzip
lib_LTLIBRARIES		= libsgz.la

libsgz_la_SOURCES	= sgzlib.c sgzlib.h
sgzip_LDADD		= libsgz.la -lz
