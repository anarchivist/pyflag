AM_CFLAGS = -I$(srcdir)/../auxtools -DLINUX2 -include config.h

noinst_PROGRAMS		= img_stat
noinst_LTLIBRARIES 	= libimgtools.la

libimgtools_la_SOURCES	= img_tools.h raw.h split.h \
						  img_cat.c img_open.c img_types.c raw.c split.c

img_stat_SOURCES	= img_stat.c
img_stat_LDADD		= libimgtools.la ../auxtools/libauxtools.la ../../../lib/liboo.la
