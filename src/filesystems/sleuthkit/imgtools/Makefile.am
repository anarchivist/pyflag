AM_CFLAGS = -I$(srcdir)/../auxtools -DLINUX2 -include config.h

noinst_PROGRAMS		= img_stat
noinst_LTLIBRARIES 	= libimgtools.la

libimgtools_la_SOURCES	= img_lib.h img_tools.h libimgtools.h raw.h split.h \
			  img_open.c raw.c split.c img_types.c img_types.h

img_stat_SOURCES	= img_stat.c
img_stat_LDADD		= libimgtools.la ../auxtools/libauxtools.la
