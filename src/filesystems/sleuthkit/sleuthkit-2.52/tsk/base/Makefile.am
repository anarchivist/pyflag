AM_CFLAGS = -I../.. -Wall 

noinst_LTLIBRARIES = libtskbase.la
libtskbase_la_SOURCES = data_buf.c md5c.c mymalloc.c sha1c.c \
    tsk_endian.c tsk_error.c tsk_list.c tsk_parse.c tsk_printf.c \
    tsk_unicode.c tsk_version.c tsk_base_i.h

libtskbase_la_LIBADD = ../../../../../lib/liboo.la

EXTRA_DIST = XGetopt.c XGetopt.h .indent.pro

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
