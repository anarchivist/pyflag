AM_CFLAGS = -I../.. -Wall
EXTRA_DIST = .indent.pro DESIGN.txt

noinst_LTLIBRARIES = libtskimg.la
libtskimg_la_SOURCES = img_open.c img_types.c raw.c raw.h \
    split.c split.h aff.c aff.h ewf.c ewf.h tsk_img_i.h

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
