if HAVE_LIBJPEG
jpeg_la_SOURCES = jpeg.c suspend.c suspend.h
jpeg_la_CPPFLAGS= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
jpeg_la_LIBADD	= ../lib/liboo.la
jpeg_la_LDFLAGS = -module $(PYTHON_LDFLAGS) -ljpeg
pkgpyexec_LTLIBRARIES = jpeg.la
endif