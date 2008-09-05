include $(top_srcdir)/config/Makefile.rules

pkgpython_PYTHON 	= dissect.py

if HAVE_GEOIP
geoip_la_SOURCES = geoip.c
geoip_la_CPPFLAGS= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
geoip_la_LDFLAGS = -module $(PYTHON_LDFLAGS)

if HAVE_WINDOWS
AM_LDFLAGS	=  -lGeoIP -lws2_32
else
AM_LDFLAGS	=  -lGeoIP
endif

noinst_LTLIBRARIES 	= _dissect.la reassembler.la pypcap.la geoip.la libnetwork.la
nodist_pkgpyexec_PYTHON	= _dissect$(PYTHON_EXTENSION) reassembler$(PYTHON_EXTENSION)\
			  pypcap$(PYTHON_EXTENSION) geoip$(PYTHON_EXTENSION)
else
noinst_LTLIBRARIES 	= _dissect.la reassembler.la pypcap.la libnetwork.la
nodist_pkgpyexec_PYTHON	= _dissect$(PYTHON_EXTENSION) reassembler$(PYTHON_EXTENSION)\
			  pypcap$(PYTHON_EXTENSION)
endif

libnetwork_la_SOURCES	= network.c
libnetwork_la_CFLAGS 	= -I$(top_srcdir)/src/include
libnetwork_la_LIBADD	= ../lib/liboo.la

pypcap_la_SOURCES	= pcap.c pypcap.c
pypcap_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
pypcap_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS)
pypcap_la_LIBADD	= libnetwork.la

_dissect_la_SOURCES 	= _dissect.c pcap.c
_dissect_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
_dissect_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS)
_dissect_la_LIBADD	= libnetwork.la

reassembler_la_SOURCES = reassembler.c tcp.c
reassembler_la_CPPFLAGS= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
reassembler_la_LDFLAGS = -module $(PYTHON_LDFLAGS)
reassembler_la_LIBADD  = libnetwork.la

noinst_HEADERS		= tcp.h GeoIPCity.h GeoIP.h pypcap.h reassembler.h
