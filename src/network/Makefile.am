pkgpython_PYTHON 	= dissect.py
pkgpyexec_LTLIBRARIES 	= _dissect.la reassembler.la pypcap.la geoip.la

noinst_LTLIBRARIES	= libnetwork.la
libnetwork_la_SOURCES	= network.c
libnetwork_la_CFLAGS 	= -I$(top_srcdir)/src/include
libnetwork_la_LIBADD	= ../lib/liboo.la

pypcap_la_SOURCES	= pcap.c pypcap.c
pypcap_la_CPPFLAGS 	= $(PYTHON_CSPEC) -I$(top_srcdir)/src/include
pypcap_la_LDFLAGS 	= -module $(PYTHON_LSPEC)
pypcap_la_LIBADD	= libnetwork.la

_dissect_la_SOURCES 	= dissect.c pcap.c
_dissect_la_CPPFLAGS 	= $(PYTHON_CSPEC) -I$(top_srcdir)/src/include
_dissect_la_LDFLAGS 	= -module $(PYTHON_LSPEC)
_dissect_la_LIBADD	= libnetwork.la

reassembler_la_SOURCES = reassembler.c tcp.c
reassembler_la_CPPFLAGS= $(PYTHON_CSPEC) -I$(top_srcdir)/src/include
reassembler_la_LDFLAGS = -module $(PYTHON_LSPEC)
reassembler_la_LIBADD  = libnetwork.la

geoip_la_SOURCES = py_GeoIP.c
geoip_la_CPPFLAGS= $(PYTHON_CSPEC) -I$(top_srcdir)/src/include
geoip_la_LDFLAGS = -module $(PYTHON_LSPEC) -lGeoIP

noinst_HEADERS		= network.h tcp.h