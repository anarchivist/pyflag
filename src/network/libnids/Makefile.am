noinst_LTLIBRARIES = libnids.la

libnids_la_SOURCES = allpromisc.c  hash.c         ip_options.c  libnids.c  tcp.c \
		    checksum.c    ip_fragment.c  killtcp.c     scan.c     util.c
libnids_la_CFLAGS   = -D_BSD_SOURCE -DHAVE_BSD_UDPHDR=1  -DLIBNET_VER=-1 -DHAVE_ICMPHDR=1 -DHAVE_TCP_STATES=1
libnids_la_LIBADD   =  -lpcap