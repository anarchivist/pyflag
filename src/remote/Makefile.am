INCLUDES     = -I$(top_srcdir)/src/include -include config.h 

bin_PROGRAMS = remote_server

noinst_PROGRAMS = pki_gen_keys

noinst_LTLIBRARIES = libremote.la

remote_server_LDADD = libremote.la ../lib/liboo.la ../lib/libexcept.la

libremote_la_SOURCES = ecc.c rc4.c remote.c ecc.h remote.h rc4.h

pkgpyexec_LTLIBRARIES = remote.la

# python module specifics
remote_la_SOURCES 	= remote_client.c
remote_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS)
remote_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS)
remote_la_LIBADD      = libremote.la ../lib/liboo.la

ecc.c: pki.h ecc.h

## This is a helper program to generate random keys
pki.h: pki_gen_keys
	./pki_gen_keys > pki.h

noinst_HEADERS	=	pki.h remote.h ecc.h rc4.h
