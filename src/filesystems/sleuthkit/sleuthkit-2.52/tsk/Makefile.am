# Compile the sub directories
SUBDIRS = base img vs fs hashdb

# Merge the libraries into one
noinst_LTLIBRARIES = libtsk-pf.la
libtsk_pf_la_SOURCES =
libtsk_pf_la_LIBADD = base/libtskbase.la img/libtskimg.la \
    vs/libtskvs.la fs/libtskfs.la hashdb/libtskhashdb.la
# current:revision:age
libtsk_pf_la_LDFLAGS = -version-info 1:2:0

EXTRA_DIST = tsk_tools_i.h
