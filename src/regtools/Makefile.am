include $(top_srcdir)/config/Makefile.rules

bin_PROGRAMS	= reglookup

reglookup_SOURCES = lru_cache.c range_list.c regfi.c reglookup.c smb_deps.c void_stack.c
reglookup_LDADD  = ../lib/liboo.la -lm

noinst_HEADERS = $(srcdir)/*.h

