include $(top_srcdir)/config/Makefile.rules

noinst_LTLIBRARIES 	= pydistorm.la
nodist_pkgpyexec_PYTHON = pydistorm$(PYTHON_EXTENSION)

noinst_HEADERS 		= decoder.h  instructions.h  insts.h  operands.h\
			  prefix.h  pydistorm.h  textdefs.h  wstring.h  x86defs.h

pydistorm_la_SOURCES	= decoder.c  instructions.c  operands.c pydistorm.c  \
			  wstring.c  distorm.c  insts.c prefix.c textdefs.c x86defs.c
pydistorm_la_CPPFLAGS 	= $(PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
pydistorm_la_LDFLAGS 	= -module $(PYTHON_LDFLAGS)
