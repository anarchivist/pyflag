# Makefile for dd_rescue
# (c) garloff@suse.de, 99/10/09, GNU GPL
# $Id: Makefile,v 1.1 2004/08/19 12:57:38 scudette Exp $

VERSION = 1.03

DESTDIR = 

CC = gcc
INCL   = -I../../iosubsys/hashtools/
CFLAGS = -O2 -Wall $(INCL) $(EXTRA_CFLAGS)
#CFLAGS = -Wall -g -ggdb $(EXTRA_CFLAGS)
DEFINES = -DVERSION=\"$(VERSION)\"
INSTALL = install
INSTALLFLAGS = -s
prefix = $(DESTDIR)/usr
#INSTALLDIR = $(prefix)/bin
INSTALLDIR = $(DESTDIR)/bin
#MYDIR = dd_rescue-$(VERSION)
MYDIR = dd_rescue
TARGETS = dd_rescue
OBJECTS = dd_rescue.o ../../iosubsys/hashtools/md5c.o
DOCDIR = $(prefix)/share/doc/packages

default: $(TARGETS)

dd_rescue: $(OBJECTS)
	$(CC) $(CFLAGS) $(DEFINES) $(OBJECTS) -o $@
	mv $@ ../../bin/

dd_rescue.o: dd_rescue.c
	$(CC) $(CFLAGS) $(DEFINES) -c $< -o $@

clean:
	rm -f $(TARGETS) $(OBJECTS) core

distclean: clean
	rm -f *~

dist: distclean
	tar cvzf ../dd_rescue-$(VERSION).tar.gz -C.. --exclude=$(MYDIR)/CV* $(MYDIR)/

install: $(TARGETS)
	mkdir -p $(INSTALLDIR)
	$(INSTALL) $(INSTALLFLAGS) -o root -g root -m 755 $(TARGETS) $(INSTALLDIR)
	#$(INSTALL) -o root -g root -m 755 -d $(DOCDIR)/dd_rescue
	#$(INSTALL) -o root -g root -m 644 README.dd_rescue $(DOCDIR)/dd_rescue/
