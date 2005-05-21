## This make file builds pyethereal by copying these source files into
## the source directory and compiling it there..

## This is the ethereal source tree - it should be completely built
ETHEREAL_SRC = $(shell find ../sources/ -type d -name ethereal\*| head -1)

## These are the libraries we need from ethereal. They are specified
## relative to the ETHEREAL_SRC
ETHEREAL_LIBS = $(ETHEREAL_SRC)/wiretap/.libs/libwiretap.so.0* $(ETHEREAL_SRC)/epan/.libs/libethereal.so.0* $(ETHEREAL_SRC)/.libs/_pyethereal.so $(ETHEREAL_SRC)/pyethereal.py

MISC_LIBS = ../libs/

## These are the files which make up our sources:
SOURCES = Makefile.pyethereal pyethereal.i pcaptool.c

all: pcaptool
	if [ -d "$(ETHEREAL_SRC)" ]; then cp $(SOURCES) $(ETHEREAL_SRC); else echo Unable to find Ethereal source code in ../sources/ && false; fi
	cd $(ETHEREAL_SRC); make -f Makefile.pyethereal pyethereal
	for f in `ls $(ETHEREAL_LIBS)`; do cp $$f $(MISC_LIBS); done

pcaptool:
	cd $(ETHEREAL_SRC); make -f Makefile.pyethereal pcaptool	
	mv $(ETHEREAL_SRC)/pcaptool ../bin/

clean:
	for f in `ls $(ETHEREAL_LIBS)`; do rm -f $(MISC_LIBS)/`basename $$f`; done
	rm -f ../bin/pcap_parse	
