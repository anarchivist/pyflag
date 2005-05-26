# This makefile patches and compiles the relevant sources
BIN		= ../bin/
SLEUTHKIT	= sleuthkit-2.01
## If ethereal should be compiled statically
STATIC		= yes
PLOTICUS	= pl231src

## The TCPDUMP reports are inactive for now - therefore we do not need to compile ethereal at all.
PROGS		= $(BIN)/dbtool $(BIN)/pl $(BIN)/prefabs 

## This bit compiles and patches ethereal, note that we expect to have
## the ethereal-xxx.tar.bz2 in the sources directory.

all: $(PROGS)

$(BIN)/dbtool:
	tar -xvzf $(SLEUTHKIT).tar.gz || (echo -e "--------------------------\\r\\nYou must have $(SLEUTHKIT).tar.gz in the sources directory\\r\\nYou can get it from http://sleuthkit.sf.net\\r\\n--------------------------" && exit -1)
	cd $(SLEUTHKIT) && make
	cp $(SLEUTHKIT)/bin/fls $(SLEUTHKIT)/bin/mmls $(BIN)

$(BIN)/pl $(BIN)/prefabs:
	tar -xvzf $(PLOTICUS).tar.gz || (echo -e "--------------------------\\r\\nYou must have $(PLOTICUS).tar.gz in the sources directory\\r\\nYou can get it from http://ploticus.sourceforge.net\\r\\n--------------------------" && exit -1)
	cd $(PLOTICUS)/src && make
	cp -r $(PLOTICUS)/prefabs $(PLOTICUS)/src/pl $(BIN)

clean:
	rm -rf $(ETHEREAL) $(PLOTICUS) $(PROGS) $(SLEUTHKIT)
