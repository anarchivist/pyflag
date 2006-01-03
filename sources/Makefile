# This makefile patches and compiles the relevant sources
BIN		= ../bin/
SLEUTHKIT	= sleuthkit-2.02
## If ethereal should be compiled statically
STATIC		= yes
PLOTICUS	= pl231src
ETHEREAL 	= ethereal-0.10.12

## The TCPDUMP reports are inactive for now - therefore we do not need to compile ethereal at all.
PROGS		= $(BIN)/dbtool 

## This bit compiles and patches ethereal, note that we expect to have
## the ethereal-xxx.tar.bz2 in the sources directory.

all: $(PROGS)

$(BIN)/dbtool:
	tar -xvzf $(SLEUTHKIT).tar.gz || (echo -e "--------------------------\\r\\nYou must have $(SLEUTHKIT).tar.gz in the sources directory\\r\\nYou can get it from http://sleuthkit.sf.net\\r\\n--------------------------" && exit -1)
	cd $(SLEUTHKIT) && make
	cp $(SLEUTHKIT)/bin/fls $(SLEUTHKIT)/bin/mmls $(BIN)


dist-clean:
	rm -rf $(ETHEREAL) $(PLOTICUS) $(PROGS) $(SLEUTHKIT)

clean:
	rm -f $(PROGS)