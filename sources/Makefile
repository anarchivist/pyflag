# This makefile patches and compiles the relevant sources
BIN		= ../bin/
ETHEREAL	= ethereal-0.10.2
## If ethereal should be compiled statically
STATIC		= yes
PLOTICUS	= pl220src

PROGS		= $(BIN)/tethereal $(BIN)/pl $(BIN)/prefabs

## This bit compiles and patches ethereal, note that we expect to have
## the ethereal-xxx.tar.bz2 in the sources directory.

all: $(PROGS)

$(BIN)/tethereal:
	tar -xvjf $(ETHEREAL).tar.bz2 || (echo -e "--------------------------\\r\\nYou must have $(ETHEREAL).tar.gz in the sources directory\\r\\nYou can get it from http://www.ethereal.com\\r\\n--------------------------" && exit -1)
	patch -p0 < ../patches/$(ETHEREAL)_sql_kb.patch
	cd $(ETHEREAL) && (./autogen.sh && ./configure --enable-static=$(STATIC) --enable-ethereal=no --enable-tethereal=yes --enable-gtk2=no --disable-gtktest --enable-editcap=no --enable-mergecap=no --enable-text2pcap=no --enable-idl2eth=no --enable-ipv6=no --with-plugins=no && make)
	cp $(ETHEREAL)/tethereal $(BIN)

$(BIN)/pl $(BIN)/prefabs:
	tar -xvzf $(PLOTICUS).tar.gz || (echo -e "--------------------------\\r\\nYou must have $(PLOTICUS).tar.gz in the sources directory\\r\\nYou can get it from http://ploticus.sourceforge.net\\r\\n--------------------------" && exit -1)
	cd $(PLOTICUS)/src && make
	cp -r $(PLOTICUS)/prefabs $(PLOTICUS)/src/pl $(BIN)

clean:
	rm -rf $(ETHEREAL) $(PLOTICUS) $(PROGS)
