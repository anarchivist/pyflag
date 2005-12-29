CFLAGS = -g -Wall -D__DEBUG__ -I/usr/include/python2.4/ -I../include/
#CFLAGS = -Os
LDFLAGS = -lpcap
OBJS = ../lib/class.o ../lib/stringio.o ../lib/struct.o ../lib/talloc.o ../lib/packet.o ../lib/misc.o network.o

all: deps main pcaptool _dissect.so copy_pcap

main: $(OBJS)

deps: $(OBJS)
	@echo Invoking Initialization functions
	@nm --defined-only $(OBJS) | grep __MODULE_INIT | awk '{ print "extern void "$$3"();" }' > init.h
	@nm --defined-only $(OBJS) | grep __MODULE_INIT | awk '{ print $$3"();" }' > init.c

## This is the python binding:
_dissect.so: dissect.o $(OBJS)
	gcc -o $@ -shared  $(OBJS) dissect.o -ldl -lutil
#	cp dissect.py $@ $(LIB_TARGET)

copy_pcap: pcaptool
	cp pcaptool $(BIN_DIR)

clean:
	rm -f *.o *.so main pcaptool $(LIB_TARGET)/dissect.so