LIBS    = ../../iosubsys/hashtools/md5c.o ../../iosubsys/misc/except.o -lz
INCL    = -I../../iosubsys/misc -I../../iosubsys/hashtools
CFLAGS = $(INCL) -g -Wall `getconf LFS_CFLAGS`
LDFLAGS = $(LIBS) `getconf LFS_LDFLAGS`

all: mdd
mdd: server.o client.o mdd.c multicaster.o

clean:
	rm -f *.o mdd