INCLUDES = -I../misc/ -I../sgzip/ -I../libevf/ -I../fstools/

CFLAGS=-g -Wall `getconf LFS_CFLAGS` $(INCLUDES)
LIBS = ../misc/except.o fs_io.o ../sgzip/sgzlib.o ../fstools/libevf.o -lz ../hashtools/md5c.o
all:  libhooker.so.1

libhooker.so.1: $(LIBS)
	gcc -fPIC -rdynamic $(CFLAGS) -c hooker.c
	gcc -shared -WI,-soname,libhooker.so $(LIBS) -o libhooker.so hooker.o -lc -ldl

clean:
	rm -f *.o *.so

test:
	echo "Hello world" > /tmp/test.txt
	../../bin/sgzip /tmp/test.txt
	LD_PRELOAD=./libhooker.so IO_SUBSYS=sgzip IO_OPTS='filename=/tmp/test.txt.sgz' ./open
