include ../../Makefile.in

INCL = -I../misc/ -I../sgzip/ -I../libevf/ -I../hashtools/ -I../include/

BIN_DIR = ../../bin/
CFLAGS=-g -Wall `getconf LFS_CFLAGS` $(INCL)
MISCLIBS=../misc/except.o ../hashtools/md5c.o
LIBS = $(MISCLIBS) iosubsys.o ../sgzip/sgzlib.o libevf.o -lz  remote_client.o
STATIC_LIB_PATH = /usr/i586-mingw32msvc/lib/
OBJS = class.o stringio.o struct.o talloc.o packet.o misc.o

all: open libio_hooker.so python_binding $(BIN_DIR)/evtool $(BIN_DIR)/iowrapper $(BIN_DIR)/remote_server $(OBJS)

win32:  evtool.exe remote_server.exe

evtool.exe: libevf.o evtool.c
	$(CC) $(CFLAGS) -DCYGWIN evtool.c -o $@ libevf.o $(MISCLIBS) $(STATIC_LIB_PATH)/libz.a

remote_server.exe: remote_server_win32.c
	$(CC) $(CFLAGS) -o $@ remote_server_win32.c  $(STATIC_LIB_PATH)/libws2_32.a $(STATIC_LIB_PATH)/libiberty.a

libio_hooker.so: $(LIBS) hooker.c
	$(CC) -fPIC -rdynamic $(CFLAGS) -c hooker.c
	gcc -shared -WI,-soname,libio_hooker.so -g $(LIBS) -o libio_hooker.so hooker.o -lc -ldl
	cp libio_hooker.so $(LIB_TARGET)

$(BIN_DIR)/evtool: evtool.o $(LIBS)
	$(CC) $(CFLAGS) -o $@ evtool.o  $(LIBS)

$(BIN_DIR)/iowrapper: iowrapper.o $(LIBS)
	$(CC) $(CFLAGS) -o $@ iowrapper.o  $(LIBS) -L$(LIB_TARGET) -lio_hooker

clean:
	rm -f *.o *.so open $(LIB_TARGET)/libio_hooker.so $(LIB_TARGET)/_?iosubsys.* $(BIN_DIR)/evtool $(BIN_DIR)/remote_server

$(BIN_DIR)/remote_server: remote_server.o $(LIBS)
	$(CC) $(CFLAGS) -o $@ remote_server.o  $(LIBS)

python_binding: io.i
	swig -python io.i
	$(CC) $(CFLAGS) $(INCL) -I$(PYTHONINCL) io_wrap.c -shared $(LIBOBJ) $(LIBS) -o _iosubsys.so
	cp _iosubsys.so iosubsys.py $(LIB_TARGET)

test: all
	echo "Hello world" > /tmp/test.txt
	../../bin/sgzip /tmp/test.txt
	LD_LIBRARY_PATH=.:$$LD_LIBRARY_PATH LD_PRELOAD=libio_hooker.so IO_SUBSYS=sgzip IO_OPTS='filename=/tmp/test.txt.sgz' ./open

evtool.o: evtool.c
evtool.o: libevf.h
evtool.o: libevf.h
evtool.o: evtool.c
