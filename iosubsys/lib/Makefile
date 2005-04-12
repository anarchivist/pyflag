include ../../Makefile.in

INCL = -I../misc/ -I../sgzip/ -I../libevf/ -I../hashtools/
## Where libraries should go
TARGET = ../../libs/
BIN_DIR = ../../bin/
CFLAGS=-g -Wall `getconf LFS_CFLAGS` $(INCL)
MISCLIBS=../misc/except.o ../hashtools/md5c.o
LIBS = $(MISCLIBS) iosubsys.o ../sgzip/sgzlib.o libevf.o -lz  remote_client.o

all: open libio_hooker.so python_binding $(BIN_DIR)/evtool $(BIN_DIR)/iowrapper $(BIN_DIR)/remote_server

win32:  evtool.exe remote_server.exe

evtool.exe: libevf.o evtool.c
	$(CC) $(CFLAGS) -DCYGWIN evtool.c -o $@ libevf.o $(MISCLIBS) $(STATIC_LIB_PATH)/libz.a

remote_server.exe: remote_server.c
	$(CC) $(CFLAGS) -o $@ remote_server.c  $(LIBS)

libio_hooker.so: $(LIBS) hooker.c
	$(CC) -fPIC -rdynamic $(CFLAGS) -c hooker.c
	gcc -shared -WI,-soname,libio_hooker.so -g $(LIBS) -o libio_hooker.so hooker.o -lc -ldl
	cp libio_hooker.so $(TARGET)

$(BIN_DIR)/evtool: evtool.o $(LIBS)
	$(CC) $(CFLAGS) -o $@ evtool.o  $(LIBS)

$(BIN_DIR)/iowrapper: iowrapper.o $(LIBS)
	$(CC) $(CFLAGS) -o $@ iowrapper.o  $(LIBS) -L$(TARGET) -lio_hooker

clean:
	rm -f *.o *.so open $(TARGET)/libio_hooker.so $(TARGET)/_?iosubsys.* $(BIN_DIR)/evtool $(BIN_DIR)/remote_server

$(BIN_DIR)/remote_server: remote_server.o $(LIBS)
	$(CC) $(CFLAGS) -o $@ remote_server.o  $(LIBS)

python_binding: io.i
	swig -python io.i
	$(CC) $(CFLAGS) $(INCL) -I$(PYTHONINCL) io_wrap.c -shared $(LIBOBJ) $(LIBS) -o _iosubsys.so
	cp _iosubsys.so iosubsys.py $(TARGET)

test: all
	echo "Hello world" > /tmp/test.txt
	../../bin/sgzip /tmp/test.txt
	LD_LIBRARY_PATH=.:$$LD_LIBRARY_PATH LD_PRELOAD=libio_hooker.so IO_SUBSYS=sgzip IO_OPTS='filename=/tmp/test.txt.sgz' ./open

evtool.o: evtool.c
evtool.o: libevf.h
evtool.o: libevf.h
evtool.o: evtool.c
