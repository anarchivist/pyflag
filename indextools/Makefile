OPT     = -O0 -Wall
DEBUG   = -g
INCL    = -I../iosubsys/misc/
CFLAGS  = $(DEFS) $(INCL) $(OPT) $(DEBUG)

LIBS    = ../iosubsys/misc/except.o

index: index.o python_binding
	$(CC) $(CFLAGS) -o $@ index.o $(LIBS)

index.o: index.c index.h

python_binding: index.i
	swig -python index.i
	$(CC) $(CFLAGS) $(INCL) -I/usr/include/python2.3 index_wrap.c -shared $(LIBOBJ) $(LIBS) index.o -o _index.so
	cp _index.so index.py ../

clean:
	rm -f *.o index ../_index.so ../index.py
