include ../Makefile.in

OPT     = -O0 -Wall
DEBUG   = -g
INCL    = -I../iosubsys/misc/
CFLAGS  = $(DEFS) $(INCL) $(OPT) $(DEBUG)
TARGETS = ../libs/
LIBS    = ../iosubsys/misc/except.o

index: index.o python_binding
	$(CC) $(CFLAGS) -o $@ index.o $(LIBS)

index.o: index.c index.h

python_binding: index.i
	swig -python index.i
	$(CC) $(CFLAGS) $(INCL) -I$(PYTHONINCL) index_wrap.c -shared $(LIBOBJ) $(LIBS) index.o -o _index.so
	cp _index.so index.py $(TARGETS)/

clean:
	rm -f *.o index $(TARGETS)/_index.so $(TARGETS)/index.py
