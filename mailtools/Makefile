include ../Makefile.in
PSTVER = `echo libpst-*`
INCL    = -I$(PYTHONINCL) -I$(PSTVER)
TARGET = ../libs/
LIBS	=$(PSTVER)/libpst.o $(PSTVER)/timeconv.o $(PSTVER)/libstrfunc.o $(PSTVER)/debug.o $(PSTVER)/lzfu.o

$(TARGET)/pypst2:	$(TARGET)/pypst.py
	cp pypst2.py $(TARGET)/

$(TARGET)/pypst.py $(TARGET)/_pypst.so:	pypst.i libpst
	swig -python pypst.i
	$(CC) -g $(INCL) pypst_wrap.c -shared $(LIBS) -o $(TARGET)/_pypst.so
	mv pypst.py $(TARGET)/

libpst:
	echo Entering directory $(PSTVER)
	cd $(PSTVER) && make "CC=$(CC)"
	echo leaving directory $(PSTVER)

clean:
	rm -f pypst_wrap.c pypst_wrap.o $(TARGET)/_pypst.so $(TARGET)/pypst.py $(TARGET)/pypst2.py
	echo Entering directory $(PSTVER)
	cd $(PSTVER) && make "CC=$(CC)" clean
	echo leaving directory $(PSTVER)

test:	test.c
	$(CC) -g $(INCL) test.c -shared $(LIBS) -o test
