PSTVER = `echo libpst-*`
INCL    = -I/usr/include/python2.3 -I$(PSTVER)
LIBS	=$(PSTVER)/libpst.o $(PSTVER)/timeconv.o $(PSTVER)/libstrfunc.o $(PSTVER)/debug.o $(PSTVER)/lzfu.o

../pypst2:	../pypst.py
	cp pypst2.py ../

../pypst.py ../_pypst.so:	pypst.i libpst
	swig -python pypst.i
	$(CC) -g $(INCL) pypst_wrap.c -shared $(LIBS) -o ../_pypst.so
	mv pypst.py ../

libpst:
	echo Entering directory $(PSTVER)
	cd $(PSTVER) && make "CC=$(CC)"
	echo leaving directory $(PSTVER)

clean:
	rm -f pypst_wrap.c pypst_wrap.o ../_pypst.so ../pypst.py ../pypst2.py
	echo Entering directory $(PSTVER)
	cd $(PSTVER) && make "CC=$(CC)" clean
	echo leaving directory $(PSTVER)

test:	test.c
	$(CC) -g $(INCL) test.c -shared $(LIBS) -o test
