INCL 	= -I/usr/include/python2.3 
LIBS	= -lclamav

../clamav.py ../_clamav.so:	clamav.i
	swig -python clamav.i
	$(CC) -I/usr/include/python2.3 clamav_wrap.c -shared $(LIBS) -o ../_clamav.so
	mv clamav.py ../clamav.py

clean:
	rm -f ../_clamav.so ../clamav.py clamav_wrap.c
