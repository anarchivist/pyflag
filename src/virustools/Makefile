include ../Makefile.in
INCL 	= -I$(PYTHONINCL)
LIBS	= -lclamav
TARGET = ../libs/

$(TARGET)/clamav.py $(TARGET)/_clamav.so:	clamav.i
	swig -python clamav.i
	$(CC) $(INCL) clamav_wrap.c -shared $(LIBS) -o $(TARGET)/_clamav.so
	mv clamav.py $(TARGET)/clamav.py

clean:
	rm -f $(TARGET)/_clamav.so $(TARGET)/clamav.py clamav_wrap.c
