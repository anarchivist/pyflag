include ../../Makefile.in
INCL 	= -I$(PYTHONINCL)
LIBS	= -lmagic
#Path where all the python things live
PYTHONPATH = ../../libs/

$(PYTHONPATH)/magic.py $(PYTHONPATH)/_magic.so:	magic.i
	swig -python magic.i
	$(CC) $(INCL) magic_wrap.c -shared $(LIBS) -o $(PYTHONPATH)/_magic.so
	mv magic.py $(PYTHONPATH)

clean:
	rm -rf $(PYTHONPATH)/_magic.so $(PYTHONPATH)/magic.py magic_wrap.c
