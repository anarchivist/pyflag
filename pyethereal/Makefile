ETHEREAL_LIB = /usr/lib/ethereal
ETHEREAL_SRC = ../sources/ethereal-0.10.11/
MISC_LIBS = ../libs/

all: pcaptool pyethereal

pcaptool: pcaptool.c
	gcc -I$(ETHEREAL_SRC)/wiretap/ `glib-config --cflags glib` $@.c -o $@ -L$(ETHEREAL_LIB) -lwiretap
	cp $@ ../bin/

pyethereal: pyethereal.i
	swig -python $@.i
	gcc -I /usr/include/python2.3/ -I $(ETHEREAL_SRC) -I $(ETHEREAL_SRC)/epan/ -I $(ETHEREAL_SRC)/wiretap/ `glib-config --cflags glib` pyethereal_wrap.c  -shared  -o _pyethereal.so -lz -lm /usr/lib/libgmodule-2.0.so  -Wl,--export-dynamic  $(ETHEREAL_LIB)/libethereal.so.0 -Wl,--export-dynamic $(ETHEREAL_LIB)/libwiretap.so

clean:
	rm -f *.o pcaptool _pyethereal.so pyethereal.py