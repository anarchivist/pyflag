include $(TOPLEVEL)/Makefile.in

ETHEREAL_SRC = ../sources/ethereal-0.10.11/
ETHEREAL_SRC_INCLUDES =  -I $(ETHEREAL_SRC) -I $(ETHEREAL_SRC)/epan/ -I $(ETHEREAL_SRC)/wiretap/

MISC_LIBS = ../libs/

all: pcaptool pyethereal

pcaptool: pcaptool.c check_headers
	gcc `glib-config --cflags glib` $@.c -o $@ -L$(ETHEREAL_LIB) -Wl,--export-dynamic /usr/lib/ethereal/libwiretap.so.0
	cp $@ ../bin/

pyethereal: pyethereal.i check_headers
	swig -python $@.i
	gcc -I /usr/include/python2.3/ `glib-config --cflags glib` pyethereal_wrap.c  -shared  -o _pyethereal.so -lz -lm /usr/lib/libgmodule-2.0.so  -Wl,--export-dynamic  $(ETHEREAL_LIB)/libethereal.so.0 -Wl,--export-dynamic $(ETHEREAL_LIB)/libwiretap.so.0
	mv _pyethereal.so pyethereal.py $(MISC_LIBS)/

check_headers:
	if [ ! -e wiretap.h -o ! -e ethereal.h ]; then echo -e \\n\\n Required headers are missing. Please edit this Makefile for the location of ethereal source tree and type make headers; false ; fi

#This target generates headers from ethereal sources for use in our own code. This is done so we can distribute these headers and people can compile our code without needing the ethereal codebase. Maybe one day distributions can package the headers in a ethereal-dev package or something like that...
headers: wiretap_includes.h ethereal_includes.h
	cpp -nostdinc -P $(ETHEREAL_SRC_INCLUDES) wiretap_includes.h > wiretap.h 2>/dev/null || true
	cpp -nostdinc -P $(ETHEREAL_SRC_INCLUDES) ethereal_includes.h  > ethereal.h 2>/dev/null || true

clean:
	rm -f *.o pcaptool _pyethereal.so pyethereal.py pyethereal_wrap.c

dist-clean: clean
	rm -f wiretap.h ethereal.h