include $(TOPLEVEL)/Makefile.in

ETHEREAL_SRC = $(shell find ../sources/ -type d -maxdepth 1 -name ethereal\*)
ETHEREAL_SRC_INCLUDES =  -I $(ETHEREAL_SRC) -I $(ETHEREAL_SRC)/epan/ -I $(ETHEREAL_SRC)/wiretap/ -I.

MISC_LIBS = ../libs/

all: pcaptool pyethereal

pcaptool: pcaptool.c check_headers
	gcc `glib-config --cflags glib` $@.c -o $@ $(ETHEREAL_SRC_INCLUDES) -L$(ETHEREAL_LIB) -Wl,--export-dynamic /usr/lib/ethereal/libwiretap.so.0
	cp $@ ../bin/

pyethereal: pyethereal.i check_headers
	swig -python $@.i
	gcc -g -Wall -I $(PYTHONINCL) $(ETHEREAL_SRC_INCLUDES) `glib-config --cflags glib` -c pyethereal_wrap.c  -o pyethereal_wrap.o
	ld pyethereal_wrap.o  -shared  -o _pyethereal.so $$(ldd $$(which tethereal ethereal | head -n 1) | awk '{print $$3};')
	mv pyethereal_wrap.o _pyethereal.so pyethereal.py $(MISC_LIBS)/

check_headers:
	if [ ! -e wiretap.h -o ! -e ethereal.h ]; then echo -e \\n\\n Required headers are missing. Please edit this Makefile for the location of ethereal source tree and type make headers; false ; fi

#This target generates headers from ethereal sources for use in our own code. This is done so we can distribute these headers and people can compile our code without needing the ethereal codebase. Maybe one day distributions can package the headers in a ethereal-dev package or something like that...
headers: wiretap_includes.h ethereal_includes.h
	cpp -nostdinc -P $(ETHEREAL_SRC_INCLUDES) wiretap_includes.h > wiretap.h 2>/dev/null || true
	cpp -nostdinc -P $(ETHEREAL_SRC_INCLUDES) ethereal_includes.h  > ethereal.h 2>/dev/null || true

# Ethereal library dependency is a nightmare... libethereal does not import all the symbols it needs

clean:
	rm -f *.o pcaptool _pyethereal.so pyethereal.py pyethereal_wrap.c

dist-clean: clean
	rm -f wiretap.h ethereal.h