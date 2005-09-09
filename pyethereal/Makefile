include $(TOPLEVEL)/Makefile.in

ETHEREAL_SRC = $(shell (find ../sources/ -maxdepth 1  -type d -name ethereal\* ; find /usr/include/ -maxdepth 1  -type d -name ethereal\*) | head -n1 )
ETHEREAL_SRC_INCLUDES =  -I $(ETHEREAL_SRC) -I $(ETHEREAL_SRC)/epan/ -I $(ETHEREAL_SRC)/wiretap/ -I.

## Work out which libethereal to use - we prefer the one in sources if
## its available, because it generally has many less dependancies, but
## the system will do if available:
LIBETHEREAL = $(shell (find $(ETHEREAL_SRC) -name libethereal.so\* ; find /usr/lib/ethereal/ -name libethereal.so\*) | head -n1)
LIBWIRETAP = $(shell (find $(ETHEREAL_SRC) -name libwiretap.so\* ; find /usr/lib/ethereal/ -name libwiretap.so\*) | head -n1)

ETHEREAL_BINARY = $(shell (find $(ETHEREAL_SRC) -type f -name tethereal -o -type f -name ethereal; which tethereal; which ethereal) | head -n1)

MISC_LIBS = ../libs/

all: pcaptool pyethereal

pcaptool: pcaptool.c check_headers
	gcc `glib-config --cflags glib` $@.c -o $@ $(ETHEREAL_SRC_INCLUDES) -L$(ETHEREAL_LIB) -Wl,--export-dynamic $(LIBWIRETAP)
	cp $@ ../bin/
	cp $(LIBWIRETAP) $(MISC_LIBS)/libwiretap.so.0

pyethereal: pyethereal.i check_headers
	swig -python $@.i
	gcc -g -Wall -I $(PYTHONINCL) $(ETHEREAL_SRC_INCLUDES) `glib-config --cflags glib` -c pyethereal_wrap.c  -o pyethereal_wrap.o
	cp $(LIBETHEREAL) $(MISC_LIBS)/libethereal.so.0
	ld pyethereal_wrap.o  -shared  -o _pyethereal.so $(MISC_LIBS)/libwiretap.so.0  $(MISC_LIBS)/libethereal.so.0 $$(ldd $(ETHEREAL_BINARY) | grep -v "not found" | grep -v ethereal | grep -v gate | awk '{print $$3};')
	cp pyethereal_wrap.o _pyethereal.so pyethereal.py $(MISC_LIBS)/

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