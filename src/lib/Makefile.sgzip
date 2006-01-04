#!/usr/bin/make

BIN_DIR	= ../../bin
LIBS	= ../misc/aux_lib.a ../hashtools/md5c.o ../misc/except.o -lz
INCL	= -I../misc -I../hashtools
MISCLIBS=../misc/except.o ../hashtools/md5c.o

KERNEL_DIR?=/usr/src/linux

#CFLAGS:=`getconf LFS_CFLAGS` -Wall -Wstrict-prototypes -Wno-trigraphs -O2 -s -I. -fno-strict-aliasing -fno-common -fomit-frame-pointer
CFLAGS:=`getconf LFS_CFLAGS` -Wall -Wstrict-prototypes -Wno-trigraphs -g -I.
-include $(KERNEL_DIR)/.config
-include $(KERNEL_DIR)/conf.vars

CKERNOPS:=-D__KERNEL__ -DMODULE -fno-builtin -nostdlib -DKBUILD_MODNAME="sgloop" -DKBUILD_BASENAME="sgloop"

ifdef CONFIG_MODVERSIONS
ifneq ($(shell grep . $(KERNEL_DIR)/include/linux/modversions.h 2>/dev/null),)
MODVERSIONS:= -DMODVERSIONS -include $(KERNEL_DIR)/include/linux/modversions.h
CKERNOPS += $(MODVERSIONS)
endif
endif

# Check for SMP in config and #define __SMP__ if necessary.
# This is ESSENTIAL when compiling a SMP version of cloop.o
# Otherwise, the module will block the entire block buffer management on read.

ifdef CONFIG_SMP
CKERNOPS += -D__SMP__
endif

KERNOBJ:=sgloop.o

all: $(BIN_DIR)/sgzip

win32: sgzip.exe

sgzip.exe: sgzip.c sgzlib.c
	$(CC) $(CFLAGS) -DCYGWIN $(INCL)  sgzip.c sgzlib.c -o $@ $(MISCLIBS) $(STATIC_LIB_PATH)/libz.a

$(BIN_DIR)/sgzip: sgzip.o sgzlib.o
	$(CC) -o $@  $(CFLAGS) $(LIB) $(LIBS) $(SYSLIBS) sgzip.o sgzlib.o

sgzip.o: sgzip.c sgzlib.h
	$(CC) $(CFLAGS) $(INCL) -c sgzip.c

sgzlib.o: sgzlib.c
	$(CC) $(CFLAGS) $(INCL) -c sgzlib.c

sgloop.ko: sgloop.o
	cp sgloop.o sgloop.ko

#sgloop.o: sgloop.o
#	$(LD) -r -o $@ $^
clean:
	rm -f $(KERNOBJ) *.o *.ko $(BIN_DIR)/sgzip

dist: clean
	cd .. ; \
	tar -cf - cloop/{Makefile,*.[ch],CHANGELOG,README} | \
	bzip2 -9 > $(HOME)/redhat/SOURCES/sgloop.tar.bz2

# There mus be a better way to handle this
$(KERNOBJ): %.o : %.c
	$(CC) -I$(KERNEL_DIR)/include -I$(KERNEL_DIR)/include/asm/mach-default $(CFLAGS) $(CKERNOPS) $< -c -o $@
