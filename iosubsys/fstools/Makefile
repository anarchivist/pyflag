SHELL	= /bin/sh
CC	= gcc
# uncomment the following for a static build
# OPT	= -O -Wall -static
OPT	= -O0 -Wall 
DEBUG	= -g
INCL	= -I../misc -I../hashtools
CFLAGS	= $(DEFS) $(INCL) $(OPT) $(DEBUG)
LIBOBJ	= fs_buf.o fs_inode.o fs_io.o fs_open.o \
	fs_dent.o fs_types.o fs_data.o mylseek.o get.o \
	ffs.o ffs_dent.o ext2fs.o ext2fs_dent.o \
	fatfs.o fatfs_dent.o ntfs.o ntfs_dent.o \
	../sgzip/sgzlib.o libevf.o ../misc/except.o
LIBS	= ../misc/aux_lib.a ../hashtools/md5c.o -lz
LIB	= fs_lib.a
BIN_DIR	= ../../bin
PROGS	= $(BIN_DIR)/icat $(BIN_DIR)/fls $(BIN_DIR)/dcat \
	$(BIN_DIR)/istat $(BIN_DIR)/evtool $(BIN_DIR)/dbtool \
	$(BIN_DIR)/fdd \
	python_binding
## Where libraries should go
TARGET = ../../libs/

defs:
	@CC="$(CC)" sh ../makedefs

all:	$(LIB) $(PROGS)

$(LIB):	$(LIBOBJ)
	$(AR) $@ $?
	$(RANLIB) $@

$(BIN_DIR)/dls: dls.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ dls.o $(LIB) $(LIBS) $(SYSLIBS)

$(BIN_DIR)/ils: ils.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ ils.o $(LIB) $(LIBS) $(SYSLIBS)

$(BIN_DIR)/icat: icat.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ icat.o $(LIB) $(LIBS) $(SYSLIBS)


$(BIN_DIR)/ifind: ifind.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ ifind.o $(LIB) $(LIBS) $(SYSLIBS)

$(BIN_DIR)/ffind: ffind.o $(LIB) $(LIBS) 
	$(CC) $(CFLAGS) -o $@ ffind.o $(LIB) $(LIBS) $(SYSLIBS) 


$(BIN_DIR)/fdd: fdd.o $(LIB) $(LIBS) 
	$(CC) $(CFLAGS) -o $@ fdd.o $(LIB) $(LIBS) $(SYSLIBS) 

$(BIN_DIR)/fls: fls.o $(LIB) $(LIBS) 
	$(CC) $(CFLAGS) -o $@ fls.o $(LIB) $(LIBS) $(SYSLIBS) 

$(BIN_DIR)/dcat: dcat.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ dcat.o $(LIB) $(LIBS) $(SYSLIBS)

$(BIN_DIR)/istat: istat.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ istat.o $(LIB) $(LIBS) $(SYSLIBS)

$(BIN_DIR)/dcalc: dcalc.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ dcalc.o $(LIB) $(LIBS) $(SYSLIBS)

$(BIN_DIR)/dstat: dstat.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ dstat.o $(LIB) $(LIBS) $(SYSLIBS)

$(BIN_DIR)/fsstat: fsstat.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ fsstat.o $(LIB) $(LIBS) $(SYSLIBS)

$(BIN_DIR)/evtool: evtool.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ evtool.o $(LIB) $(LIBS) $(SYSLIBS)

$(BIN_DIR)/dbtool: dbtool.o $(LIB) $(LIBS)
	$(CC) $(CFLAGS) -o $@ dbtool.o $(LIB) $(LIBS) $(SYSLIBS)

python_binding: io.i
	swig -python io.i
	$(CC) $(CFLAGS) $(INCL) -I/usr/include/python2.3 io_wrap.c -shared $(LIBOBJ) $(LIBS) -o _iosubsys.so
	cp _iosubsys.so iosubsys.py $(TARGET)/

clean:
	rm -f $(PROGS) $(LIB) *.o *core *.so

depend: $(MAKES)
	(sed '1,/^# do not edit/!d' Makefile; \
	set -e; for i in [a-z][a-z0-9]*.c; do \
	    $(CC) -E $(DEFS) $(INCL) $$i | sed -n -e '/^# *1 *"\([^"]*\)".*/{' \
	    -e 's//'`echo $$i|sed 's/c$$/o/'`': \1/' -e 'p' -e '}'; \
	done) | grep -v '[.][o][:][ ][/]' >$$$$ && mv $$$$ Makefile

# do not edit - this was generated with make depend
dcalc.o: fs_tools.h
dcalc.o: fs_types.h
dcalc.o: ../misc/error.h
dcalc.o: ../misc/split_at.h
fdd.o: fs_tools.h
fdd.o: fs_types.h
fdd.o: ../misc/error.h
dcat.o: fs_tools.h
dcat.o: fs_types.h
dcat.o: ../misc/error.h
dls.o: fs_tools.h
dls.o: fs_types.h
dls.o: ../misc/error.h
dls.o: ../misc/split_at.h
dstat.o: fs_tools.h
dstat.o: fs_types.h
dstat.o: ../misc/error.h
dstat.o: ffs.h
dstat.o: ext2fs.h
evtool.o: evtool.c
evtool.o: libevf.h
evtool.o: libevf.h
evtool.o: evtool.c
ext2fs.o: ext2fs.c
ext2fs.o: fs_tools.h
ext2fs.o: fs_types.h
ext2fs.o: ext2fs.h
ext2fs.o: fs_io.h
ext2fs.o: ../misc/mymalloc.h
ext2fs.o: ../misc/error.h
ext2fs_dent.o: fs_tools.h
ext2fs_dent.o: fs_types.h
ext2fs_dent.o: ext2fs.h
ext2fs_dent.o: ../misc/mymalloc.h
ext2fs_dent.o: ../misc/error.h
fatfs.o: fs_tools.h
fatfs.o: fs_types.h
fatfs.o: fatfs.h
fatfs.o: fs_io.h
fatfs.o: ../misc/mymalloc.h
fatfs.o: ../misc/error.h
fatfs_dent.o: fs_tools.h
fatfs_dent.o: fs_types.h
fatfs_dent.o: fatfs.h
fatfs_dent.o: ../misc/mymalloc.h
fatfs_dent.o: ../misc/error.h
ffind.o: fs_tools.h
ffind.o: fs_types.h
ffind.o: ../misc/error.h
ffs.o: fs_tools.h
ffs.o: fs_types.h
ffs.o: ffs.h
ffs.o: ../misc/mymalloc.h
ffs.o: ../misc/error.h
ffs.o: fs_io.h
ffs_dent.o: fs_tools.h
ffs_dent.o: fs_types.h
ffs_dent.o: ffs.h
ffs_dent.o: ../misc/mymalloc.h
ffs_dent.o: ../misc/error.h
fls.o: fs_tools.h
fls.o: fs_types.h
fls.o: ../misc/error.h
fls.o: fs_io.h
fls.o: ntfs.h
fs_buf.o: fs_tools.h
fs_buf.o: fs_types.h
fs_buf.o: ../misc/mymalloc.h
fs_buf.o: ../misc/error.h
fs_data.o: fs_tools.h
fs_data.o: fs_types.h
fs_data.o: ../misc/mymalloc.h
fs_data.o: ../misc/error.h
fs_dent.o: fs_tools.h
fs_dent.o: fs_types.h
fs_dent.o: ../misc/mymalloc.h
fs_dent.o: ../misc/error.h
fs_inode.o: fs_tools.h
fs_inode.o: fs_types.h
fs_inode.o: ../misc/mymalloc.h
fs_inode.o: ../misc/error.h
fs_inode.o: fs_data.h
fs_io.o: fs_tools.h
fs_io.o: fs_types.h
fs_io.o: ../misc/error.h
fs_io.o: fs_io.h
fs_io.o: sgzlib.h
fs_io.o: libevf.h
fs_open.o: fs_tools.h
fs_open.o: fs_types.h
fs_open.o: ../misc/error.h
fsstat.o: fs_tools.h
fsstat.o: fs_types.h
fsstat.o: ../misc/error.h
fscheck.o: fs_tools.h
fscheck.o: fs_types.h
fscheck.o: ../misc/error.h
fs_types.o: fs_tools.h
fs_types.o: fs_types.h
get.o: fs_tools.h
get.o: fs_types.h
get.o: ../misc/error.h
icat.o: fs_tools.h
icat.o: fs_types.h
icat.o: fs_io.h
icat.o: ../misc/error.h
ifind.o: fs_tools.h
ifind.o: fs_types.h
ifind.o: ../misc/error.h
ils.o: fs_tools.h
ils.o: fs_types.h
ils.o: ../misc/error.h
ils.o: ../misc/split_at.h
istat.o: fs_tools.h
istat.o: fs_types.h
istat.o: ../misc/error.h
istat.o: ffs.h
istat.o: ext2fs.h
libevf.o: libevf.h
libevf.o: libevf.h
mylseek.o: fs_tools.h
mylseek.o: fs_types.h
ntfs.o: fs_tools.h
ntfs.o: fs_types.h
ntfs.o: ntfs.h
ntfs.o: ../misc/error.h
ntfs.o: fs_data.h
ntfs.o: fs_io.h
ntfs_dent.o: fs_tools.h
ntfs_dent.o: fs_types.h
ntfs_dent.o: ntfs.h
ntfs_dent.o: fs_data.h
ntfs_dent.o: ../misc/error.h
