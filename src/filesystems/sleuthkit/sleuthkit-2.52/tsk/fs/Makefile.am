AM_CFLAGS = -I../.. -Wall 
EXTRA_DIST = .indent.pro

noinst_LTLIBRARIES = libtskfs.la
# Note that the .h files are in the top-level Makefile
libtskfs_la_SOURCES  = fs_inode.c fs_io.c fs_open.c \
    fs_dent.c fs_types.c fs_data.c fs_load.c tsk_fs_i.h \
    ffs.c ffs_dent.c ext2fs.c ext2fs_dent.c ext2fs_journal.c \
    fatfs.c fatfs_dent.c ntfs.c ntfs_dent.c swapfs.c rawfs.c \
    dcalc_lib.c dcat_lib.c dls_lib.c dstat_lib.c ffind_lib.c \
    fls_lib.c icat_lib.c ifind_lib.c ils_lib.c \
    iso9660.c iso9660_dent.c \
    hfs.c hfs_dent.c hfs_journal.c 

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
