AM_CFLAGS		= -I$(srcdir)/../auxtools -I$(srcdir)/../imgtools -I$(top_srcdir)/src/include -DLINUX2 -include config.h 

bin_PROGRAMS		= dbtool
noinst_LTLIBRARIES	= libfstools.la
noinst_PROGRAMS	= ils dls icat fls dcat ffind istat ifind dcalc dstat \
		          fsstat jls jcat
libfstools_la_SOURCES	= ext2fs.h fatfs.h ffs.h fs_tools.h fs_tools_i.h iso9660.h \
						  ntfs.h dcalc_lib.c dcat_lib.c dls_lib.c dstat_lib.c ext2fs.c \
					      ext2fs_dent.c ext2fs_journal.c fatfs.c fatfs_dent.c ffind_lib.c \
					      ffs.c ffs_dent.c fls_lib.c fs_data.c fs_dent.c fs_inode.c \
					      fs_io.c fs_load.c fs_open.c fs_types.c icat_lib.c ifind_lib.c \
					      ils_lib.c iso9660.c iso9660_dent.c ntfs.c ntfs_dent.c \
					      rawfs.c swapfs.c

# fscheck.c hfs.h hfs.c hfs_dent.c hfs_journal.c

libfstools_la_LIBADD	= ../auxtools/libauxtools.la ../imgtools/libimgtools.la ../mmtools/libmmtools.la ../../../lib/liboo.la
dbtool_LDADD		= libfstools.la ../../../lib/libexcept.la ../../../lib/libiosubsys/libiosubsys.la  ../../../lib/libiosubsys/libio_hooker.la

ils_LDADD		= libfstools.la
dls_LDADD		= libfstools.la
icat_LDADD		= libfstools.la
fls_LDADD		= libfstools.la
dcat_LDADD		= libfstools.la
ffind_LDADD		= libfstools.la
istat_LDADD		= libfstools.la
ifind_LDADD		= libfstools.la
dcalc_LDADD		= libfstools.la
dstat_LDADD		= libfstools.la
fsstat_LDADD	= libfstools.la
jls_LDADD		= libfstools.la
jcat_LDADD		= libfstools.la
