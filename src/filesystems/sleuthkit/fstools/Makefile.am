AM_CFLAGS		= -I$(srcdir)/../auxtools -I$(srcdir)/../imgtools -I$(top_srcdir)/src/include -DLINUX2

bin_PROGRAMS		= dbtool
noinst_LTLIBRARIES	= libfstools.la
#noinst_PROGRAMS	= ils dls icat fls dcat ffind istat ifind dcalc dstat \
#		          fsstat jls jcat
libfstools_la_SOURCES	= ext2fs.h fatfs.h ffs.h fs_data.h fs_lib.h fs_tools.h \
			  fs_types.h fs_unicode.h hfs.h iso9660.h libfstools.h ntfs.h \
			  fs_inode.c fs_io.c fs_open.c \
			  fs_dent.c fs_types.c fs_data.c fs_load.c fs_unicode.c \
			  ffs.c ffs_dent.c ext2fs.c ext2fs_dent.c ext2fs_journal.c \
			  fatfs.c fatfs_dent.c ntfs.c ntfs_dent.c swapfs.c rawfs.c \
			  dcalc_lib.c dcat_lib.c dls_lib.c dstat_lib.c ffind_lib.c \
			  fls_lib.c icat_lib.c ifind_lib.c ils_lib.c

libfstools_la_LIBADD	= ../auxtools/libauxtools.la ../imgtools/libimgtools.la
dbtool_LDADD		= libfstools.la ../../../lib/libexcept.la

#ils_LDADD		= libfstools.la
#dls_LDADD		= libfstools.la
#icat_LDADD		= libfstools.la
#fls_LDADD		= libfstools.la
#dcat_LDADD		= libfstools.la
#ffind_LDADD		= libfstools.la
#istat_LDADD		= libfstools.la
#ifind_LDADD		= libfstools.la
#dcalc_LDADD		= libfstools.la
#dstat_LDADD		= libfstools.la
#fsstat_LDADD		= libfstools.la
#jls_LDADD		= libfstools.la
#jcat_LDADD		= libfstools.la
