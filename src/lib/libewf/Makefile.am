bin_PROGRAMS		= ewfacquire ewfinfo ewfexport ewfverify
pkglib_LTLIBRARIES		= libewf.la
noinst_HEADERS  = $(srcdir)/*.h

libewf_la_SOURCES    = libewf_endian.c ewf_compress.c ewf_crc.c ewf_data.c   	 \
	ewf_error2.c ewf_file_header.c ewf_hash.c ewf_header.c ewf_header2.c	 \
	 ewf_md5hash.c ewf_section.c ewf_sectors.c ewf_table.c ewf_volume.c	 \
	ewf_volume_smart.c handle.c header_values.c file.c file_read.c file_write.c  \
	notify.c offset_table.c section_list.c segment_table.c

libewf_la_LDFLAGS	   = -lz
libewf_la_LIBADD	   = ../libexcept.la ../libmd5.la

ewfacquire_SOURCES  =  ewfacquire.c
ewfacquire_LDADD	   = libewf.la

ewfinfo_SOURCES        = ewfinfo.c
ewfinfo_LDADD	    = libewf.la

ewfexport_SOURCES   = ewfexport.c
ewfexport_LDADD       =  libewf.la

ewfverify_SOURCES    = ewfverify.c
ewfverify_LDADD	  = libewf.la
