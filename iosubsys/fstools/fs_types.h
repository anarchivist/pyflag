/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
*/

#ifndef _FS_TYPES_H
#define _FS_TYPES_H

extern char fs_parse_type(const char *);
extern void fs_print_types();

/*
** the most-sig-nibble is the file system type, which indictates which
** _open function to call.  The least-sig-nibble is the specific type
** of implementation.  
*/
#define FSMASK			0xf0
#define OSMASK			0x0f

#define UNSUPP_FS       0x00

/* FFS */
#define FFS_TYPE		0x10

#define FFS_1			0x11	/* FreeBSD, OpenBSD, BSDI ... */
#define FFS_2			0x12	/* Solaris (no type) */


#define	EXTxFS_TYPE		0x20
#define EXT2FS			0x21	
#define EXT3FS			0x22	
#define EXTAUTO			0x23

/* FAT */
#define FATFS_TYPE		0x30

#define MS12_FAT        0x31
#define MS16_FAT        0x32
#define MS32_FAT        0x33
#define MSAUTO_FAT		0x34

#define NTFS_TYPE		0x40
#define NTFS         0x40

#define	SWAPFS_TYPE		0x50
#define	SWAP			0x50

#define	RAWFS_TYPE		0x60
#define	RAW				0x60

#endif
