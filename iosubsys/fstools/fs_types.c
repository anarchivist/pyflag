/*
** fs_types
** The Sleuth Kit 
**
** Identify the type of file system being used
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
*/

#include "fs_tools.h"

/* Based on fs_open.c in TCT-1.07 */

typedef struct {
    char	*name;
	char code;
	char	*comment;
} FS_TYPES;

FS_TYPES fs_open_table[] = {
	{"bsdi", FFS_1, "BSDi FFS"},
	{"fat", MSAUTO_FAT, "auto-detect FAT"},
	{"fat12", MS12_FAT, "FAT12"},
	{"fat16", MS16_FAT, "FAT16"},
	{"fat32", MS32_FAT, "FAT32"},
	{"freebsd", FFS_1, "FreeBSD FFS"},
	{"linux-ext", EXTAUTO, "auto-detect Linux EXTxFS"},
	{"linux-ext2", EXT2FS, "Linux EXT2FS"},
	{"linux-ext3", EXT3FS, "Linux EXT3FS"},
	{"netbsd", FFS_1, "NetBSD FFS"},
	{"ntfs", NTFS, "NTFS"},
	{"openbsd", FFS_1, "OpenBSD FFS"},
	{"raw", RAW, "Raw Data"},
	{"solaris", FFS_2, "Solaris FFS"},
	{"swap", SWAP, "Swap Space"},
	{0},
};


char
fs_parse_type(const char *str) 
{
    FS_TYPES *sp;
    if(str)
	for (sp = fs_open_table; sp->name; sp++) {
		if (strcmp(str, sp->name) == 0) {
			return sp->code;
		}
	}
	return UNSUPP_FS;
}

void 
fs_print_types() 
{
	FS_TYPES *sp;
	for (sp = fs_open_table; sp->name; sp++)
		printf("\t%s (%s)\n", sp->name, sp->comment);
}

