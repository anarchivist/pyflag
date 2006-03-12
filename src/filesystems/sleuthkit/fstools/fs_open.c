/*
** fs_open
** The Sleuth Kit 
**
** $Date: 2005/10/13 04:15:21 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.
*/

/* TCT */
/*++
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

#include "fs_tools.h"

/* fs_open - open a file system */

FS_INFO *
fs_open(IMG_INFO * img_info, const char *type)
{

    /* We will try different file systems ... 
     * We need to try all of them in case more than one matches
     */
    if (type == NULL) {
	FS_INFO *fs_info, *fs_set = NULL;
	char *set = NULL;

	if ((fs_info = ntfs_open(img_info, NTFS, 1)) != NULL) {
	    set = "NTFS";
	    fs_set = fs_info;
	}

	if ((fs_info = fatfs_open(img_info, FATAUTO, 1)) != NULL) {
	    if (set == NULL) {
		set = "FAT";
		fs_set = fs_info;
	    }
	    else {
		fs_set->close(fs_set);
		fs_info->close(fs_info);
		error("Cannot determine if FAT or %s", set);
	    }
	}

	if ((fs_info = ext2fs_open(img_info, EXTAUTO, 1)) != NULL) {
	    if (set == NULL) {
		set = "EXT2/3";
		fs_set = fs_info;
	    }
	    else {
		fs_set->close(fs_set);
		fs_info->close(fs_info);
		error("Cannot determine if EXT2/3 or %s", set);
	    }
	}

	if ((fs_info = ffs_open(img_info, FFSAUTO, 1)) != NULL) {
	    if (set == NULL) {
		set = "UFS";
		fs_set = fs_info;
	    }
	    else {
		fs_set->close(fs_set);
		fs_info->close(fs_info);
		error("Cannot determine if UFS or %s", set);
	    }
	}

	if ((fs_info = hfs_open(img_info, HFS, 1)) != NULL) {
	    if (set == NULL) {
		set = "HFS";
		fs_set = fs_info;
	    }
	    else {
		fs_set->close(fs_set);
		fs_info->close(fs_info);
		error("Cannot determine if HFS or %s", set);
	    }
	}
	if ((fs_info = iso9660_open(img_info, ISO9660, 1)) != NULL) {
	   if (set != NULL) {
	       fs_set->close(fs_set);
	       fs_info->close(fs_info);
	       error("Cannot determine if ISO9660 or %s", set);
	   }
	   fs_set = fs_info;
	}

	if (fs_set != NULL) {
	    return fs_set;
	}
	else {
	    printf("Cannot determine file system type\n");
	    exit(1);
	}
    }
    else {
	unsigned char ftype;
	ftype = fs_parse_type(type);

	switch (ftype & FSMASK) {
	case FFS_TYPE:
	    return ffs_open(img_info, ftype, 0);
	case EXTxFS_TYPE:
	    return ext2fs_open(img_info, ftype, 0);
	case FATFS_TYPE:
	    return fatfs_open(img_info, ftype, 0);
	case NTFS_TYPE:
	    return ntfs_open(img_info, ftype, 0);
	case ISO9660_TYPE:
	    return iso9660_open(img_info, ftype, 0);
	case HFS_TYPE:
	    return hfs_open(img_info, ftype, 0);
	case RAWFS_TYPE:
	    return rawfs_open(img_info, ftype);
	case SWAPFS_TYPE:
	    return swapfs_open(img_info, ftype);
	case UNSUPP_FS:
	default:
	    fprintf(stderr, "unknown filesystem type: %s\n", type);
	    fprintf(stderr, "known types:\n");
	    fs_print_types(stderr);
	    exit(1);
	}
    }
    return NULL;
}
