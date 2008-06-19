/*
** tsk_fs_open
** The Sleuth Kit 
**
** $Date: 2007/12/19 23:12:04 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
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

#include "tsk_fs_i.h"

/**
 * \file fs_open.c
 * Contains the general code to open a file system -- this calls
 * the file system -specific opening routines. 
 */

/**
 * Tries to open data (at a given offset) as a file system. 
 * Returns a structure that can be used for analysis and reporting. 
 *
 * @param img_info Disk image to analyze
 * @param offset Byte offset to start analyzing from
 * @param type String type of file system type 
 * (autodetects if set to NULL)
 *
 * @return NULL on error 
 */

TSK_FS_INFO *
tsk_fs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    const TSK_TCHAR * type)
{

    /* We will try different file systems ... 
     * We need to try all of them in case more than one matches
     */
    if (type == NULL) {
        TSK_FS_INFO *fs_info, *fs_set = NULL;
        char *set = NULL;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fsopen: Auto detection mode at offset %" PRIuOFF "\n",
                offset);

        if ((fs_info =
                ntfs_open(img_info, offset, TSK_FS_INFO_TYPE_NTFS_AUTO,
                    1)) != NULL) {
            set = "NTFS";
            fs_set = fs_info;
        }
        else {
            tsk_error_reset();
        }

        if ((fs_info =
                fatfs_open(img_info, offset, TSK_FS_INFO_TYPE_FAT_AUTO,
                    1)) != NULL) {
            if (set == NULL) {
                set = "FAT";
                fs_set = fs_info;
            }
            else {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_UNKTYPE;
                snprintf(tsk_errstr, TSK_ERRSTR_L, "FAT or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }

        if ((fs_info =
                ext2fs_open(img_info, offset, TSK_FS_INFO_TYPE_EXT_AUTO,
                    1)) != NULL) {
            if (set == NULL) {
                set = "EXT2/3";
                fs_set = fs_info;
            }
            else {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_UNKTYPE;
                snprintf(tsk_errstr, TSK_ERRSTR_L, "EXT2/3 or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }

        if ((fs_info =
                ffs_open(img_info, offset,
                    TSK_FS_INFO_TYPE_FFS_AUTO)) != NULL) {
            if (set == NULL) {
                set = "UFS";
                fs_set = fs_info;
            }
            else {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_UNKTYPE;
                snprintf(tsk_errstr, TSK_ERRSTR_L, "UFS or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }


#if TSK_USE_HFS
        if ((fs_info =
                hfs_open(img_info, offset, TSK_FS_INFO_TYPE_HFS,
                    1)) != NULL) {
            if (set == NULL) {
                set = "HFS";
                fs_set = fs_info;
            }
            else {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_UNKTYPE;
                snprintf(tsk_errstr, TSK_ERRSTR_L, "HFS or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }
#endif

        if ((fs_info =
                iso9660_open(img_info, offset, TSK_FS_INFO_TYPE_ISO9660,
                    1)) != NULL) {
            if (set != NULL) {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_UNKTYPE;
                snprintf(tsk_errstr, TSK_ERRSTR_L, "ISO9660 or %s", set);
                return NULL;
            }
            fs_set = fs_info;
        }
        else {
            tsk_error_reset();
        }


        if (fs_set == NULL) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_UNKTYPE;
            tsk_errstr[0] = '\0';
            tsk_errstr2[0] = '\0';
            return NULL;
        }
        return fs_set;
    }
    else {
        uint8_t ftype;
        ftype = tsk_fs_parse_type(type);

        switch (ftype & TSK_FS_INFO_TYPE_FS_MASK) {
        case TSK_FS_INFO_TYPE_FFS_TYPE:
            return ffs_open(img_info, offset, ftype);
        case TSK_FS_INFO_TYPE_EXT_TYPE:
            return ext2fs_open(img_info, offset, ftype, 0);
        case TSK_FS_INFO_TYPE_FAT_TYPE:
            return fatfs_open(img_info, offset, ftype, 0);
        case TSK_FS_INFO_TYPE_NTFS_TYPE:
            return ntfs_open(img_info, offset, ftype, 0);
        case TSK_FS_INFO_TYPE_ISO9660_TYPE:
            return iso9660_open(img_info, offset, ftype, 0);
#if 0
        case TSK_FS_INFO_TYPE_HFS_TYPE:
            return hfs_open(img_info, offset, ftype, 0);
#endif
        case TSK_FS_INFO_TYPE_RAW_TYPE:
            return rawfs_open(img_info, offset);
        case TSK_FS_INFO_TYPE_SWAP_TYPE:
            return swapfs_open(img_info, offset);
        case TSK_FS_INFO_TYPE_UNSUPP:
        default:
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_UNSUPTYPE;
            snprintf(tsk_errstr, TSK_ERRSTR_L, "%s", type);
            return NULL;
        }
    }
}
