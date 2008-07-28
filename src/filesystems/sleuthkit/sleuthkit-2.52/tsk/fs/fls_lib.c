/*
** fls
** The Sleuth Kit 
**
** $Date: 2008/01/30 14:26:21 $
**
** Given an image and directory inode, display the file names and 
** directories that exist (both active and deleted)
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carier.  All rights reserved
**
** TASK
** Copyright (c) 2002 @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/** \file fls_lib.c 
 * Contains the library code associated with the 'fls' functionality of listing files in a directory.
 */

#include "tsk_fs_i.h"
#include "tsk_ntfs.h"

/* Time skew of the system in seconds */
static int32_t sec_skew = 0;


/*directory prefix for printing mactime output */
static char *macpre = NULL;

static int localflags;



/* this is a wrapper type function that takes care of the runtime
 * flags
 * 
 * fs_data should be set to NULL for all NTFS file systems
 */
static void
printit(TSK_FS_INFO * fs, TSK_FS_DENT * fs_dent, TSK_FS_DATA * fs_data)
{
    unsigned int i;

    if (!(localflags & TSK_FS_FLS_FULL)) {
        for (i = 0; i < fs_dent->pathdepth; i++)
            tsk_fprintf(stdout, "+");

        if (fs_dent->pathdepth)
            tsk_fprintf(stdout, " ");
    }


    if (localflags & TSK_FS_FLS_MAC) {
        if ((sec_skew != 0) && (fs_dent->fsi)) {
            fs_dent->fsi->mtime -= sec_skew;
            fs_dent->fsi->atime -= sec_skew;
            fs_dent->fsi->ctime -= sec_skew;
        }

        tsk_fs_dent_print_mac(stdout, fs_dent, fs, fs_data, macpre);

        if ((sec_skew != 0) && (fs_dent->fsi)) {
            fs_dent->fsi->mtime += sec_skew;
            fs_dent->fsi->atime += sec_skew;
            fs_dent->fsi->ctime += sec_skew;
        }
    }

    else if (localflags & TSK_FS_FLS_LONG) {
        if ((sec_skew != 0) && (fs_dent->fsi)) {
            fs_dent->fsi->mtime -= sec_skew;
            fs_dent->fsi->atime -= sec_skew;
            fs_dent->fsi->ctime -= sec_skew;
        }

        if (TSK_FS_FLS_FULL & localflags)
            tsk_fs_dent_print_long(stdout, fs_dent, fs, fs_data);
        else {
            char *tmpptr = fs_dent->path;
            fs_dent->path = NULL;
            tsk_fs_dent_print_long(stdout, fs_dent, fs, fs_data);
            fs_dent->path = tmpptr;
        }

        if ((sec_skew != 0) && (fs_dent->fsi)) {
            fs_dent->fsi->mtime += sec_skew;
            fs_dent->fsi->atime += sec_skew;
            fs_dent->fsi->ctime += sec_skew;
        }
    }
    else {
        if (TSK_FS_FLS_FULL & localflags)
            tsk_fs_dent_print(stdout, fs_dent, fs, fs_data);
        else {
            char *tmpptr = fs_dent->path;
            fs_dent->path = NULL;
            tsk_fs_dent_print(stdout, fs_dent, fs, fs_data);
            fs_dent->path = tmpptr;
        }
        tsk_printf("\n");
    }
}


/* 
 * call back action function for dent_walk
 */
static TSK_WALK_RET_ENUM
print_dent_act(TSK_FS_INFO * fs, TSK_FS_DENT * fs_dent, void *ptr)
{

    /* only print dirs if TSK_FS_FLS_DIR is set and only print everything
     ** else if TSK_FS_FLS_FILE is set (or we aren't sure what it is)
     */
    if (((localflags & TSK_FS_FLS_DIR) &&
            ((fs_dent->fsi) &&
                ((fs_dent->fsi->mode & TSK_FS_INODE_MODE_FMT) ==
                    TSK_FS_INODE_MODE_DIR)))
        || ((localflags & TSK_FS_FLS_FILE) && (((fs_dent->fsi)
                    && ((fs_dent->fsi->mode & TSK_FS_INODE_MODE_FMT) !=
                        TSK_FS_INODE_MODE_DIR))
                || (!fs_dent->fsi)))) {


        /* Make a special case for NTFS so we can identify all of the
         * alternate data streams!
         */
        if (((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
                TSK_FS_INFO_TYPE_NTFS_TYPE)
            && (fs_dent->fsi)) {

            TSK_FS_DATA *fs_data = fs_dent->fsi->attr;
            uint8_t printed = 0;

            while (fs_data) {
                if ((fs_data->flags & TSK_FS_DATA_INUSE) == 0) {
                    fs_data = fs_data->next;
                    continue;
                }

                if (fs_data->type == NTFS_ATYPE_DATA) {
                    mode_t mode = fs_dent->fsi->mode;
                    uint8_t ent_type = fs_dent->ent_type;

                    printed = 1;


                    /* 
                     * A directory can have a Data stream, in which
                     * case it would be printed with modes of a
                     * directory, although it is really a file
                     * So, to avoid confusion we will set the modes
                     * to a file so it is printed that way.  The
                     * entry for the directory itself will still be
                     * printed as a directory
                     */

                    if ((fs_dent->fsi->mode & TSK_FS_INODE_MODE_FMT) ==
                        TSK_FS_INODE_MODE_DIR) {


                        /* we don't want to print the ..:blah stream if
                         * the -a flag was not given
                         */
                        if ((fs_dent->name[0] == '.') && (fs_dent->name[1])
                            && (fs_dent->name[2] == '\0') &&
                            ((localflags & TSK_FS_FLS_DOT) == 0)) {
                            fs_data = fs_data->next;
                            continue;
                        }

                        fs_dent->fsi->mode &= ~TSK_FS_INODE_MODE_FMT;
                        fs_dent->fsi->mode |= TSK_FS_INODE_MODE_REG;
                        fs_dent->ent_type = TSK_FS_DENT_TYPE_REG;
                    }

                    printit(fs, fs_dent, fs_data);

                    fs_dent->fsi->mode = mode;
                    fs_dent->ent_type = ent_type;
                }
                else if (fs_data->type == NTFS_ATYPE_IDXROOT) {
                    printed = 1;

                    /* If it is . or .. only print it if the flags say so,
                     * we continue with other streams though in case the 
                     * directory has a data stream 
                     */
                    if (!((TSK_FS_ISDOT(fs_dent->name)) &&
                            ((localflags & TSK_FS_FLS_DOT) == 0)))
                        printit(fs, fs_dent, fs_data);
                }

                fs_data = fs_data->next;
            }

            /* A user reported that an allocated file had the standard
             * attributes, but no $Data.  We should print something */
            if (printed == 0) {
                printit(fs, fs_dent, NULL);
            }

        }
        else {
            /* skip it if it is . or .. and we don't want them */
            if (!((TSK_FS_ISDOT(fs_dent->name))
                    && ((localflags & TSK_FS_FLS_DOT) == 0)))
                printit(fs, fs_dent, NULL);
        }
    }
    return TSK_WALK_CONT;
}


/* Returns 0 on success and 1 on error */
uint8_t
tsk_fs_fls(TSK_FS_INFO * fs, uint8_t lclflags, TSK_INUM_T inode, int flags,
    TSK_TCHAR * tpre, int32_t skew)
{

    localflags = lclflags;
    sec_skew = skew;

#ifdef TSK_WIN32
    {
        char *cpre;
        size_t clen;
        UTF8 *ptr8;
        UTF16 *ptr16;
        int retval;

        if (tpre != NULL) {
            clen = TSTRLEN(tpre) * 4;
            cpre = (char *) talloc_size(fs, clen);
            if (cpre == NULL) {
                return 1;
            }
            ptr8 = (UTF8 *) cpre;
            ptr16 = (UTF16 *) tpre;

            retval =
                tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &ptr16,
                (UTF16 *)
                & ptr16[TSTRLEN(tpre) + 1], &ptr8,
                (UTF8 *) ((uintptr_t) ptr8 + clen), TSKlenientConversion);
            if (retval != TSKconversionOK) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_UNICODE;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "Error converting fls mactime pre-text to UTF-8 %d\n",
                    retval);
                return 1;
            }
            macpre = cpre;
        }
        else {
            macpre = NULL;
            cpre = NULL;
        }

        retval = fs->dent_walk(fs, inode, flags, print_dent_act, NULL);

        if (cpre)
            talloc_free(cpre);

        return retval;
    }
#else
    macpre = tpre;
    return fs->dent_walk(fs, inode, flags, print_dent_act, NULL);
#endif
}
