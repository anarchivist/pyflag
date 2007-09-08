/*
** ffs_dent
** The  Sleuth Kit 
**
** $Date: 2007/05/17 19:32:28 $
**
** File name layer for a FFS/UFS image 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2006 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file ffs_dent.c
 * UFS/FFS file name (directory entry) processing / walking functions
 */

#include <ctype.h>
#include "fs_tools_i.h"
#include "ffs.h"


#define MAX_DEPTH   128
#define DIR_STRSZ   4096

typedef struct {
    /* Recursive path stuff */

    /* how deep in the directory tree are we */
    unsigned int depth;

    /* pointer in dirs string to where '/' is for given depth */
    char *didx[MAX_DEPTH];

    /* The current directory name string */
    char dirs[DIR_STRSZ];

} FFS_DINFO;

static uint8_t ffs_dent_walk_lcl(TSK_FS_INFO *, FFS_DINFO *, TSK_LIST **,
    INUM_T, TSK_FS_DENT_FLAG_ENUM, TSK_FS_DENT_TYPE_WALK_CB, void *);


/* 
** copy OS specific directory inode to generic TSK_FS_DENT
 * 
 * Note that this does not set the flags value
 *
 * Return 1 on error and 0 on success
 */
static uint8_t
ffs_dent_copy(FFS_INFO * ffs, FFS_DINFO * dinfo, char *ffs_dent,
    TSK_FS_DENT * fs_dent)
{
    TSK_FS_INFO *fs = &(ffs->fs_info);
    int i;

    /* this one has the type field */
    if ((fs->ftype == TSK_FS_INFO_TYPE_FFS_1)
        || (fs->ftype == TSK_FS_INFO_TYPE_FFS_2)) {
        ffs_dentry1 *dir = (ffs_dentry1 *) ffs_dent;

        fs_dent->inode = tsk_getu32(fs->endian, dir->d_ino);

        if (fs_dent->name_max != FFS_MAXNAMLEN) {
            if ((fs_dent =
                    tsk_fs_dent_realloc(fs_dent, FFS_MAXNAMLEN)) == NULL)
                return 1;
        }

        /* ffs null terminates so we can strncpy */
        strncpy(fs_dent->name, dir->d_name, fs_dent->name_max);

        /* generic types are same as FFS */
        fs_dent->ent_type = dir->d_type;

    }
    else if (fs->ftype == TSK_FS_INFO_TYPE_FFS_1B) {
        ffs_dentry2 *dir = (ffs_dentry2 *) ffs_dent;

        fs_dent->inode = tsk_getu32(fs->endian, dir->d_ino);

        if (fs_dent->name_max != FFS_MAXNAMLEN) {
            if ((fs_dent =
                    tsk_fs_dent_realloc(fs_dent, FFS_MAXNAMLEN)) == NULL)
                return 1;
        }

        /* ffs null terminates so we can strncpy */
        strncpy(fs_dent->name, dir->d_name, fs_dent->name_max);

        fs_dent->ent_type = TSK_FS_DENT_TYPE_UNDEF;
    }
    else {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ffs_dent_copy: Unknown FS type");
        return 1;
    }

    /* Clean up name */
    i = 0;
    while (fs_dent->name[i] != '\0') {
        if (TSK_IS_CNTRL(fs_dent->name[i]))
            fs_dent->name[i] = '^';
        i++;
    }

    /* copy the path data */
    fs_dent->path = dinfo->dirs;
    fs_dent->pathdepth = dinfo->depth;

    if ((fs != NULL) && (fs_dent->inode)
        && (fs_dent->inode <= fs->last_inum)) {
        /* Get inode */
        if (fs_dent->fsi)
            tsk_fs_inode_free(fs_dent->fsi);

        if ((fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode)) == NULL) {
            strncat(tsk_errstr2, " - ffs_dent_copy",
                TSK_ERRSTR_L - strlen(tsk_errstr2));
            return 1;
        }
    }
    else {
        if (fs_dent->fsi)
            tsk_fs_inode_free(fs_dent->fsi);
        fs_dent->fsi = NULL;
    }

    fs_dent->flags = 0;
    return 0;
}


/* Scan the buffer for directory entries and call action on each.
** Flags will be
** set to TSK_FS_DENT_FLAG_ALLOC for acive entires and TSK_FS_DENT_FLAG_UNALLOC for
** deleted ones
**
** len is size of buf
**
** return 0 on success, -1 on error, and 1 to stop 
*/
static int
ffs_dent_parse_block(FFS_INFO * ffs, FFS_DINFO * dinfo,
    TSK_LIST ** list_seen, char *buf, unsigned int len, int flags,
    TSK_FS_DENT_TYPE_WALK_CB action, void *ptr)
{
    unsigned int idx;
    unsigned int inode = 0, dellen = 0, reclen = 0;
    unsigned int minreclen = 4;
    TSK_FS_INFO *fs = &(ffs->fs_info);

    char *dirPtr;
    TSK_FS_DENT *fs_dent;

    if ((fs_dent = tsk_fs_dent_alloc(FFS_MAXNAMLEN + 1, 0)) == NULL)
        return -1;

    /* update each time by the actual length instead of the
     ** recorded length so we can view the deleted entries 
     */
    for (idx = 0; idx <= len - FFS_DIRSIZ_lcl(1); idx += minreclen) {
        unsigned int namelen = 0;

        dirPtr = (char *) &buf[idx];

        /* copy to local variables */
        if ((fs->ftype == TSK_FS_INFO_TYPE_FFS_1)
            || (fs->ftype == TSK_FS_INFO_TYPE_FFS_2)) {
            ffs_dentry1 *dir = (ffs_dentry1 *) dirPtr;
            inode = tsk_getu32(fs->endian, dir->d_ino);
            namelen = dir->d_namlen;
            reclen = tsk_getu16(fs->endian, dir->d_reclen);
        }
        /* TSK_FS_INFO_TYPE_FFS_1B */
        else if (fs->ftype == TSK_FS_INFO_TYPE_FFS_1B) {
            ffs_dentry2 *dir = (ffs_dentry2 *) dirPtr;
            inode = tsk_getu32(fs->endian, dir->d_ino);
            namelen = tsk_getu16(fs->endian, dir->d_namlen);
            reclen = tsk_getu16(fs->endian, dir->d_reclen);
        }

        /* what is the minimum size needed for this entry */
        minreclen = FFS_DIRSIZ_lcl(namelen);

        /* Perform a couple sanity checks 
         ** OpenBSD never zeros the inode number, but solaris
         ** does.  These checks will hopefully catch all non
         ** entries 
         */
        if ((inode > fs->last_inum) ||
            (inode < 0) ||
            (namelen > FFS_MAXNAMLEN) ||
            (namelen <= 0) ||
            (reclen < minreclen) || (reclen % 4) || (idx + reclen > len)) {

            /* we don't have a valid entry, so skip ahead 4 */
            minreclen = 4;
            if (dellen > 0)
                dellen -= 4;
            continue;
        }

        /* Before we process an entry in unallocated space, make
         * sure that it also ends in the unalloc space */
        if ((dellen) && (dellen < minreclen)) {
            minreclen = 4;
            if (dellen)
                dellen -= 4;

            continue;
        }

        /* the entry is valid */
        if (ffs_dent_copy(ffs, dinfo, dirPtr, fs_dent)) {
            tsk_fs_dent_free(fs_dent);
            return -1;
        }

        /* Do we have a deleted entry? (are we in a deleted space) */
        if ((dellen > 0) || (inode == 0)) {
            fs_dent->flags = TSK_FS_DENT_FLAG_UNALLOC;
            if (dellen)
                dellen -= minreclen;

            if (flags & TSK_FS_DENT_FLAG_UNALLOC) {
                int retval;
                retval = action(fs, fs_dent, ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_fs_dent_free(fs_dent);
                    return 1;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_fs_dent_free(fs_dent);
                    return -1;
                }
            }
        }
        else {
            fs_dent->flags = TSK_FS_DENT_FLAG_ALLOC;
            if (flags & TSK_FS_DENT_FLAG_ALLOC) {
                int retval;
                retval = action(fs, fs_dent, ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_fs_dent_free(fs_dent);
                    return 1;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_fs_dent_free(fs_dent);
                    return -1;
                }
            }
        }

        /* If we have some slack, the set dellen */
        if ((reclen != minreclen) && (dellen <= 0))
            dellen = reclen - minreclen;


        /* if we have a directory and the RECURSE flag is set, then
         * lets do it
         */
        if ((fs_dent->flags & TSK_FS_DENT_FLAG_ALLOC) &&
            (flags & TSK_FS_DENT_FLAG_RECURSE) &&
            (!TSK_FS_ISDOT(fs_dent->name)) &&
            ((fs_dent->fsi->mode & TSK_FS_INODE_MODE_FMT) ==
                TSK_FS_INODE_MODE_DIR)) {
            int depth_added = 0;

            /* Make sure we do not get into an infinite loop */
            if (0 == tsk_list_find(*list_seen, fs_dent->inode)) {
                if (tsk_list_add(list_seen, fs_dent->inode)) {
                    tsk_fs_dent_free(fs_dent);
                    return -1;
                }

                /* save the path */
                if ((dinfo->depth < MAX_DEPTH) &&
                    (DIR_STRSZ >
                        strlen(dinfo->dirs) + strlen(fs_dent->name))) {
                    dinfo->didx[dinfo->depth] =
                        &dinfo->dirs[strlen(dinfo->dirs)];
                    strncpy(dinfo->didx[dinfo->depth], fs_dent->name,
                        DIR_STRSZ - strlen(dinfo->dirs));
                    strncat(dinfo->dirs, "/", DIR_STRSZ);
                    depth_added = 1;
                }
                dinfo->depth++;

                /* Call ourselves again */
                if (ffs_dent_walk_lcl(&(ffs->fs_info), dinfo, list_seen,
                        fs_dent->inode, flags, action, ptr)) {
                    /* If the directory could not be loaded, 
                     * then move on */
                    if (tsk_verbose) {
                        tsk_fprintf(stderr,
                            "ffs_dent_parse_block: error reading directory: %"
                            PRIuINUM "\n", fs_dent->inode);
                        tsk_error_print(stderr);
                    }
                    tsk_error_reset();
                }

                dinfo->depth--;
                if (depth_added)
                    *dinfo->didx[dinfo->depth] = '\0';
            }
        }

    }                           /* end for size */

    tsk_fs_dent_free(fs_dent);
    return 0;
}                               /* end ffs_dent_parse_block */



/* Process _inode_ as a directory inode and process the data blocks
** as file entries.  Call action on all entries with the flags set to
** TSK_FS_DENT_FLAG_ALLOC for active entries
**
**
** Use the following flags: TSK_FS_DENT_FLAG_ALLOC, TSK_FS_DENT_FLAG_UNALLOC, 
** TSK_FS_DENT_FLAG_RECURSE
 *
 * returns 1 on error and 0 on success
 */
uint8_t
ffs_dent_walk(TSK_FS_INFO * fs, INUM_T inode, TSK_FS_DENT_FLAG_ENUM flags,
    TSK_FS_DENT_TYPE_WALK_CB action, void *ptr)
{
    FFS_DINFO dinfo;
    TSK_LIST *list_seen = NULL;
    int retval;

    // clean up any error messages that are lying around
    tsk_error_reset();

    memset(&dinfo, 0, sizeof(FFS_DINFO));
    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((flags & TSK_FS_DENT_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_DENT_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_UNALLOC);
    }

    retval =
        ffs_dent_walk_lcl(fs, &dinfo, &list_seen, inode, flags, action,
        ptr);
    tsk_list_free(list_seen);
    list_seen = NULL;
    return retval;

}

/* Return 0 on success and 1 on error */
static uint8_t
ffs_dent_walk_lcl(TSK_FS_INFO * fs, FFS_DINFO * dinfo,
    TSK_LIST ** list_seen, INUM_T inode, TSK_FS_DENT_FLAG_ENUM flags,
    TSK_FS_DENT_TYPE_WALK_CB action, void *ptr)
{
    OFF_T size;
    TSK_FS_INODE *fs_inode;
    FFS_INFO *ffs = (FFS_INFO *) fs;
    char *dirbuf;
    int nchnk, cidx;
    TSK_FS_LOAD_FILE load_file;
    int retval = 0;

    if (inode < fs->first_inum || inode > fs->last_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ffs_dent_walk_lcl: Invalid inode value: %" PRIuINUM, inode);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ffs_dent_walk: Processing directory %" PRIuINUM "\n", inode);

    if ((fs_inode = fs->inode_lookup(fs, inode)) == NULL) {
        strncat(tsk_errstr2, " - ffs_dent_walk_lcl",
            TSK_ERRSTR_L - strlen(tsk_errstr2));
        return 1;
    }

    /* make a copy of the directory contents that we can process */
    /* round up cause we want the slack space too */
    size = roundup(fs_inode->size, FFS_DIRBLKSIZ);
    if ((dirbuf = tsk_malloc((size_t) size)) == NULL) {
        tsk_fs_inode_free(fs_inode);
        return 1;
    }

    load_file.total = load_file.left = (size_t) size;
    load_file.base = load_file.cur = dirbuf;

    if (fs->file_walk(fs, fs_inode, 0, 0,
            TSK_FS_FILE_FLAG_SLACK | TSK_FS_FILE_FLAG_NOID,
            tsk_fs_load_file_action, (void *) &load_file)) {
        free(dirbuf);
        tsk_fs_inode_free(fs_inode);
        strncat(tsk_errstr2, " - ffs_dent_walk_lcl",
            TSK_ERRSTR_L - strlen(tsk_errstr2));
        return 1;
    }

    /* Not all of the directory was copied, so we return */
    if (load_file.left > 0) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_FWALK;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ffs_dent_walk: Error reading directory %" PRIuINUM, inode);
        free(dirbuf);
        tsk_fs_inode_free(fs_inode);
        return 1;
    }

    /* Directory entries are written in chunks of DIRBLKSIZ
     ** determine how many chunks of this size we have to read to
     ** get a full block
     **
     ** Entries do not cross over the DIRBLKSIZ boundary
     */
    nchnk = (int) (size) / (FFS_DIRBLKSIZ) + 1;

    for (cidx = 0; cidx < nchnk && (int64_t) size > 0; cidx++) {
        int len = (FFS_DIRBLKSIZ < size) ? FFS_DIRBLKSIZ : (int) size;

        retval =
            ffs_dent_parse_block(ffs, dinfo, list_seen,
            dirbuf + cidx * FFS_DIRBLKSIZ, len, flags, action, ptr);

        /* one is returned when the action wants to stop */
        if ((retval == 1) || (retval == -1))
            break;

        size -= len;
    }

    tsk_fs_inode_free(fs_inode);
    free(dirbuf);
    if (retval == -1)
        return 1;
    else
        return 0;
}
