/*
** ext2fs_dent
** The Sleuth Kit 
**
** $Date: 2008/03/21 16:31:41 $
**
** File name layer support for an TSK_FS_INFO_TYPE_EXT_2 image
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2006 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILS
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file ext2fs_dent.c
 * File name walking / processing code for Ext2 / ext3
 */

#include <ctype.h>
#include "tsk_fs_i.h"
#include "tsk_ext2fs.h"

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

} EXT2FS_DINFO;


static uint8_t ext2fs_dent_walk_lcl(TSK_FS_INFO *, EXT2FS_DINFO *,
    TSK_LIST **, TSK_INUM_T, TSK_FS_DENT_FLAG_ENUM,
    TSK_FS_DENT_TYPE_WALK_CB, void *);

/* 
 *
 * NoTe that this does not set the flag value.
 *
 * return 1 on error and 0 on success */
static uint8_t
ext2fs_dent_copy(EXT2FS_INFO * ext2fs, EXT2FS_DINFO * dinfo,
    char *ext2_dent, TSK_FS_DENT * fs_dent)
{
    TSK_FS_INFO *fs = &(ext2fs->fs_info);
    int i;

    if (ext2fs->deentry_type == EXT2_DE_V1) {
        ext2fs_dentry1 *dir = (ext2fs_dentry1 *) ext2_dent;

        fs_dent->inode = tsk_getu32(fs->endian, dir->inode);

        /* ext2 does not null terminate */
        if (tsk_getu16(fs->endian, dir->name_len) >= fs_dent->name_max) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_ARG;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "ext2fs_dent_copy: Name Space too Small %d %zu",
                tsk_getu16(fs->endian, dir->name_len), fs_dent->name_max);
            return 1;
        }

        /* Copy and Null Terminate */
        strncpy(fs_dent->name, dir->name, tsk_getu16(fs->endian,
                dir->name_len));
        fs_dent->name[tsk_getu16(fs->endian, dir->name_len)] = '\0';

        fs_dent->ent_type = TSK_FS_DENT_TYPE_UNDEF;
    }
    else {
        ext2fs_dentry2 *dir = (ext2fs_dentry2 *) ext2_dent;

        fs_dent->inode = tsk_getu32(fs->endian, dir->inode);

        /* ext2 does not null terminate */
        if (dir->name_len >= fs_dent->name_max) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_ARG;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "ext2_dent_copy: Name Space too Small %d %zu",
                dir->name_len, fs_dent->name_max);
            return 1;
        }

        /* Copy and Null Terminate */
        strncpy(fs_dent->name, dir->name, dir->name_len);
        fs_dent->name[dir->name_len] = '\0';

        switch (dir->type) {
        case EXT2_DE_REG_FILE:
            fs_dent->ent_type = TSK_FS_DENT_TYPE_REG;
            break;
        case EXT2_DE_DIR:
            fs_dent->ent_type = TSK_FS_DENT_TYPE_DIR;
            break;
        case EXT2_DE_CHRDEV:
            fs_dent->ent_type = TSK_FS_DENT_TYPE_CHR;
            break;
        case EXT2_DE_BLKDEV:
            fs_dent->ent_type = TSK_FS_DENT_TYPE_BLK;
            break;
        case EXT2_DE_FIFO:
            fs_dent->ent_type = TSK_FS_DENT_TYPE_FIFO;
            break;
        case EXT2_DE_SOCK:
            fs_dent->ent_type = TSK_FS_DENT_TYPE_SOCK;
            break;
        case EXT2_DE_SYMLINK:
            fs_dent->ent_type = TSK_FS_DENT_TYPE_LNK;
            break;
        case EXT2_DE_UNKNOWN:
        default:
            fs_dent->ent_type = TSK_FS_DENT_TYPE_UNDEF;
            break;
        }
    }

    /* Clean up name */
    i = 0;
    while (fs_dent->name[i] != '\0') {
        if (TSK_IS_CNTRL(fs_dent->name[i]))
            fs_dent->name[i] = '^';
        i++;
    }

    fs_dent->path = dinfo->dirs;
    fs_dent->pathdepth = dinfo->depth;

    if ((fs != NULL) && (fs_dent->inode)
        && (fs_dent->inode <= fs->last_inum)) {
        /* Get inode */
        if (fs_dent->fsi)
            tsk_fs_inode_free(fs_dent->fsi);

        if ((fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode)) == NULL) {
            strncat(tsk_errstr2, " - ext2fs_dent_copy",
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


/* 
**
** Read contents of directory block
**
** if entry is active call action with myflags set to TSK_FS_DENT_FLAG_ALLOC, if 
** it is deleted then call action with TSK_FS_DENT_FLAG_UNALLOC.
** len is the size of buf
**
** return 1 to stop, 0 on success, and -1 on error
*/
static int
ext2fs_dent_parse_block(EXT2FS_INFO * ext2fs, EXT2FS_DINFO * dinfo,
    TSK_LIST ** list_seen, char *buf, int len, int flags,
    TSK_FS_DENT_TYPE_WALK_CB action, void *ptr)
{
    TSK_FS_INFO *fs = &(ext2fs->fs_info);

    int dellen = 0;
    int idx;
    uint16_t reclen;
    uint32_t inode;
    char *dirPtr;
    TSK_FS_DENT *fs_dent;
    int minreclen = 4;

    if ((fs_dent = tsk_fs_dent_alloc(EXT2FS_MAXNAMLEN + 1, 0)) == NULL)
        return -1;

    /* update each time by the actual length instead of the
     ** recorded length so we can view the deleted entries 
     */
    for (idx = 0; idx <= len - EXT2FS_DIRSIZ_lcl(1); idx += minreclen) {

        unsigned int namelen;
        dirPtr = &buf[idx];

        if (ext2fs->deentry_type == EXT2_DE_V1) {
            ext2fs_dentry1 *dir = (ext2fs_dentry1 *) dirPtr;
            inode = tsk_getu32(fs->endian, dir->inode);
            namelen = tsk_getu16(fs->endian, dir->name_len);
            reclen = tsk_getu16(fs->endian, dir->rec_len);
        }
        else {
            ext2fs_dentry2 *dir = (ext2fs_dentry2 *) dirPtr;
            inode = tsk_getu32(fs->endian, dir->inode);
            namelen = dir->name_len;
            reclen = tsk_getu16(fs->endian, dir->rec_len);
        }

        minreclen = EXT2FS_DIRSIZ_lcl(namelen);

        /* 
         ** Check if we may have a valid directory entry.  If we don't,
         ** then increment to the next word and try again.  
         */
        if ((inode > fs->last_inum) ||  // inode is unsigned
            (namelen > EXT2FS_MAXNAMLEN) || (namelen == 0) ||   // namelen is unsigned
            (reclen < minreclen) || (reclen % 4) || (idx + reclen > len)) {

            minreclen = 4;
            if (dellen > 0)
                dellen -= 4;
            continue;
        }

        /* Before we process an entry in unallocated space, make
         * sure that it also ends in the unalloc space */
        if ((dellen) && (dellen < minreclen)) {
            minreclen = 4;
            dellen -= 4;
            continue;
        }

        if (ext2fs_dent_copy(ext2fs, dinfo, dirPtr, fs_dent)) {
            tsk_fs_dent_free(fs_dent);
            return -1;
        }


        /* Do we have a deleted entry? */
        if ((dellen > 0) || (inode == 0)) {
            fs_dent->flags = TSK_FS_DENT_FLAG_UNALLOC;
            if (dellen > 0)
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
        /* We have a non-deleted entry */
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

        /* If the actual length is shorter then the 
         ** recorded length, then the next entry(ies) have been 
         ** deleted.  Set dellen to the length of data that 
         ** has been deleted
         **
         ** Because we aren't guaranteed with Ext2FS that the next
         ** entry begins right after this one, we will check to
         ** see if the difference is less than a possible entry
         ** before we waste time searching it
         */
        if ((reclen - minreclen >= EXT2FS_DIRSIZ_lcl(1))
            && (dellen <= 0))
            dellen = reclen - minreclen;


        /* we will be recursing directories */
        if ((fs_dent->inode != 0)  && 
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
                if (ext2fs_dent_walk_lcl(&(ext2fs->fs_info), dinfo,
                        list_seen, fs_dent->inode, flags, action, ptr)) {
                    /* If this fails because the directory could not be 
                     * loaded, then we still continue */
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
    }

    tsk_fs_dent_free(fs_dent);
    return 0;
}                               /* end ext2fs_dent_parse_block() */


/**
 * \internal
 * Process the contents of a directory and pass each file name to a callback function.
 *
 * @param fs File system to analyze
 * @param inode Metadata address of directory to analyze
 * @param flags Flags used during analysis
 * @param action Callback function that is called for each file name
 * @param ptr Pointer to data that is passed to callback
 * @returns 1 on error and 0 on success
 */
uint8_t
ext2fs_dent_walk(TSK_FS_INFO * fs, TSK_INUM_T inode,
    TSK_FS_DENT_FLAG_ENUM flags, TSK_FS_DENT_TYPE_WALK_CB action,
    void *ptr)
{
    EXT2FS_DINFO dinfo;
    TSK_LIST *list_seen = NULL;
    uint8_t retval;

    // clean up any error messages that are lying around
    tsk_error_reset();

    memset(&dinfo, 0, sizeof(EXT2FS_DINFO));
    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((flags & TSK_FS_DENT_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_DENT_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_UNALLOC);
    }

    retval =
        ext2fs_dent_walk_lcl(fs, &dinfo, &list_seen, inode, flags, action,
        ptr);
    tsk_list_free(list_seen);
    list_seen = NULL;
    return retval;
}

/* returns 0 on success and 1 on error */
static uint8_t
ext2fs_dent_walk_lcl(TSK_FS_INFO * fs, EXT2FS_DINFO * dinfo,
    TSK_LIST ** list_seen, TSK_INUM_T inode, TSK_FS_DENT_FLAG_ENUM flags,
    TSK_FS_DENT_TYPE_WALK_CB action, void *ptr)
{
    TSK_FS_INODE *fs_inode;
    EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
    char *dirbuf, *dirptr;
    TSK_OFF_T size;
    TSK_FS_LOAD_FILE load_file;
    int retval = 0;

    if (inode < fs->first_inum || inode > fs->last_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ext2fs_dent_walk_lcl: inode value: %" PRIuINUM "\n", inode);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ext2fs_dent_walk_lcl: Processing directory %" PRIuINUM
            "\n", inode);

    if ((fs_inode = fs->inode_lookup(fs, inode)) == NULL) {
        strncat(tsk_errstr2, " - ext2fs_dent_walk_lcl",
            TSK_ERRSTR_L - strlen(tsk_errstr2));
        return 1;
    }

    size = roundup(fs_inode->size, fs->block_size);
    if ((dirbuf = tsk_malloc((size_t) size)) == NULL) {
        tsk_fs_inode_free(fs_inode);
        return 1;
    }

    /* make a copy of the directory contents that we can process */
    load_file.left = load_file.total = (size_t) size;
    load_file.base = load_file.cur = dirbuf;

    if (fs->file_walk(fs, fs_inode, 0, 0,
            TSK_FS_FILE_FLAG_SLACK | TSK_FS_FILE_FLAG_NOID,
            tsk_fs_load_file_action, (void *) &load_file)) {
        free(dirbuf);
        tsk_fs_inode_free(fs_inode);
        strncat(tsk_errstr2, " - extX_dent_walk_lcl",
            TSK_ERRSTR_L - strlen(tsk_errstr2));

        return 1;
    }

    /* Not all of the directory was copied, so we exit */
    if (load_file.left > 0) {
        free(dirbuf);
        tsk_fs_inode_free(fs_inode);
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_FWALK;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ext2fs_dent_walk: Error reading directory contents: %"
            PRIuINUM "\n", inode);
        return 1;
    }
    dirptr = dirbuf;

    while ((int64_t) size > 0) {
        int len = (fs->block_size < size) ? fs->block_size : (int) size;

        retval =
            ext2fs_dent_parse_block(ext2fs, dinfo, list_seen, dirptr, len,
            flags, action, ptr);

        /* if 1, then the action wants to stop, -1 is error */
        if ((retval == 1) || (retval == -1))
            break;

        size -= len;
        dirptr = (char *) ((uintptr_t) dirptr + len);
    }

    tsk_fs_inode_free(fs_inode);
    free(dirbuf);

    if (retval == -1)
        return 1;
    else
        return 0;
}
