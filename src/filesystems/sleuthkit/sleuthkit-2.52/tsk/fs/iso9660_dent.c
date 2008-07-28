/*
** The Sleuth Kit
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c)2007 Brian Carrier.  All righs reserved.
**
**
** This software is subject to the IBM Public License ver. 1.0,
** which was displayed prior to download and is included in the readme.txt
** file accompanying the Sleuth Kit files.  It may also be requested from:
** Crucial Security Inc.
** 14900 Conference Center Drive
** Chantilly, VA 20151
**
** Wyatt Banks [wbanks@crucialsecurity.com]
** Copyright (c) 2005 Crucial Security Inc.  All rights reserved.
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/* TCT
 * LICENSE
 *      This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *      Wietse Venema
 *      IBM T.J. Watson Research
 *      P.O. Box 704
 *      Yorktown Heights, NY 10598, USA
 --*/

/*
** You may distribute the Sleuth Kit, or other software that incorporates
** part of all of the Sleuth Kit, in object code form under a license agreement,
** provided that:
** a) you comply with the terms and conditions of the IBM Public License
**    ver 1.0; and
** b) the license agreement
**     i) effectively disclaims on behalf of all Contributors all warranties
**        and conditions, express and implied, including warranties or
**        conditions of title and non-infringement, and implied warranties
**        or conditions of merchantability and fitness for a particular
**        purpose.
**    ii) effectively excludes on behalf of all Contributors liability for
**        damages, including direct, indirect, special, incidental and
**        consequential damages such as lost profits.
**   iii) states that any provisions which differ from IBM Public License
**        ver. 1.0 are offered by that Contributor alone and not by any
**        other party; and
**    iv) states that the source code for the program is available from you,
**        and informs licensees how to obtain it in a reasonable manner on or
**        through a medium customarily used for software exchange.
**
** When the Sleuth Kit or other software that incorporates part or all of
** the Sleuth Kit is made available in source code form:
**     a) it must be made available under IBM Public License ver. 1.0; and
**     b) a copy of the IBM Public License ver. 1.0 must be included with
**        each copy of the program.
*/

/**
 * \file iso9660_dent.c
 * ISO9660 file system code to handle the parsing of file names and directory
 * structures.
 */

#include "tsk_fs_i.h"
#include "tsk_iso9660.h"

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

} ISO9660_DINFO;



uint8_t
iso9660_dent_walk_lcl(TSK_FS_INFO * fs, ISO9660_DINFO * dinfo,
    TSK_LIST ** list_seen, TSK_INUM_T inum,
    TSK_FS_DENT_FLAG_ENUM flags, TSK_FS_DENT_TYPE_WALK_CB action,
    void *ptr)
{
    ISO_INFO *iso = (ISO_INFO *) fs;
    TSK_FS_DENT *fs_dent;
    char *buf;                  /* temp storage for directory extent */
    int length = 0;             /* size of directory extent */
    iso9660_dentry *dd;         /* directory descriptor */
    iso9660_inode_node *in;
    TSK_OFF_T offs;                 /* where we are reading in the file */
    int retval;
    ssize_t cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (inum < fs->first_inum || inum > fs->last_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "iso9660_dent_walk: inode value: %" PRIuINUM "\n", inum);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "iso9660_dent_walk: Processing directory %"PRIuINUM"\n", inum);

    /* Load the directory to be processed */
    if (iso9660_dinode_load(iso, inum))
        return 1;

    if ((iso->dinode->dr.flags & ISO9660_FLAG_DIR) != ISO9660_FLAG_DIR) {
        return 0;
    }

    /* calculate directory extent location */
    offs =
        (TSK_OFF_T) (fs->block_size *
        tsk_getu32(fs->endian, iso->dinode->dr.ext_loc_m));

    /* read directory extent into memory */
    length = tsk_getu32(fs->endian, iso->dinode->dr.data_len_m);

    if ((fs_dent = tsk_fs_dent_alloc(ISO9660_MAXNAMLEN + 1, 0)) == NULL)
        return 1;

    if ((buf = talloc_size(fs_dent, length)) == NULL)
        return 1;

    cnt = tsk_fs_read_random(fs, buf, length, offs);
    if (cnt != length) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_READ;
            tsk_errstr[0] = '\0';
        }
        snprintf(tsk_errstr2, TSK_ERRSTR_L, "iso_dent_walk:");
        tsk_fs_dent_free(fs_dent);
        return 1;
    }

    dd = (iso9660_dentry *) buf;

    /* handle "." entry */
    fs_dent->inode = inum;
    strcpy(fs_dent->name, ".");
    fs_dent->path = dinfo->dirs;
    fs_dent->pathdepth = dinfo->depth;
    fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);
    fs_dent->ent_type = TSK_FS_DENT_TYPE_DIR;
    fs_dent->flags = TSK_FS_DENT_FLAG_ALLOC;

    if (flags & TSK_FS_DENT_FLAG_ALLOC) {
        retval = action(fs, fs_dent, ptr);
        if (retval == TSK_WALK_ERROR) {
            tsk_fs_dent_free(fs_dent);
            return 1;
        }
        else if (retval == TSK_WALK_STOP) {
            tsk_fs_dent_free(fs_dent);
            return 0;
        }
    }

    length -= dd->entry_len;
    dd = (iso9660_dentry *) ((char *) dd + dd->entry_len);

    /* handle ".." entry */
    in = iso->in_list;
    while (in
        && (tsk_getu32(fs->endian, in->inode.dr.ext_loc_m) !=
            tsk_getu32(fs->endian, dd->ext_loc_m)))
        in = in->next;
    if (in) {
        fs_dent->inode = in->inum;
        strcpy(fs_dent->name, "..");

        fs_dent->path = dinfo->dirs;
        fs_dent->pathdepth = dinfo->depth;
        fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);
        fs_dent->ent_type = TSK_FS_DENT_TYPE_DIR;
        fs_dent->flags = TSK_FS_DENT_FLAG_ALLOC;

        if (flags & TSK_FS_DENT_FLAG_ALLOC) {
            retval = action(fs, fs_dent, ptr);
            if (retval == TSK_WALK_ERROR) {
                tsk_fs_dent_free(fs_dent);
                return 1;
            }
            else if (retval == TSK_WALK_STOP) {
                tsk_fs_dent_free(fs_dent);
                return 0;
            }
        }
    }
    length -= dd->entry_len;
    dd = (iso9660_dentry *) ((char *) dd + dd->entry_len);

    // process the rest of the entries in the directory
    while (length > sizeof(iso9660_dentry)) {
        if (dd->entry_len) {
            int retval;
            int i;

            // find the entry in our list of files
            in = iso->in_list;
            while ((in)
                && (tsk_getu32(fs->endian,
                        in->inode.dr.ext_loc_m) != tsk_getu32(fs->endian,
                        dd->ext_loc_m))) {
                in = in->next;
            }

            if ((!in)
                || (tsk_getu32(fs->endian,
                        in->inode.dr.ext_loc_m) != tsk_getu32(fs->endian,
                        dd->ext_loc_m))) {
                // @@@ 
                tsk_fs_dent_free(fs_dent);
                return 0;
            }


            fs_dent->inode = in->inum;
            strncpy(fs_dent->name, in->inode.fn, ISO9660_MAXNAMLEN);

            /* Clean up name */
            i = 0;
            while (fs_dent->name[i] != '\0') {
                if (TSK_IS_CNTRL(fs_dent->name[i]))
                    fs_dent->name[i] = '^';
                i++;
            }


            fs_dent->path = dinfo->dirs;
            fs_dent->pathdepth = dinfo->depth;
            fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);

            if (dd->flags & ISO9660_FLAG_DIR)
                fs_dent->ent_type = TSK_FS_DENT_TYPE_DIR;
            else
                fs_dent->ent_type = TSK_FS_DENT_TYPE_REG;
            fs_dent->flags = TSK_FS_DENT_FLAG_ALLOC;

            if (flags & TSK_FS_DENT_FLAG_ALLOC) {
                retval = action(fs, fs_dent, ptr);
                if (retval == TSK_WALK_ERROR) {
                    tsk_fs_dent_free(fs_dent);
                    return 1;
                }
                else if (retval == TSK_WALK_STOP) {
                    tsk_fs_dent_free(fs_dent);
                    return 0;
                }
            }

            if ((dd->flags & ISO9660_FLAG_DIR)
                && (flags & TSK_FS_DENT_FLAG_RECURSE)) {
                int depth_added = 0;

                /* Make sure we do not get into an infinite loop */
                if (0 == tsk_list_find(*list_seen, fs_dent->inode)) {
                    if (tsk_list_add(fs, list_seen, fs_dent->inode)) {
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
                    if (iso9660_dent_walk_lcl(fs, dinfo, list_seen,
                            in->inum, flags, action, ptr)) {
                        /* If the directory could not be loaded,
                         * then move on */
                        if (tsk_verbose) {
                            tsk_fprintf(stderr,
                                "iso_dent_parse_block: error reading directory: %"
                                PRIuINUM "\n", in->inum);
                            tsk_error_print(stderr);
                        }
                        tsk_error_reset();
                    }

                    dinfo->depth--;
                    if (depth_added)
                        *dinfo->didx[dinfo->depth] = '\0';
                }
            }

            length -= dd->entry_len;

            dd = (iso9660_dentry *) ((char *) dd + dd->entry_len);
            /* we need to look for files past the next NULL we discover, in case
             * directory has a hole in it (this is common) */
        }
        else {
            char *a, *b;
            length -= sizeof(iso9660_dentry);

            /* find next non-zero byte and we'll start over there */

            a = (char *) dd;
            b = a + sizeof(iso9660_dentry);

            while ((*a == 0) && (a != b))
                a++;

            if (a != b) {
                length += (int) (b - a);
                dd = (iso9660_dentry *) ((char *) dd +
                    (sizeof(iso9660_dentry) - (int) (b - a)));
            }
        }
    }

    tsk_fs_dent_free(fs_dent);
    return 0;
}

/**
 * Process the contents of a directory and pass each file name to a callback function.
 *
 * @param fs File system to analyze
 * @param inum Metadata address of directory to analyze
 * @param flags Flags used during analysis
 * @param action Callback function that is called for each file name
 * @param ptr Pointer to data that is passed to callback
 * @returns 1 on error and 0 on success
 */
uint8_t
iso9660_dent_walk(TSK_FS_INFO * fs, TSK_INUM_T inum,
    TSK_FS_DENT_FLAG_ENUM flags, TSK_FS_DENT_TYPE_WALK_CB action,
    void *ptr)
{
    ISO9660_DINFO dinfo;
    TSK_LIST *list_seen = NULL;
    uint8_t retval;

    // clean up any error messages that are lying around
    tsk_error_reset();

    memset(&dinfo, 0, sizeof(ISO9660_DINFO));
    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((flags & TSK_FS_DENT_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_DENT_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_UNALLOC);
    }

    retval =
        iso9660_dent_walk_lcl(fs, &dinfo, &list_seen, inum, flags, action,
        ptr);

    tsk_list_free(list_seen);
    list_seen = NULL;
    return retval;
}
