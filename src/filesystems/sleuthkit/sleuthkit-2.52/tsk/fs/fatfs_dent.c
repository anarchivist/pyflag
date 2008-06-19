/*
** fatfs_dent
** The Sleuth Kit 
**
** $Date: 2007/12/20 16:17:56 $
**
** Human interface Layer support for the FAT file system
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
** Unicode added with support from I.D.E.A.L. Technology Corp (Aug '05)
**
*/

/**
 * \file fatfs_dent.c
 * FAT file name walking code.
 */

#include "tsk_fs_i.h"
#include "tsk_fatfs.h"

/*
 * DESIGN NOTES
 *
 * the basic goal of this code is to parse directory entry structures for
 * file names.  The main function is fatfs_dent_walk, which takes an
 * inode value, reads in the contents of the directory into a buffer, 
 * and the processes the buffer.  
 *
 * The buffer is processed in directory entry size chunks and if the
 * entry meets tne flag requirements, an action function is called.
 *
 * One of the odd aspects of this code is that the 'inode' values are
 * the 'slot-address'.  Refer to the document on how FAT was implemented
 * for more details. This means that we need to search for the actual
 * 'inode' address for the '.' and '..' entries though!  The search
 * for '..' is quite painful if this code is called from a random 
 * location.  It does save what the parent is though, so the search
 * only has to be done once per session.
 */



/* Special data structure allocated for each directory to hold the long
 * file name entries until all entries have been found */
typedef struct {
    uint8_t name[FATFS_MAXNAMLEN_UTF8]; /* buffer for lfn - in reverse order */
    uint16_t start;             /* current start of name */
    uint8_t chk;                /* current checksum */
    uint8_t seq;                /* seq of first entry in lfn */
} FATFS_LFN;

#define MAX_DEPTH   	128
#define DIR_STRSZ  	4096

typedef struct {
    /* Recursive path stuff */

    /* how deep in the directory tree are we */
    unsigned int depth;

    /* pointer in dirs string to where '/' is for given depth */
    char *didx[MAX_DEPTH];

    /* The current directory name string */
    char dirs[DIR_STRSZ];

    /* as FAT does not use inode numbers, we are making them up.  This causes
     * minor problems with the . and .. entries.  These variables help
     * us out with that
     */
    TSK_INUM_T curdir_inode;        /* the . inode */
    TSK_INUM_T pardir_inode;        /* the .. inode */


    /* We need to search for an inode addr based on starting cluster, 
     * these do it */
    TSK_DADDR_T find_clust;
    TSK_DADDR_T find_inode;

    /* Set to 1 when we are recursing down a deleted directory.  This will
     * supress the errors that may occur from invalid data
     */
    uint8_t recdel;

    /* Set to 1 when we are collecting inode allocation information. 
     * The info is used by inode_walk when looking for ORPHAN files.
     */
    uint8_t save_inum_named;

} FATFS_DINFO;


static uint8_t fatfs_dent_walk_lcl(TSK_FS_INFO *, FATFS_DINFO *,
    TSK_LIST **, TSK_INUM_T, int, TSK_FS_DENT_TYPE_WALK_CB, void *);


/**************************************************************************
 *
 * find_parent
 *
 *************************************************************************/

/**
 * dent walk callback used when finding the parent directory.  It
 * compares the starting cluster of the directory with the target
 * starting cluster. 
 */
static TSK_WALK_RET_ENUM
find_parent_act(TSK_FS_INFO * fs, TSK_FS_DENT * fsd, void *ptr)
{
    FATFS_DINFO *dinfo = (FATFS_DINFO *) ptr;

    /* we found the directory entry that has allocated the cluster 
     * we are looking for */
    if (fsd->fsi->direct_addr[0] == dinfo->find_clust) {
        dinfo->find_inode = fsd->inode;
        return TSK_WALK_STOP;
    }
    return TSK_WALK_CONT;
}

/**
 * Find the inode address of the parent directory of a 
 * given directory.  This starts to walk the directory tree
 * starting at the root.
 *
 * @param fatfs File system information structure.
 * @param fs_dent File name of directory to find parent of.
 * @return The inode address of the parent directory or 0
 * on error.
 */
static TSK_INUM_T
find_parent(FATFS_INFO * fatfs, TSK_FS_DENT * fs_dent)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;
    FATFS_DINFO dinfo;
    TSK_LIST *list_seen = NULL;

    memset(&dinfo, 0, sizeof(FATFS_DINFO));

    /* set the value that the action function will use */
    dinfo.find_clust = fs_dent->fsi->direct_addr[0];

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_find_parent: Looking for directory in cluster %"
            PRIuDADDR "\n", dinfo.find_clust);

    /* Are we searching for the root directory? */
    if (fs->ftype == TSK_FS_INFO_TYPE_FAT_32) {
        TSK_OFF_T clust = FATFS_SECT_2_CLUST(fatfs, fatfs->rootsect);

        if ((clust == dinfo.find_clust) || (dinfo.find_clust == 0)) {
            return fs->root_inum;
        }
    }
    else {
        if ((dinfo.find_clust == 1) || (dinfo.find_clust == 0)) {
            return fs->root_inum;
        }
    }

    if ((fs_dent->fsi->mode & TSK_FS_INODE_MODE_FMT) !=
        TSK_FS_INODE_MODE_DIR) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_find_parent called on a non-directory");
        return 0;
    }


    /* walk the inodes - looking for an inode that has allocated the
     * same first sector 
     */

    if (fatfs_dent_walk_lcl(fs, &dinfo, &list_seen, fs->root_inum,
            TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_RECURSE,
            find_parent_act, (void *) &dinfo)) {
        tsk_list_free(list_seen);
        list_seen = NULL;
        return 0;
    }
    tsk_list_free(list_seen);
    list_seen = NULL;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_find_parent: Directory %" PRIuINUM
            " found for cluster %" PRIuDADDR "\n", dinfo.find_inode,
            dinfo.find_clust);

    /* if we didn't find anything then 0 will be returned */
    return dinfo.find_inode;
}


/* 
 * Process the contents of a directory and call the callback for
 * each valid directory entry. 
 * 
 * @param fatfs File system information structure
 * @param dinfo FAT directory entry state information sructure to keep 
 * state between calls.
 * @list_seen List of directory inodes that have been seen thus far in
 * directory walking (can be a pointer to a NULL pointer on first call). 
 * @param buf Buffer that contains the directory contents. 
 * @param len Length of buffer in bytes (must be a multiple of sector size)
 * @param addrs Array where each element is the original address of the 
 * corresponding block in buf (size of array is number of blocks in directory).
 * @param flags Flags to use while processing (TSK_FS_DENT_FLAG_ALLOC, 
 * TSK_FS_DENT_FLAG_UNALLOC, TSK_FS_DENT_FLAG_RECURSE)
 * @param action Callback for each directory entry. 
 * @param ptr Pointer to pass to callback.
 *
 * @return -1 on error, 0 on success, and 1 to stop
 */
static int8_t
fatfs_dent_parse_buf(FATFS_INFO * fatfs, FATFS_DINFO * dinfo,
    TSK_LIST ** list_seen, char *buf, TSK_OFF_T len,
    TSK_DADDR_T * addrs, TSK_FS_DENT_FLAG_ENUM flags,
    TSK_FS_DENT_TYPE_WALK_CB action, void *ptr)
{
    unsigned int idx, sidx;
    int a, b;
    TSK_INUM_T inode, ibase;
    fatfs_dentry *dep;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;
    int sectalloc;
    TSK_FS_DENT *fs_dent;
    FATFS_LFN lfninfo;

    if (buf == NULL) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_dent_parse_buf: buffer is NULL");
        return -1;
    }

    dep = (fatfs_dentry *) buf;

    if ((fs_dent = tsk_fs_dent_alloc(FATFS_MAXNAMLEN_UTF8, 32)) == NULL) {
        return -1;
    }
    else if ((fs_dent->fsi =
            tsk_fs_inode_alloc(FATFS_NDADDR, FATFS_NIADDR)) == NULL) {
        tsk_fs_dent_free(fs_dent);
        return -1;
    }

    memset(&lfninfo, 0, sizeof(FATFS_LFN));
    lfninfo.start = FATFS_MAXNAMLEN_UTF8 - 1;

    for (sidx = 0; sidx < (unsigned int) (len / fatfs->ssize); sidx++) {

        /* Get the base inode for this sector */
        ibase = FATFS_SECT_2_INODE(fatfs, addrs[sidx]);

        if (ibase > fs->last_inum) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_ARG;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "fatfs_parse: inode address is too large");
            tsk_fs_dent_free(fs_dent);
            return -1;
        }

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_dent_parse_buf: Parsing sector %" PRIuDADDR
                "\n", addrs[sidx]);

        if ((sectalloc = is_sectalloc(fatfs, addrs[sidx])) == -1) {
            tsk_fs_dent_free(fs_dent);
            return -1;
        }

        /* cycle through the directory entries */
        for (idx = 0; idx < fatfs->dentry_cnt_se; idx++, dep++) {
            fatfs_dentry *dir;
            int i;

            /* is it a valid dentry? */
            if (0 == fatfs_isdentry(fatfs, dep))
                continue;

            /* Copy the directory entry into the TSK_FS_DENT structure */
            dir = (fatfs_dentry *) dep;

            inode = ibase + idx;

            /* Take care of the name 
             * Copy a long name to a buffer and take action if it
             * is a small name */
            if ((dir->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
                fatfs_dentry_lfn *dirl = (fatfs_dentry_lfn *) dir;

                /* Store the name in dinfo until we get the 8.3 name 
                 * Use the checksum to identify a new sequence 
                 * */
                if (((dirl->seq & FATFS_LFN_SEQ_FIRST)
                        && (dirl->seq != FATFS_SLOT_DELETED))
                    || (dirl->chksum != lfninfo.chk)) {
                    // @@@ Do a partial output here


                    /* Reset the values */
                    lfninfo.seq = dirl->seq & FATFS_LFN_SEQ_MASK;
                    lfninfo.chk = dirl->chksum;
                    lfninfo.start = FATFS_MAXNAMLEN_UTF8 - 1;

                }
                else if (dirl->seq != lfninfo.seq - 1) {
                    // @@@ Check the sequence number - the checksum is correct though...

                }

                /* Copy the UTF16 values starting at end of buffer */
                for (a = 3; a >= 0; a--) {
                    if ((lfninfo.start > 0))
                        lfninfo.name[lfninfo.start--] = dirl->part3[a];
                }
                for (a = 11; a >= 0; a--) {
                    if ((lfninfo.start > 0))
                        lfninfo.name[lfninfo.start--] = dirl->part2[a];
                }
                for (a = 9; a >= 0; a--) {
                    if ((lfninfo.start > 0))
                        lfninfo.name[lfninfo.start--] = dirl->part1[a];
                }

                // Skip ahead until we get a new sequence num or the 8.3 name
                continue;
            }
            /* Special case for volume label: name does not have an
             * extension and we add a note at the end that it is a label */
            else if ((dir->attrib & FATFS_ATTR_VOLUME) ==
                FATFS_ATTR_VOLUME) {
                a = 0;

                for (b = 0; b < 8; b++) {
                    if ((dir->name[b] >= 0x20) && (dir->name[b] != 0xff)) {
                        fs_dent->name[a++] = dir->name[b];
                    }
                    else {
                        fs_dent->name[a++] = '^';
                    }
                }
                for (b = 0; b < 3; b++) {
                    if ((dir->ext[b] >= 0x20) && (dir->ext[b] != 0xff)) {
                        fs_dent->name[a++] = dir->ext[b];
                    }
                    else {
                        fs_dent->name[a++] = '^';
                    }
                }

                fs_dent->name[a] = '\0';
                /* Append a string to show it is a label */
                if (a + 22 < FATFS_MAXNAMLEN_UTF8) {
                    char *volstr = " (Volume Label Entry)";
                    strncat(fs_dent->name, volstr,
                        FATFS_MAXNAMLEN_UTF8 - a);
                }
            }

            /* A short (8.3) entry */
            else {
                char *name_ptr; // The dest location for the short name

                /* if we have a lfn, copy it into fs_dent->name
                 * and put the short name in fs_dent->shrt_name */
                if (lfninfo.start != FATFS_MAXNAMLEN_UTF8 - 1) {
                    int retVal;

                    /* @@@ Check the checksum */

                    /* Convert the UTF16 to UTF8 */
                    UTF16 *name16 =
                        (UTF16 *) ((uintptr_t) & lfninfo.
                        name[lfninfo.start + 1]);
                    UTF8 *name8 = (UTF8 *) fs_dent->name;

                    retVal =
                        tsk_UTF16toUTF8(fs->endian,
                        (const UTF16 **) &name16,
                        (UTF16 *) & lfninfo.name[FATFS_MAXNAMLEN_UTF8],
                        &name8,
                        (UTF8 *) ((uintptr_t) name8 +
                            FATFS_MAXNAMLEN_UTF8), TSKlenientConversion);

                    if (retVal != TSKconversionOK) {
                        tsk_error_reset();
                        tsk_errno = TSK_ERR_FS_UNICODE;
                        snprintf(tsk_errstr, TSK_ERRSTR_L,
                            "fatfs_parse: Error converting FAT LFN to UTF8: %d",
                            retVal);
                        continue;
                    }

                    /* Make sure it is NULL Terminated */
                    if ((uintptr_t) name8 >
                        (uintptr_t) fs_dent->name + FATFS_MAXNAMLEN_UTF8)
                        fs_dent->name[FATFS_MAXNAMLEN_UTF8 - 1] = '\0';
                    else
                        *name8 = '\0';

                    /* Clean up name */
                    i = 0;
                    while (fs_dent->name[i] != '\0') {
                        if (TSK_IS_CNTRL(fs_dent->name[i]))
                            fs_dent->name[i] = '^';
                        i++;
                    }

                    lfninfo.start = FATFS_MAXNAMLEN_UTF8 - 1;
                    name_ptr = fs_dent->shrt_name;      // put 8.3 into shrt_name
                }
                /* We don't have a LFN, so put the short name in 
                 * fs_dent->name */
                else {
                    fs_dent->shrt_name[0] = '\0';
                    name_ptr = fs_dent->name;   // put 8.3 into normal location
                }


                /* copy in the short name into the place specified above. 
                 * Skip spaces and put in the . */
                a = 0;
                for (b = 0; b < 8; b++) {
                    if ((dir->name[b] != 0) && (dir->name[b] != 0xff) &&
                        (dir->name[b] != 0x20)) {

                        if ((b == 0)
                            && (dir->name[0] == FATFS_SLOT_DELETED)) {
                            name_ptr[a++] = '_';
                        }
                        else if ((dir->lowercase & FATFS_CASE_LOWER_BASE)
                            && (dir->name[b] >= 'A')
                            && (dir->name[b] <= 'Z')) {
                            name_ptr[a++] = dir->name[b] + 32;
                        }
                        else {
                            name_ptr[a++] = dir->name[b];
                        }
                    }
                }

                for (b = 0; b < 3; b++) {
                    if ((dir->ext[b] != 0) && (dir->ext[b] != 0xff) &&
                        (dir->ext[b] != 0x20)) {
                        if (b == 0)
                            name_ptr[a++] = '.';
                        if ((dir->lowercase & FATFS_CASE_LOWER_EXT) &&
                            (dir->ext[b] >= 'A') && (dir->ext[b] <= 'Z'))
                            name_ptr[a++] = dir->ext[b] + 32;
                        else
                            name_ptr[a++] = dir->ext[b];
                    }
                }
                name_ptr[a] = '\0';
            }

            /* Clean up name to remove control chars */
            i = 0;
            while (fs_dent->name[i] != '\0') {
                if (TSK_IS_CNTRL(fs_dent->name[i]))
                    fs_dent->name[i] = '^';
                i++;
            }

            /* add the path data */
            fs_dent->path = dinfo->dirs;
            fs_dent->pathdepth = dinfo->depth;


            /* file type: FAT only knows DIR and FILE */
            if ((dir->attrib & FATFS_ATTR_DIRECTORY) ==
                FATFS_ATTR_DIRECTORY)
                fs_dent->ent_type = TSK_FS_DENT_TYPE_DIR;
            else
                fs_dent->ent_type = TSK_FS_DENT_TYPE_REG;

            /* Get inode */
            fs_dent->inode = inode;
            if (fatfs_dinode_copy(fatfs, fs_dent->fsi, dir, addrs[sidx],
                    inode) != TSK_OK) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "fatfs_dent_parse: could not copy inode -- ignoring\n");
            }


            /* Handle the . and .. entries specially
             * The current inode 'address' they have is for the current
             * slot in the cluster, but it needs to refer to the original
             * slot 
             */
            if ((dep->name[0] == '.') &&
                (dep->name[2] == ' ') && (dep->name[3] == ' ') &&
                (dep->name[4] == ' ') && (dep->name[5] == ' ') &&
                (dep->name[6] == ' ') && (dep->name[7] == ' ') &&
                (dep->name[8] == ' ') && (dep->name[9] == ' ') &&
                (dep->name[10] == ' ') && (dep->name[11] == '\0')) {

                /* dinfo->curdir_inode is always set and we can copy it in */
                if (dep->name[1] == ' ')
                    inode = fs_dent->inode = dinfo->curdir_inode;

                /* dinfo->pardir_inode is not always set, so we may have to search */
                else if (dep->name[1] == '.') {

                    if ((!dinfo->pardir_inode) && (!dinfo->find_clust))
                        dinfo->pardir_inode = find_parent(fatfs, fs_dent);

                    inode = fs_dent->inode = dinfo->pardir_inode;

                    /* If the .. entry is for the root directory, then make
                     * up the data
                     */
                    if (inode == fs->root_inum) {
                        if (fatfs_make_root(fatfs, fs_dent->fsi)) {
                            if (tsk_verbose)
                                tsk_fprintf(stderr,
                                    "fatfs_dent_parse: could not make root directory -- ignoring\n");
                        }
                    }
                }
            }


            /* The allocation status of an entry is based on the allocation
             * status of the sector it is in and the flag.  Deleted directories
             * do not always clear the flags of each entry
             */
            if (sectalloc == 1) {
                fs_dent->flags = (dep->name[0] == FATFS_SLOT_DELETED) ?
                    TSK_FS_DENT_FLAG_UNALLOC : TSK_FS_DENT_FLAG_ALLOC;
            }
            else {
                fs_dent->flags = TSK_FS_DENT_FLAG_UNALLOC;
            }

            if ((flags & fs_dent->flags) == fs_dent->flags) {
                int retval = action(fs, fs_dent, ptr);

                if (retval == TSK_WALK_STOP) {
                    tsk_fs_dent_free(fs_dent);

                    /* free the list -- the main API has no way
                     * of knowing that we stopped early w/out error.
                     */
                    if (dinfo->save_inum_named) {
                        tsk_list_free(fs->list_inum_named);
                        fs->list_inum_named = NULL;
                        dinfo->save_inum_named = 0;
                    }
                    return 1;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_fs_dent_free(fs_dent);
                    return -1;
                }

                // save the inode info -- if the setup is right
                if ((dinfo->save_inum_named) && (fs_dent->fsi)
                    && (fs_dent->fsi->flags & TSK_FS_INODE_FLAG_UNALLOC)) {
                    if (tsk_list_add(&fs->list_inum_named,
                            fs_dent->fsi->addr)) {

                        // if there is an error, then clear the list
                        tsk_list_free(fs->list_inum_named);
                        fs->list_inum_named = NULL;
                        dinfo->save_inum_named = 0;
                    }
                }
            }

            /* if we have a directory and need to recurse then do it */
            if (((fs_dent->fsi->mode & TSK_FS_INODE_MODE_FMT) ==
                    TSK_FS_INODE_MODE_DIR)
                && (flags & TSK_FS_DENT_FLAG_RECURSE)
                && (!TSK_FS_ISDOT(fs_dent->name))) {

                TSK_INUM_T back_p = 0;
                uint8_t back_recdel = 0;
                int depth_added = 0;

                /* Make sure we do not get into an infinite loop */
                if (0 == tsk_list_find(*list_seen, fs_dent->inode)) {
                    if (tsk_list_add(list_seen, fs_dent->inode)) {
                        tsk_fs_dent_free(fs_dent);
                        return -1;
                    }

                    /* append our name */
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

                    /* save the .. inode value */
                    back_p = dinfo->pardir_inode;
                    dinfo->pardir_inode = dinfo->curdir_inode;
                    dinfo->depth++;


                    /* This will prevent errors from being generated from the invalid
                     * deleted files.  save the current setting and set it to del */
                    if (fs_dent->flags & TSK_FS_DENT_FLAG_ALLOC) {
                        back_recdel = dinfo->recdel;
                        dinfo->recdel = 1;
                    }

                    if (fatfs_dent_walk_lcl(&(fatfs->fs_info), dinfo,
                            list_seen, fs_dent->inode, flags, action,
                            ptr)) {
                        /* If the directory could not be loaded,
                         *                  * then move on */
                        if (tsk_verbose) {
                            tsk_fprintf(stderr,
                                "fatfs_dent_parse: error reading directory: %"
                                PRIuINUM "\n", fs_dent->inode);
                            tsk_error_print(stderr);
                        }
                        tsk_error_reset();
                    }

                    dinfo->depth--;
                    dinfo->curdir_inode = dinfo->pardir_inode;
                    dinfo->pardir_inode = back_p;

                    if (depth_added)
                        *dinfo->didx[dinfo->depth] = '\0';

                    /* Restore the recursion setting */
                    if (fs_dent->flags & TSK_FS_DENT_FLAG_ALLOC) {
                        dinfo->recdel = back_recdel;
                    }
                }
            }
        }
    }
    tsk_fs_dent_free(fs_dent);

    return 0;
}



/**************************************************************************
 *
 * dent_walk
 *
 *************************************************************************/

/* values used to copy the directory contents into a buffer */


typedef struct {
    /* ptr to the current location in a local buffer */
    char *curdirptr;

    /* number of bytes left in curdirptr */
    size_t dirleft;

    /* ptr to a local buffer for the stack of sector addresses */
    TSK_DADDR_T *addrbuf;

    /* num of entries allocated to addrbuf */
    size_t addrsize;

    /* The current index in the addrbuf stack */
    size_t addridx;

} FATFS_LOAD_DIR;



/**
 * file walk callback that is used to load directory contents
 * into a buffer
 */
static TSK_WALK_RET_ENUM
fatfs_dent_action(TSK_FS_INFO * fs, TSK_DADDR_T addr, char *buf,
    size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    FATFS_LOAD_DIR *load = (FATFS_LOAD_DIR *) ptr;

    /* how much of the buffer are we copying */
    size_t len = (load->dirleft < size) ? load->dirleft : size;

    /* Copy the sector into a buffer and increment the pointers */
    memcpy(load->curdirptr, buf, len);
    load->curdirptr = (char *) ((uintptr_t) load->curdirptr + len);
    load->dirleft -= len;

    /* fill in the stack of addresses of sectors 
     *
     * if we are at the last entry, then realloc more */
    if (load->addridx == load->addrsize) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_dent_walk: Trying to put more sector address in stack than were allocated (%lu)",
            (long) load->addridx);
        return TSK_WALK_ERROR;
    }

    /* Add this sector to the stack */
    load->addrbuf[load->addridx++] = addr;

    if (load->dirleft)
        return TSK_WALK_CONT;
    else
        return TSK_WALK_STOP;
}



/**
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
fatfs_dent_walk(TSK_FS_INFO * fs, TSK_INUM_T inode,
    TSK_FS_DENT_FLAG_ENUM flags,
    TSK_FS_DENT_TYPE_WALK_CB action, void *ptr)
{
    FATFS_DINFO dinfo;
    TSK_LIST *list_seen = NULL;
    uint8_t retval;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((flags & TSK_FS_DENT_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_DENT_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_UNALLOC);
    }

    memset(&dinfo, 0, sizeof(FATFS_DINFO));

    /* if the flags are right, we can collect info that may be needed
     * for an orphan walk.  If the walk fails or stops, the code that
     * calls the action will clear this stuff. 
     */
    if ((fs->list_inum_named == NULL) && (inode == fs->root_inum) &&
        (flags & (TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_UNALLOC |
                TSK_FS_DENT_FLAG_RECURSE))) {
        dinfo.save_inum_named = 1;
    }

    retval =
        fatfs_dent_walk_lcl(fs, &dinfo, &list_seen, inode, flags, action,
        ptr);

    /* If there was an error, then we stopped early and we should get
     * rid of the partial list we were making.
     */
    if ((retval == 1) && (dinfo.save_inum_named == 1)) {
        tsk_list_free(fs->list_inum_named);
        fs->list_inum_named = NULL;
    }

    tsk_list_free(list_seen);
    list_seen = NULL;
    return retval;
}


/** 
 * The internal and recursive function to do directory entry walking
 *
 * @param fs File system state structure
 * @param dinfo FAT directory entry state information sructure to keep 
 * state between calls.
 * @list_seen List of directory inodes that have been seen thus far in
 * directory walking (can be a pointer to a NULL pointer on first call). 
 * @param inode Directory inode to start walking on
 * @param flags flags to use while walking (TSK_FS_DENT_FLAG_ALLOC, TSK_FS_DENT_FLAG_UNALLOC, and TSK_FS_DENT_FLAG_RECURSE)
 # @param action Callback to call for each directory entry.
 * @param ptr Pointer to data that should be passed to callback. 
 *
 * @return 1 on error and 0 on success.
 */
static uint8_t
fatfs_dent_walk_lcl(TSK_FS_INFO * fs, FATFS_DINFO * dinfo,
    TSK_LIST ** list_seen, TSK_INUM_T inode, int flags,
    TSK_FS_DENT_TYPE_WALK_CB action, void *ptr)
{
    TSK_OFF_T size, len;
    TSK_FS_INODE *fs_inode;
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    char *dirbuf;
    TSK_DADDR_T *addrbuf;
    FATFS_LOAD_DIR load;
    int retval;

    if ((inode < fs->first_inum) || (inode > fs->last_inum)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_dent_walk: invalid inode value: %" PRIuINUM "\n",
            inode);
        return 1;
    }

    fs_inode = fs->inode_lookup(fs, inode);
    if (!fs_inode) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_INODE_NUM;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_dent_walk: %" PRIuINUM " is not a valid inode", inode);
        return 1;
    }

    size = fs_inode->size;
    len = roundup(size, fatfs->ssize);

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_dent_walk: Processing directory %" PRIuINUM "\n",
            inode);

    /* Save the current inode value ('.') */
    dinfo->curdir_inode = inode;

    /* Make a copy of the directory contents using file_walk */
    if ((dirbuf = tsk_malloc((size_t) len)) == NULL) {
        tsk_fs_inode_free(fs_inode);
        return 1;
    }
    memset(dirbuf, 0, (size_t) len);
    load.curdirptr = dirbuf;
    load.dirleft = (size_t) size;

    /* We are going to save the address of each sector in the directory
     * in a stack - they are needed to determine the inode address.  
     */
    load.addrsize = (size_t) (len / fatfs->ssize);
    addrbuf = (TSK_DADDR_T *) tsk_malloc(load.addrsize * sizeof(TSK_DADDR_T));
    if (addrbuf == NULL) {
        tsk_fs_inode_free(fs_inode);
        free(dirbuf);
        return 1;
    }

    /* Set the variables that are used during the copy */
    load.addridx = 0;
    load.addrbuf = addrbuf;

    /* save the directory contents into dirbuf */
    if (fs->file_walk(fs, fs_inode, 0, 0,
            TSK_FS_FILE_FLAG_SLACK | TSK_FS_FILE_FLAG_RECOVER |
            TSK_FS_FILE_FLAG_NOID, fatfs_dent_action, (void *) &load)) {
        tsk_fs_inode_free(fs_inode);
        free(dirbuf);
        strncat(tsk_errstr2, " - fatfs_dent_walk",
            TSK_ERRSTR_L - strlen(tsk_errstr2));
        return 1;
    }

    /* We did not copy the entire directory, which occurs if an error occured */
    if (load.dirleft > 0) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_FWALK;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_dent_walk: Error reading directory %" PRIuINUM, inode);

        /* Free the local buffers */
        tsk_fs_inode_free(fs_inode);
        free(dirbuf);
        free(addrbuf);

        return 1;
    }

    retval =
        fatfs_dent_parse_buf(fatfs, dinfo, list_seen, dirbuf, len, addrbuf,
        flags, action, ptr);


    tsk_fs_inode_free(fs_inode);
    free(dirbuf);
    free(addrbuf);

    return (retval == -1) ? 1 : 0;
}
