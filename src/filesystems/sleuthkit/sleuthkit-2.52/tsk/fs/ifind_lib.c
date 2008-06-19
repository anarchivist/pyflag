/*
** ifind (inode find)
** The Sleuth Kit
**
** $Date: 2007/12/20 20:32:38 $
**
** Given an image  and block number, identify which inode it is used by
** 
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
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
 * \file ifind_lib.c
 * Contains the library API functions used by the ifind command
 * line tool.
 */

#include "tsk_fs_i.h"


static uint8_t s_localflags;
static uint8_t s_found;


/*******************************************************************************
 * Find an unallocated NTFS MFT entry based on its parent directory
 */

static TSK_FS_DENT *s_fs_dent = NULL;
static TSK_INUM_T s_parinode = 0;

/* dent call back for finding unallocated files based on parent directory
 */
static TSK_WALK_RET_ENUM
ifind_par_act(TSK_FS_INFO * fs, TSK_FS_INODE * fs_inode, void *ptr)
{
    TSK_FS_INODE_NAME_LIST *fs_name;

    /* go through each file name structure */
    fs_name = fs_inode->name;
    while (fs_name) {
        if (fs_name->par_inode == s_parinode) {
            /* Fill in the basics of the fs_dent entry */
            s_fs_dent->fsi = fs_inode;
            s_fs_dent->inode = fs_inode->addr;
            s_fs_dent->flags = TSK_FS_DENT_FLAG_UNALLOC;
            strncpy(s_fs_dent->name, fs_name->name, s_fs_dent->name_max);
            if (s_localflags & TSK_FS_IFIND_PAR_LONG) {
                tsk_fs_dent_print_long(stdout, s_fs_dent, fs, NULL);
            }
            else {
                tsk_fs_dent_print(stdout, s_fs_dent, fs, NULL);
                tsk_printf("\n");
            }
            s_fs_dent->fsi = NULL;
            s_found = 1;
        }
        fs_name = fs_name->next;
    }

    return TSK_WALK_CONT;
}



/* return 1 on error and 0 on success */
uint8_t
tsk_fs_ifind_par(TSK_FS_INFO * fs, uint8_t lclflags, TSK_INUM_T par)
{
    s_found = 0;
    s_localflags = lclflags;
    s_parinode = par;
    s_fs_dent = tsk_fs_dent_alloc(256, 0);
    if (s_fs_dent == NULL)
        return 1;

    /* Walk unallocated MFT entries */
    if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
            TSK_FS_INODE_FLAG_UNALLOC, ifind_par_act, NULL)) {
        tsk_fs_dent_free(s_fs_dent);
        return 1;
    }

    tsk_fs_dent_free(s_fs_dent);
    return 0;
}



/*******************************************************************************
 * Find an inode given a file path
 */

#define IFIND_PATH_DATA_ID	0x00886644
typedef struct {
    int id;
    char *cur_dir;              ///< The "current" directory or file we are looking for
    char *cur_attr;             ///< The "current" attribute of the dir we are looking for
    char *strtok_last;
    uint8_t found;
    uint8_t badpath;
    TSK_INUM_T addr;                // "Inode" address for file name
} IFIND_PATH_DATA;

/* 
 * dent_walk for finding the inode based on path
 *
 * This is run from the main function and from this function when
 * the needed directory is found
 */
static TSK_WALK_RET_ENUM
ifind_path_act(TSK_FS_INFO * fs, TSK_FS_DENT * a_fs_dent, void *ptr)
{
    IFIND_PATH_DATA *ipd = (IFIND_PATH_DATA *) ptr;
    char *pname;

    if ((!ipd) || (ipd->id != IFIND_PATH_DATA_ID)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ifind_path_act: callback pointer is not IFIND_DATA_ID\n");
        return TSK_WALK_ERROR;
    }

    /* This crashed because cur_dir was null, but I'm not sure how
     * it got that way, so this was added
     */
    if (ipd->cur_dir == NULL) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "ifind: cur_dir is null: Please run with '-v' and send output to carrier <at> sleuthkit <dot> org\n");
        return TSK_WALK_ERROR;
    }

    /* 
     * Check if this is the name that we are currently looking for,
     * as identified in 'cur_dir'
     *
     * All non-matches will return from these checks
     */
    if (((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
            TSK_FS_INFO_TYPE_EXT_TYPE)
        || ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
            TSK_FS_INFO_TYPE_FFS_TYPE)) {
        if (strcmp(a_fs_dent->name, ipd->cur_dir) != 0) {
            return TSK_WALK_CONT;
        }
    }

    /* NTFS gets a case insensitive comparison */
    else if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_NTFS_TYPE) {
        if (strcasecmp(a_fs_dent->name, ipd->cur_dir) != 0) {
            return TSK_WALK_CONT;
        }

        /*  ensure we have the right attribute name */
        if (ipd->cur_attr != NULL) {
            int fail = 1;

            if (a_fs_dent->fsi) {
                TSK_FS_DATA *fs_data;

                for (fs_data = a_fs_dent->fsi->attr;
                    fs_data != NULL; fs_data = fs_data->next) {

                    if ((fs_data->flags & TSK_FS_DATA_INUSE) == 0)
                        continue;

                    if (strcasecmp(fs_data->name, ipd->cur_attr) == 0) {
                        fail = 0;
                        break;
                    }
                }
            }
            if (fail) {
                tsk_printf("Attribute name (%s) not found in %s: %"
                    PRIuINUM "\n", ipd->cur_attr, ipd->cur_dir,
                    a_fs_dent->inode);

                return TSK_WALK_STOP;
            }
        }
    }
    /* FAT is a special case because we do case insensitive and we check
     * the short name 
     */
    else if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_FAT_TYPE) {
        if (strcasecmp(a_fs_dent->name, ipd->cur_dir) != 0) {
            if (strcasecmp(a_fs_dent->shrt_name, ipd->cur_dir) != 0) {
                return TSK_WALK_CONT;
            }
        }
    }

    /* If we made it here, then this file or directory was what
     * we were looking for.  So, we move on to the next. 
     */
    pname = ipd->cur_dir;       // save a copy of the current name pointer
    ipd->cur_dir = (char *) strtok_r(NULL, "/", &(ipd->strtok_last));
    ipd->cur_attr = NULL;

    if (tsk_verbose)
        tsk_fprintf(stderr, "Found it (%s), now looking for %s\n",
            a_fs_dent->name, ipd->cur_dir);

    /* That was the last name in the path -- we found the file! */
    if (ipd->cur_dir == NULL) {
        ipd->found = 1;
        ipd->addr = a_fs_dent->inode;

        /* if our only hit is an unallocated entry 
         * then keep on looking -- this commonly happens with NTFS */
        if (a_fs_dent->flags & TSK_FS_DENT_FLAG_UNALLOC) {
            ipd->cur_dir = pname;
            return TSK_WALK_CONT;
        }

        return TSK_WALK_STOP;
    }
    /* There are more dirs / files to find */
    /* Make sure this name has metadata / content */
    else if (a_fs_dent->fsi == NULL) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "Name does not point to an inode (%s)\n",
                a_fs_dent->name);
        return TSK_WALK_STOP;
    }

    /* Make sure this name is for a directory */
    else if ((a_fs_dent->fsi->mode & TSK_FS_INODE_MODE_FMT) !=
        TSK_FS_INODE_MODE_DIR) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "Name is not for a directory (%s) (mode: %x)\n",
                a_fs_dent->name,
                a_fs_dent->fsi->mode & TSK_FS_INODE_MODE_FMT);
        ipd->badpath = 1;
        return TSK_WALK_STOP;
    }

    /* if it is an NTFS image with an ADS in the name, then
     * break it up 
     */
    if (((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
            TSK_FS_INFO_TYPE_NTFS_TYPE)
        && ((ipd->cur_attr = strchr(ipd->cur_dir, ':')) != NULL)) {
        *(ipd->cur_attr) = '\0';
        ipd->cur_attr++;
    }

    /* Recurse on the directory */
    if (fs->dent_walk(fs, a_fs_dent->inode,
            TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_UNALLOC,
            ifind_path_act, (void *) ipd)) {
        return TSK_WALK_ERROR;
    }

    return TSK_WALK_STOP;
}


/**
 * Find the meta data address for a given file name
 *
 * @param fs FS to analyze
 * @param lclflags Flags for search
 * @param tpath Path of file to search for
 * @param [out] result Meta data address of file
 * @returns -1 on error, 0 if found, and 1 if not found
 */
int8_t
tsk_fs_ifind_path(TSK_FS_INFO * fs, uint8_t lclflags, TSK_TCHAR * tpath,
    TSK_INUM_T * result)
{
    char *cpath;                // utf-8 version of path to find
    IFIND_PATH_DATA ipd;

    s_localflags = lclflags;

#ifdef TSK_WIN32
    // Convert the UTF-16 path to UTF-8
    {
        size_t clen;
        UTF8 *ptr8;
        UTF16 *ptr16;
        int retval;

        clen = TSTRLEN(tpath) * 4;
        if ((cpath = (char *) tsk_malloc(clen)) == NULL) {
            return -1;
        }
        ptr8 = (UTF8 *) cpath;
        ptr16 = (UTF16 *) tpath;

        retval =
            tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &ptr16, (UTF16 *)
            & ptr16[TSTRLEN(tpath) + 1], &ptr8,
            (UTF8 *) ((uintptr_t) ptr8 + clen), TSKlenientConversion);
        if (retval != TSKconversionOK) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_UNICODE;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "tsk_fs_ifind_path: Error converting path to UTF-8: %d",
                retval);
            free(cpath);
            return -1;
        }
    }
#else
    {
        // copy to a buffer that we can modify
        size_t clen = strlen(tpath) + 1;
        if ((cpath = (char *) tsk_malloc(clen)) == NULL) {
            return -1;
        }
        strncpy(cpath, tpath, clen);
    }
#endif

    ipd.id = IFIND_PATH_DATA_ID;
    ipd.found = 0;
    ipd.badpath = 0;
    ipd.cur_dir = (char *) strtok_r(cpath, "/", &ipd.strtok_last);
    ipd.cur_attr = NULL;

    /* If there is no token, then only a '/' was given */
    if (!(ipd.cur_dir)) {
        free(cpath);
        *result = fs->root_inum;
        return 0;
    }

    /* If this is NTFS, seperate out the attribute of the current directory */
    if (((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
            TSK_FS_INFO_TYPE_NTFS_TYPE)
        && ((ipd.cur_attr = strchr(ipd.cur_dir, ':')) != NULL)) {
        *(ipd.cur_attr) = '\0';
        ipd.cur_attr++;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "Looking for %s\n", ipd.cur_dir);

    if (fs->dent_walk(fs, fs->root_inum,
            TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_UNALLOC,
            ifind_path_act, (void *) &ipd)) {
        /* If we found files before the error was encountered, then 
         * ignore it */
        if (ipd.found == 0) {
            free(cpath);
            return -1;
        }
        else {
            tsk_error_reset();
        }
    }

    free(cpath);

    if (1 == ipd.badpath) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "Invalid path (%s is a file)\n",
                ipd.cur_dir);
        *result = 0;
        return 1;
    }
    else if (0 == ipd.found) {
        if (tsk_verbose)
            TFPRINTF(stderr, _TSK_T("File not found: %s\n"), tpath);
        *result = 0;
        return 1;
    }

    *result = ipd.addr;
    return 0;
}





/*******************************************************************************
 * Find an inode given a data unit
 */

static TSK_DADDR_T block = 0;       /* the block to find */
static TSK_INUM_T curinode;         /* the inode being analyzed */

static uint32_t curtype;        /* the type currently being analyzed: NTFS */
static uint16_t curid;

/*
 * file_walk action for non-ntfs
 */
static TSK_WALK_RET_ENUM
ifind_data_file_act(TSK_FS_INFO * fs, TSK_DADDR_T addr, char *buf,
    size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    /* Drop references to block zero (sparse)
     * This becomes an issue with fragments and looking for fragments
     * within the first block.  They will be triggered by sparse 
     * entries, even though the first block can not be allocated
     */
    if (!addr)
        return TSK_WALK_CONT;

    if ((block >= addr) &&
        (block < (addr + (size + fs->block_size - 1) / fs->block_size))) {
        tsk_printf("%" PRIuINUM "\n", curinode);

        if (!(s_localflags & TSK_FS_IFIND_ALL)) {
            fs->close(fs);
            exit(0);
        }
        s_found = 1;
    }
    return TSK_WALK_CONT;
}


/* 
 * file_walk action callback for ntfs  
 *
 */
static TSK_WALK_RET_ENUM
ifind_data_file_ntfs_act(TSK_FS_INFO * fs, TSK_DADDR_T addr, char *buf,
    size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    if (addr == block) {
        tsk_printf("%" PRIuINUM "-%" PRIu32 "-%" PRIu16 "\n", curinode,
            curtype, curid);

        if (!(s_localflags & TSK_FS_IFIND_ALL)) {
            fs->close(fs);
            exit(0);
        }
        s_found = 1;
    }
    return TSK_WALK_CONT;
}



/*
** find_inode
**
** Callback action for inode_walk
*/
static TSK_WALK_RET_ENUM
ifind_data_act(TSK_FS_INFO * fs, TSK_FS_INODE * fs_inode, void *ptr)
{
    int file_flags = (TSK_FS_FILE_FLAG_AONLY);

    /* If the meta data structure is unallocated, then set the recovery flag */
    if (fs_inode->flags & TSK_FS_INODE_FLAG_UNALLOC)
        file_flags |= TSK_FS_FILE_FLAG_RECOVER;

    curinode = fs_inode->addr;

    /* NT Specific Stuff: search all ADS */
    if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_NTFS_TYPE) {
        TSK_FS_DATA *data;


        file_flags |= TSK_FS_FILE_FLAG_SLACK;
        for (data = fs_inode->attr; data != NULL; data = data->next) {

            if ((data->flags & TSK_FS_DATA_INUSE) == 0)
                continue;

            curtype = data->type;
            curid = data->id;
            if (data->flags & TSK_FS_DATA_NONRES) {
                if (fs->file_walk(fs, fs_inode, data->type, data->id,
                        file_flags, ifind_data_file_ntfs_act, ptr)) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "Error walking file %" PRIuINUM,
                            fs_inode->addr);

                    /* Ignore these errors */
                    tsk_error_reset();
                }
            }
        }
        return TSK_WALK_CONT;
    }
    else if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_FAT_TYPE) {
        file_flags |= (TSK_FS_FILE_FLAG_SLACK | TSK_FS_FILE_FLAG_NOID);
        if (fs->file_walk(fs, fs_inode, 0, 0, file_flags,
                ifind_data_file_act, ptr)) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "Error walking file %" PRIuINUM,
                    fs_inode->addr);

            /* Ignore these errors */
            tsk_error_reset();
        }
    }
    /* UNIX do not need the SLACK flag because they use fragments - if the
     * SLACK flag exists then any unused fragments in a block will be 
     * correlated with the incorrect inode
     *
     * The META flag is needed though to find indirect blocks
     */
    else {
        file_flags |= (TSK_FS_FILE_FLAG_NOID | TSK_FS_FILE_FLAG_META);
        if (fs->file_walk(fs, fs_inode, 0, 0, file_flags,
                ifind_data_file_act, ptr)) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "Error walking file %" PRIuINUM,
                    fs_inode->addr);

            /* Ignore these errors */
            tsk_error_reset();
        }
    }

    return TSK_WALK_CONT;
}


/*
 * if the block is a meta data block, then report that, otherwise
 * this is where we say that the inode was not found
 */
static TSK_WALK_RET_ENUM
ifind_data_block_act(TSK_FS_INFO * fs, TSK_DADDR_T addr, char *buf,
    TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    if (flags & TSK_FS_BLOCK_FLAG_META) {
        tsk_printf("Meta Data\n");
        s_found = 1;
    }

    return TSK_WALK_STOP;
}


/* 
 * Find the inode that has allocated block blk
 * Return 1 on error, 0 if no error */
uint8_t
tsk_fs_ifind_data(TSK_FS_INFO * fs, uint8_t lclflags, TSK_DADDR_T blk)
{
    s_found = 0;
    s_localflags = lclflags;
    block = blk;

    if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
            TSK_FS_INODE_FLAG_ALLOC | TSK_FS_INODE_FLAG_UNALLOC,
            ifind_data_act, NULL)) {
        return 1;
    }

    /* 
     * If we did not find an inode yet, we call block_walk for the 
     * block to find out the associated flags so we can identify it as
     * a meta data block */
    if (0 == s_found) {
        if (fs->block_walk(fs, block, block, (TSK_FS_BLOCK_FLAG_ENUM)
                (TSK_FS_BLOCK_FLAG_UNALLOC | TSK_FS_BLOCK_FLAG_ALLOC |
                    TSK_FS_BLOCK_FLAG_META | TSK_FS_BLOCK_FLAG_CONT),
                ifind_data_block_act, NULL)) {
            return 1;
        }
    }
    if (0 == s_found) {
        tsk_printf("Inode not found\n");
    }
    return 0;
}
