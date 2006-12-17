/*
** ifind (inode find)
** The Sleuth Kit
**
** $Date: 2006/12/05 21:39:52 $
**
** Given an image  and block number, identify which inode it is used by
** 
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
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

#include "fs_tools_i.h"


static uint8_t localflags;
static uint8_t found;


/*******************************************************************************
 * Find an unallocated NTFS MFT entry based on its parent directory
 */

static FS_DENT *fs_dent = NULL;
static INUM_T parinode = 0;

/* dent call back for finding unallocated files based on parent directory
 */
static uint8_t
ifind_par_act(FS_INFO * fs, FS_INODE * fs_inode, int flags, void *ptr)
{
    FS_NAME *fs_name;

    /* go through each file name structure */
    fs_name = fs_inode->name;
    while (fs_name) {
	if (fs_name->par_inode == parinode) {
	    /* Fill in the basics of the fs_dent entry */
	    fs_dent->fsi = fs_inode;
	    fs_dent->inode = fs_inode->addr;
	    strncpy(fs_dent->name, fs_name->name, fs_dent->name_max);
	    if (localflags & IFIND_PAR_LONG) {
		fs_dent_print_long(stdout, fs_dent, FS_FLAG_NAME_UNALLOC,
		    fs, NULL);
	    }
	    else {
		fs_dent_print(stdout, fs_dent, FS_FLAG_NAME_UNALLOC, fs,
		    NULL);
		tsk_printf("\n");
	    }
	    fs_dent->fsi = NULL;
	    found = 1;
	}
	fs_name = fs_name->next;
    }

    return WALK_CONT;
}



/* return 1 on error and 0 on success */
uint8_t
fs_ifind_par(FS_INFO * fs, uint8_t lclflags, INUM_T par)
{
    found = 0;
    localflags = lclflags;
    parinode = par;
    fs_dent = fs_dent_alloc(256, 0);
    if (fs_dent == NULL)
	return 1;

    /* Walk unallocated MFT entries */
    if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
	    FS_FLAG_META_UNALLOC, ifind_par_act, NULL)) {
	fs_dent_free(fs_dent);
	return 1;
    }

    fs_dent_free(fs_dent);
    return 0;
}



/*******************************************************************************
 * Find an inode given a file path
 */

#define IFIND_PATH_DATA_ID	0x00886644
typedef struct {
    int id;
    char *cur_dir;
    char *cur_attr;
    uint8_t found;
    uint8_t badpath;
    INUM_T addr;		// "Inode" address for file name
} IFIND_PATH_DATA;

/* 
 * dent_walk for finding the inode based on path
 *
 * This is run from the main function and from this function when
 * the needed directory is found
 */
static uint8_t
ifind_path_act(FS_INFO * fs, FS_DENT * fs_dent, int flags, void *ptr)
{
    IFIND_PATH_DATA *ipd = (IFIND_PATH_DATA *) ptr;

    if ((!ipd) || (ipd->id != IFIND_PATH_DATA_ID)) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "ifind_path_act: callback pointer is not IFIND_DATA_ID\n");
	return WALK_ERROR;
    }

    /* This crashed because cur_dir was null, but I'm not sure how
     * it got that way, so this was added
     */
    if (ipd->cur_dir == NULL) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "ifind: cur_dir is null: Please run with '-v' and send output to developers\n");
	return WALK_ERROR;
    }

    /* 
     * Check if this is the name that we are currently looking for,
     * as identified in 'cur_dir'
     *
     * All non-matches will return from these checks
     */
    if (((fs->ftype & FSMASK) == EXTxFS_TYPE) ||
	((fs->ftype & FSMASK) == FFS_TYPE)) {
	if (strcmp(fs_dent->name, ipd->cur_dir) != 0) {
	    return WALK_CONT;
	}
    }

    /* NTFS gets a case insensitive comparison */
    else if ((fs->ftype & FSMASK) == NTFS_TYPE) {
	if (strcasecmp(fs_dent->name, ipd->cur_dir) != 0) {
	    return WALK_CONT;
	}

	/*  ensure we have the right attribute name */
	if (ipd->cur_attr != NULL) {
	    int fail = 1;

	    if (fs_dent->fsi) {
		FS_DATA *fs_data;

		for (fs_data = fs_dent->fsi->attr;
		    fs_data != NULL; fs_data = fs_data->next) {

		    if ((fs_data->flags & FS_DATA_INUSE) == 0)
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
		    fs_dent->inode);

		return WALK_STOP;
	    }
	}
    }
    /* FAT is a special case because we do case insensitive and we check
     * the short name 
     */
    else if ((fs->ftype & FSMASK) == FATFS_TYPE) {
	if (strcasecmp(fs_dent->name, ipd->cur_dir) != 0) {
	    if (strcasecmp(fs_dent->shrt_name, ipd->cur_dir) != 0) {
		return WALK_CONT;
	    }
	}
    }

    /* Get the next directory or file name */
    ipd->cur_dir = (char *) strtok(NULL, "/");
    ipd->cur_attr = NULL;

    if (verbose)
	tsk_fprintf(stderr, "Found it (%s), now looking for %s\n",
	    fs_dent->name, ipd->cur_dir);

    /* That was the last name in the path -- we found the file */
    if (ipd->cur_dir == NULL) {
	//tsk_printf("%" PRIuINUM "\n", fs_dent->inode);
	ipd->found = 1;
	ipd->addr = fs_dent->inode;

	// if our only hit is an unallocated entry 
	// then keep on looking -- this commonly happens with NTFS
	if (flags & FS_FLAG_NAME_UNALLOC)
	    return WALK_CONT;
	else
	    return WALK_STOP;
    }

    /* if it is an NTFS image with an ADS in the name, then
     * break it up 
     */
    if (((fs->ftype & FSMASK) == NTFS_TYPE) &&
	((ipd->cur_attr = strchr(ipd->cur_dir, ':')) != NULL)) {
	*(ipd->cur_attr) = '\0';
	ipd->cur_attr++;
    }

    /* it is a directory so we can recurse */
    if ((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR) {

	if (fs->dent_walk(fs, fs_dent->inode,
		FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC,
		ifind_path_act, (void *) ipd)) {
	    return WALK_ERROR;
	}
    }

    /* The name was correct, but it was not a directory */
    else {
	ipd->badpath = 1;
    }

    return WALK_STOP;
}


/* Return -1 for error, 0 if found, and 1 if not found */
int8_t
fs_ifind_path(FS_INFO * fs, uint8_t lclflags, TSK_TCHAR * tpath,
    INUM_T * result)
{
    char *cpath;
    IFIND_PATH_DATA ipd;


    localflags = lclflags;


#ifdef TSK_WIN32
    {
	size_t clen;
	UTF8 *ptr8;
	UTF16 *ptr16;
	int retval;

	clen = TSTRLEN(tpath) * 4;
	cpath = (char *) mymalloc(clen);
	if (cpath == NULL) {
	    return -1;
	}
	ptr8 = (UTF8 *) cpath;
	ptr16 = (UTF16 *) tpath;

	retval =
	    tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &ptr16, (UTF16 *)
	    & ptr16[TSTRLEN(tpath) + 1], &ptr8,
	    (UTF8 *) ((uintptr_t) ptr8 + clen), lenientConversion);
	if (retval != conversionOK) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_UNICODE;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"fs_ifind_path: Error converting path to UTF-8: %d",
		retval);
	    free(cpath);
	    return -1;
	}
    }
#else
    cpath = tpath;
#endif

    ipd.id = IFIND_PATH_DATA_ID;
    ipd.found = 0;
    ipd.badpath = 0;
    ipd.cur_dir = (char *) strtok(cpath, "/");
    ipd.cur_attr = NULL;

    /* If there is no token, then only a '/' was given */
    if (!(ipd.cur_dir)) {
	tsk_printf("%lu\n", (ULONG) fs->root_inum);
#ifdef TSK_WIN32
	free(cpath);
#endif
    *result = fs->root_inum;
	return 0;
    }

    /* If this is NTFS, ensure that we take out the attribute */
    if (((fs->ftype & FSMASK) == NTFS_TYPE) &&
	((ipd.cur_attr = strchr(ipd.cur_dir, ':')) != NULL)) {
	*(ipd.cur_attr) = '\0';
	ipd.cur_attr++;
    }

    if (verbose)
	tsk_fprintf(stderr, "Looking for %s\n", ipd.cur_dir);

    if (fs->dent_walk(fs, fs->root_inum,
	    FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC, ifind_path_act,
	    (void *) &ipd)) {
#ifdef TSK_WIN32
	free(cpath);
#endif
	return -1;
    }


#ifdef TSK_WIN32
    free(cpath);
#endif

    if (1 == ipd.badpath) {
	if (verbose)
	    tsk_fprintf(stderr, "Invalid path (%s is a file)\n",
		fs_dent->name);
	*result = 0;
	return 1;
    }
    else if (0 == ipd.found) {
	if (verbose)
	    tsk_printf("File not found: %s\n", ipd.cur_dir);
	*result = 0;
	return 1;
    }

    *result = ipd.addr;
    return 0;
}





/*******************************************************************************
 * Find an inode given a data unit
 */

static DADDR_T block = 0;	/* the block to find */
static INUM_T curinode;		/* the inode being analyzed */

static uint32_t curtype;	/* the type currently being analyzed: NTFS */
static uint16_t curid;

/*
 * file_walk action for non-ntfs
 */
static uint8_t
ifind_data_file_act(FS_INFO * fs, DADDR_T addr, char *buf,
    size_t size, int flags, void *ptr)
{
    /* Drop references to block zero (sparse)
     * This becomes an issue with fragments and looking for fragments
     * within the first block.  They will be triggered by sparse 
     * entries, even though the first block can not be allocated
     */
    if (!addr)
	return WALK_CONT;

    if ((block >= addr) &&
	(block < (addr + (size + fs->block_size - 1) / fs->block_size))) {
	tsk_printf("%" PRIuINUM "\n", curinode);

	if (!(localflags & IFIND_ALL)) {
	    fs->close(fs);
	    exit(0);
	}
	found = 1;
    }
    return WALK_CONT;
}


/* 
 * file_walk action callback for ntfs  
 *
 */
static uint8_t
ifind_data_file_ntfs_act(FS_INFO * fs, DADDR_T addr, char *buf,
    size_t size, int flags, void *ptr)
{
    if (addr == block) {
	tsk_printf("%" PRIuINUM "-%" PRIu32 "-%" PRIu16 "\n", curinode,
	    curtype, curid);

	if (!(localflags & IFIND_ALL)) {
	    fs->close(fs);
	    exit(0);
	}
	found = 1;
    }
    return WALK_CONT;
}



/*
** find_inode
**
** Callback action for inode_walk
*/
static uint8_t
ifind_data_act(FS_INFO * fs, FS_INODE * fs_inode, int flags, void *ptr)
{
    int file_flags = (FS_FLAG_FILE_AONLY);

    /* If the meta data structure is unallocated, then set the recovery flag */
    if (flags & FS_FLAG_META_UNALLOC)
	file_flags |= FS_FLAG_FILE_RECOVER;

    curinode = fs_inode->addr;

    /* NT Specific Stuff: search all ADS */
    if ((fs->ftype & FSMASK) == NTFS_TYPE) {
	FS_DATA *data;


	file_flags |= FS_FLAG_FILE_SLACK;
	for (data = fs_inode->attr; data != NULL; data = data->next) {

	    if ((data->flags & FS_DATA_INUSE) == 0)
		continue;

	    curtype = data->type;
	    curid = data->id;
	    if (data->flags & FS_DATA_NONRES) {
		if (fs->file_walk(fs, fs_inode, data->type, data->id,
			file_flags, ifind_data_file_ntfs_act, ptr)) {
		    if (verbose)
			tsk_fprintf(stderr,
			    "Error walking file %" PRIuINUM,
			    fs_inode->addr);

		    /* Ignore these errors */
		    tsk_error_reset();
		}
	    }
	}
	return WALK_CONT;
    }
    else if ((fs->ftype & FSMASK) == FATFS_TYPE) {
	file_flags |= (FS_FLAG_FILE_SLACK | FS_FLAG_FILE_NOID);
	if (fs->file_walk(fs, fs_inode, 0, 0, file_flags,
		ifind_data_file_act, ptr)) {
	    if (verbose)
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
	file_flags |= (FS_FLAG_FILE_NOID | FS_FLAG_FILE_META);
	if (fs->file_walk(fs, fs_inode, 0, 0, file_flags,
		ifind_data_file_act, ptr)) {
	    if (verbose)
		tsk_fprintf(stderr, "Error walking file %" PRIuINUM,
		    fs_inode->addr);

	    /* Ignore these errors */
	    tsk_error_reset();
	}
    }

    return WALK_CONT;
}


/*
 * if the block is a meta data block, then report that, otherwise
 * this is where we say that the inode was not found
 */
static uint8_t
ifind_data_block_act(FS_INFO * fs, DADDR_T addr, char *buf, int flags,
    void *ptr)
{
    if (flags & FS_FLAG_DATA_META) {
	tsk_printf("Meta Data\n");
	found = 1;
    }

    return WALK_STOP;
}


/* 
 * Find the inode that has allocated block blk
 * Return 1 on error, 0 if no error */
uint8_t
fs_ifind_data(FS_INFO * fs, uint8_t lclflags, DADDR_T blk)
{
    found = 0;
    localflags = lclflags;
    block = blk;

    if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
	    FS_FLAG_META_ALLOC | FS_FLAG_META_UNALLOC,
	    ifind_data_act, NULL)) {
	return 1;
    }

    /* 
     * If we did not find an inode yet, we call block_walk for the 
     * block to find out the associated flags so we can identify it as
     * a meta data block */
    if (0 == found) {
	if (fs->block_walk(fs, block, block,
		FS_FLAG_DATA_UNALLOC | FS_FLAG_DATA_ALLOC |
		FS_FLAG_DATA_META | FS_FLAG_DATA_CONT,
		ifind_data_block_act, NULL)) {
	    return 1;
	}
    }
    if (0 == found) {
	tsk_printf("Inode not found\n");
    }
    return 0;
}
