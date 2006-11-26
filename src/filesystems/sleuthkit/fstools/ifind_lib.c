/*
** ifind (inode find)
** The Sleuth Kit
**
** $Date: 2006/07/05 18:24:09 $
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

#include "libfstools.h"


static uint8_t localflags;
static uint8_t found;


/*******************************************************************************
 * Find an NTFS MFT entry based on its parent directory
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
	    /* Fill in teh basics of the fs_dent entry */
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
		printf("\n");
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

    if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
	    FS_FLAG_META_LINK | FS_FLAG_META_UNLINK |
	    FS_FLAG_META_UNALLOC | FS_FLAG_META_USED, ifind_par_act,
	    NULL)) {
	fs_dent_free(fs_dent);
	return 1;
    }

    fs_dent_free(fs_dent);
    return 0;
}



/*******************************************************************************
 * Find an inode given a file path
 */

struct ifind_path_state {
    char *cur_dir;
    char *cur_attr;
    uint8_t found;
    INUM_T inode;
};
/* 
 * dent_walk for finding the inode based on path
 *
 * This is run from the main function and from this function when
 * the needed directory is found
 */
static uint8_t
ifind_path_act(FS_INFO * fs, FS_DENT * fs_dent, int flags, void *ptr)
{
    struct ifind_path_state *state = (struct ifind_path_state *)ptr;

    /* This crashed because cur_dir was null, but I'm not sure how
     * it got that way, so this was added
     */
    if (state->cur_dir == NULL) {
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
	if (strcmp(fs_dent->name, state->cur_dir) != 0) {
	    return WALK_CONT;
	}
    }

    /* NTFS gets a case insensitive comparison */
    else if ((fs->ftype & FSMASK) == NTFS_TYPE) {
	if (strcasecmp(fs_dent->name, state->cur_dir) != 0) {
	    return WALK_CONT;
	}

    /* if this is a realloc'd file, try and keep going to find an allocated
     * file with the same name. NOTE: this will only skip the first realloc
     * file (can there be more than one?) */
    if(!fs_dent->fsi) {
        state->inode = fs_dent->inode;
	    state->found = 1;
        return WALK_CONT;
    }   

	/*  ensure we have the right attribute name */
	if (state->cur_attr != NULL) {
	    int fail = 1;

	    if (fs_dent->fsi) {
		FS_DATA *fs_data;
		fs_data = fs_dent->fsi->attr;

		while ((fs_data) && (fs_data->flags & FS_DATA_INUSE)) {
		    if (strcasecmp(fs_data->name, state->cur_attr) == 0) {
			fail = 0;
			break;
		    }
		    fs_data = fs_data->next;
		}
	    }
	    if (fail) {
		printf("Attribute name (%s) not found in %s: %" PRIuINUM
		    "\n", state->cur_attr, state->cur_dir, fs_dent->inode);

		return WALK_STOP;
	    }
	}
    }
    /* FAT is a special case because we do case insensitive and we check
     * the short name 
     */
    else if ((fs->ftype & FSMASK) == FATFS_TYPE) {
	if (strcasecmp(fs_dent->name, state->cur_dir) != 0) {
	    if (strcasecmp(fs_dent->shrt_name, state->cur_dir) != 0) {
		return WALK_CONT;
	    }
	}
    }

    /* Get the next directory or file name */
    state->cur_dir = (char *) strtok(NULL, "/");
    state->cur_attr = NULL;

    if (verbose)
	fprintf(stderr, "Found it (%s), now looking for %s\n",
	    fs_dent->name, state->cur_dir);

    /* That was the last one */
    if (state->cur_dir == NULL) {
    state->inode = fs_dent->inode;
	state->found = 1;
	return WALK_STOP;
    }

    /* if it is an NTFS image with an ADS in the name, then
     * break it up 
     */
    if (((fs->ftype & FSMASK) == NTFS_TYPE) &&
	((state->cur_attr = strchr(state->cur_dir, ':')) != NULL)) {
	*state->cur_attr = '\0';
	state->cur_attr++;
    }

    /* it is a directory so we can recurse */
    if ((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR) {

	if (fs->dent_walk(fs, fs_dent->inode,
		FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC,
		ifind_path_act, (void *) state)) {
	    return WALK_ERROR;
	}
    }

    /* The name was correct, but it was not a directory */
    else {
	printf("Invalid path (%s is a file)\n", fs_dent->name);
    }

    return WALK_STOP;
}

INUM_T
fs_ifind_path_ret(FS_INFO * fs, uint8_t lclflags, char *path)
{
    struct ifind_path_state state;
    state.found = 0;
    localflags = lclflags;

    state.cur_dir = (char *) strtok(path, "/");
    state.cur_attr = NULL;

    /* If there is no token, then only a '/' was given */
    if (!state.cur_dir)
        return fs->root_inum;

    /* If this is NTFS, ensure that we take out the attribute */
    if (((fs->ftype & FSMASK) == NTFS_TYPE) &&
	((state.cur_attr = strchr(state.cur_dir, ':')) != NULL)) {
	*state.cur_attr = '\0';
	state.cur_attr++;
    }

    if (verbose)
	fprintf(stderr, "Looking for %s\n", state.cur_dir);

    if (fs->dent_walk(fs, fs->root_inum,
	    FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC, ifind_path_act,
	    (void *)&state)) {
	return 0;
    }

    if (state.found)
        return state.inode;

	printf("File not found: %s\n", state.cur_dir);
    return 0;
}

/* Return 1 for error, 0 if no error */
uint8_t
fs_ifind_path(FS_INFO * fs, uint8_t lclflags, char *path)
{
    INUM_T inode = fs_ifind_path_ret(fs, lclflags, path);
    if(inode == 0)
        return 1;

    printf("%" PRIuINUM "\n", inode);
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
    unsigned int size, int flags, void *ptr)
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
	printf("%" PRIuINUM "\n", curinode);

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
    unsigned int size, int flags, void *ptr)
{
    if (addr == block) {
	printf("%" PRIuINUM "-%" PRIu32 "-%" PRIu16 "\n", curinode,
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
	FS_DATA *data = fs_inode->attr;

	file_flags |= FS_FLAG_FILE_SLACK;
	while ((data) && (data->flags & FS_DATA_INUSE)) {
	    curtype = data->type;
	    curid = data->id;
	    if (data->flags & FS_DATA_NONRES) {
		if (fs->file_walk(fs, fs_inode, data->type, data->id,
			file_flags, ifind_data_file_ntfs_act, ptr)) {
		    if (verbose)
			fprintf(stderr, "Error walking file %" PRIuINUM,
			    fs_inode->addr);
/* Ignore these errors */
		    tsk_error_reset();
		}
	    }
	    data = data->next;
	}
	return WALK_CONT;
    }
    else if ((fs->ftype & FSMASK) == FATFS_TYPE) {
	file_flags |= (FS_FLAG_FILE_SLACK | FS_FLAG_FILE_NOID);
	if (fs->file_walk(fs, fs_inode, 0, 0, file_flags,
		ifind_data_file_act, ptr)) {
	    if (verbose)
		fprintf(stderr, "Error walking file %" PRIuINUM,
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
		fprintf(stderr, "Error walking file %" PRIuINUM,
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
	printf("Meta Data\n");
	found = 1;
    }

    return WALK_STOP;
}


/* Return 1 on error, 0 if no error */
uint8_t
fs_ifind_data(FS_INFO * fs, uint8_t lclflags, DADDR_T blk)
{
    found = 0;
    localflags = lclflags;
    block = blk;

    if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
	    FS_FLAG_META_LINK | FS_FLAG_META_UNLINK |
	    FS_FLAG_META_ALLOC | FS_FLAG_META_UNALLOC |
	    FS_FLAG_META_USED | FS_FLAG_META_UNUSED, ifind_data_act,
	    NULL)) {
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
	printf("Inode not found\n");
    }
    return 0;
}
