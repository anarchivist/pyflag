/*
** fatfs_dent
** The Sleuth Kit 
**
** $Date: 2005/07/08 17:20:10 $
**
** Human interface Layer support for the FAT file system
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
*/

#include "fs_tools.h"
#include "fatfs.h"

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
    char name[FATFS_MAXNAMLEN];	/* buffer for lfn - in reverse order */
    uint16_t len;		/* current length  of name */
    uint8_t chk;		/* current checksum */
    uint8_t seq;		/* seq of first entry in lfn */
} FATFS_LFN;

#define MAX_DEPTH   64
#define DIR_STRSZ  2048

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
    INUM_T curdir_inode;	/* the . inode */
    INUM_T pardir_inode;	/* the .. inode */


    /* We need to search for an inode addr based on starting cluster, 
     * these do it */
    DADDR_T find_clust;
    DADDR_T find_inode;

    /* Set to 1 when we are recursing down a deleted directory.  This will
     * supress the errors that may occur from invalid data
     */
    uint8_t recdel;

} FATFS_DINFO;


static void fatfs_dent_walk_lcl(FS_INFO *, FATFS_DINFO *, INUM_T, int,
				FS_DENT_WALK_FN, void *);


/*
 * Copy the contents of the FAT specific directory entry into the generic
 * one.
 *
 * This gets interesting with the way that FAT handles long file names.
 * LFN are handled by proceeding the original 8.3 entry with special
 * structures that handle 13 UNICODE values.  These have a special 
 * attribute set.  The LFN structures are in reverse order and end with
 * an 8.3 entry with the short version of the name.
 *
 * We handle this by copying the LFN values into the FATFS_LFN structure
 * and then when we get the 8.3 entry the long name is copied in.  Therefore,
 * FATFS_LFN keeps state between calls to this function.
 *
 * Ideally, we should print out the partial lfn when we find one with a
 * new checksum, but that does not work because this is supposed to return
 * only one entry and that case may cause two entries to be returned.
 */
static void
fatfs_dent_copy(FATFS_INFO * fatfs, FATFS_DINFO * dinfo,
		FATFS_LFN * lfninfo, char *fatfs_dent, FS_DENT * fs_dent,
		INUM_T inum, DADDR_T sect)
{
    int i;
    fatfs_dentry *dir = (fatfs_dentry *) fatfs_dent;

    fs_dent->inode = inum;

    /* Name */
    if ((dir->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
	fatfs_dentry_lfn *dirl = (fatfs_dentry_lfn *) fatfs_dent;

	/* Store the name in dinfo until we get the 8.3 name */

	/* Is this a new sequence?  The checksum is the same for all entries
	 * in the same sequence 
	 */

	if (dirl->chksum != lfninfo->chk) {
	    lfninfo->seq = dirl->seq;
	    lfninfo->chk = dirl->chksum;
	    lfninfo->len = 0;
	}

	/* we are only going to support ASCII - not full UNICODE */
	for (i = 2; i >= 0; i -= 2) {
	    if ((dirl->part3[i] != 0) && (dirl->part3[i] != 0xff)) {
		if (lfninfo->len < FATFS_MAXNAMLEN)
		    lfninfo->name[lfninfo->len++] = dirl->part3[i];
	    }
	}
	for (i = 10; i >= 0; i -= 2) {
	    if ((dirl->part2[i] != 0) && (dirl->part2[i] != 0xff)) {
		if (lfninfo->len < FATFS_MAXNAMLEN)
		    lfninfo->name[lfninfo->len++] = dirl->part2[i];
	    }
	}
	for (i = 8; i >= 0; i -= 2) {
	    if ((dirl->part1[i] != 0) && (dirl->part1[i] != 0xff)) {
		if (lfninfo->len < FATFS_MAXNAMLEN)
		    lfninfo->name[lfninfo->len++] = dirl->part1[i];
	    }
	}
    }
    /* Special case for volume label, where name does not have an
     * extension and we add a note at the end that it is a label */
    else if ((dir->attrib & FATFS_ATTR_VOLUME) == FATFS_ATTR_VOLUME) {
	fs_dent->namlen = 0;
	for (i = 0; i < 8; i++) {
	    if ((dir->name[i] != 0) && (dir->name[i] != 0xff)) {
		fs_dent->name[fs_dent->namlen++] = dir->name[i];
	    }
	}
	for (i = 0; i < 3; i++) {
	    if ((dir->ext[i] != 0) && (dir->ext[i] != 0xff)) {
		fs_dent->name[fs_dent->namlen++] = dir->ext[i];
	    }
	}

	fs_dent->name[fs_dent->namlen] = '\0';
	/* Append a string to show it is a label */
	if (fs_dent->namlen + 22 < FATFS_MAXNAMLEN) {
	    char *volstr = " (Volume Label Entry)";
	    strncat(fs_dent->name, volstr,
		    FATFS_MAXNAMLEN - fs_dent->namlen);
	    fs_dent->namlen += strlen(volstr);
	}
    }

    /* we have a short (8.3) entry 
     * we may have the long name version already stored in the FATFS_INFO
     */
    else {

	fs_dent->namlen = 0;

	/* if we have the lfn, copy it in.  Remember it is backwards */
	/* @@@ We could check the checksum, but how would we report it */
	if (lfninfo->len != 0) {
	    for (i = 0; i < lfninfo->len; i++)
		fs_dent->name[fs_dent->namlen++] =
		    lfninfo->name[lfninfo->len - 1 - i];

	    fs_dent->name[fs_dent->namlen] = '\0';
	    lfninfo->len = 0; 
	}

	else {
	if (fs_dent->namlen + 12 < FATFS_MAXNAMLEN) {
	    /* copy in the short name, skipping spaces and putting in the . */
	    for (i = 0; i < 8; i++) {
		if ((dir->name[i] != 0) && (dir->name[i] != 0xff) &&
		    (dir->name[i] != 0x20)) {

		    if ((i == 0) && (dir->name[0] == FATFS_SLOT_DELETED))
			fs_dent->name[fs_dent->namlen++] = '_';
		    else if ((dir->lowercase & FATFS_CASE_LOWER_BASE) &&
			     (dir->name[i] >= 'A')
			     && (dir->name[i] <= 'Z'))
			fs_dent->name[fs_dent->namlen++] =
			    dir->name[i] + 32;
		    else
			fs_dent->name[fs_dent->namlen++] = dir->name[i];
		}
	    }

	    for (i = 0; i < 3; i++) {
		if ((dir->ext[i] != 0) && (dir->ext[i] != 0xff) &&
		    (dir->ext[i] != 0x20)) {
		    if (i == 0)
			fs_dent->name[fs_dent->namlen++] = '.';
		    if ((dir->lowercase & FATFS_CASE_LOWER_EXT) &&
			(dir->ext[i] >= 'A') && (dir->ext[i] <= 'Z'))
			fs_dent->name[fs_dent->namlen++] =
			    dir->ext[i] + 32;
		    else
			fs_dent->name[fs_dent->namlen++] = dir->ext[i];
		}
	    }
	    fs_dent->name[fs_dent->namlen] = '\0';
	}
	}
    }


    /* append the path data */
    fs_dent->path = dinfo->dirs;
    fs_dent->pathdepth = dinfo->depth;


    /* file type: FAT only knows DIR and FILE */
    if ((dir->attrib & FATFS_ATTR_DIRECTORY) == FATFS_ATTR_DIRECTORY)
	fs_dent->ent_type = FS_DENT_DIR;
    else
	fs_dent->ent_type = FS_DENT_REG;

    /* Get inode */
    if (inum)
	fatfs_dinode_copy(fatfs, fs_dent->fsi, dir, sect, inum);

    return;
}


/**************************************************************************
 *
 * find_parent
 *
 *************************************************************************/

/*
 * this is the call back for the dent walk when we need to find the 
 * parent directory
 *
 * dinfo->save_state should be 0 when this is running
 */
static uint8_t
find_parent_act(FS_INFO * fs, FS_DENT * fsd, int flags, void *ptr)
{
    FATFS_DINFO *dinfo = (FATFS_DINFO *) ptr;

    /* we found the directory entry that has allocated the cluster 
     * we are looking for */
    if (fsd->fsi->direct_addr[0] == dinfo->find_clust) {
	dinfo->find_inode = fsd->inode;
	return WALK_STOP;
    }
    return WALK_CONT;
}

/*
 * this function will find the parent inode of the directory
 * specified in fs_dent. It works by walking the directory tree
 * starting at the root.  
 *
 * return the inode number
 */
static INUM_T
find_parent(FATFS_INFO * fatfs, FS_DENT * fs_dent)
{
    FS_INFO *fs = (FS_INFO *) & fatfs->fs_info;
    FATFS_DINFO dinfo;

    memset(&dinfo, 0, sizeof(FATFS_DINFO));

    /* set the value that the action function will use */
    dinfo.find_clust = fs_dent->fsi->direct_addr[0];

    if (verbose)
	fprintf(logfp,
		"fatfs_find_parent: Looking for directory in cluster %"
		PRIuDADDR "\n", dinfo.find_clust);

    /* Are we searching for the root directory? */
    if (fs->ftype == FAT32) {
	OFF_T clust = FATFS_SECT_2_CLUST(fatfs, fatfs->rootsect);

	if ((clust == dinfo.find_clust) || (dinfo.find_clust == 0)) {
	    return fs->root_inum;
	}
    }
    else {
	if ((dinfo.find_clust == 1) || (dinfo.find_clust == 0)) {
	    return fs->root_inum;
	}
    }

    if ((fs_dent->fsi->mode & FS_INODE_FMT) != FS_INODE_DIR) {
	error("fatfs_find_parent called on a non-directory");
    }


    /* walk the inodes - looking for an inode that has allocated the
     * same first sector 
     */

    fatfs_dent_walk_lcl(fs, &dinfo, fs->root_inum,
			FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_RECURSE,
			find_parent_act, (void *) &dinfo);


    if (verbose)
	fprintf(logfp,
		"fatfs_find_parent: Directory %" PRIuINUM
		" found for cluster %" PRIuDADDR "\n", dinfo.find_inode,
		dinfo.find_clust);

    /* if we didn't find anything then 0 will be returned */
    return dinfo.find_inode;
}

/* 
**
** Read contents of directory sector (in buf) with length len and
** original address of addr.  len should be a multiple of 512.
**
** fs_dent should be empty and is used to hold the data, but we allocate
** it only once... 
**
** flags: FS_FLAG_NAME_ALLOC, FS_FLAG_NAME_UNALLOC, FS_FLAG_NAME_RECURSE
*/
static void
fatfs_dent_parse_buf(FATFS_INFO * fatfs, FATFS_DINFO * dinfo,
		     char *buf, int len,
		     DADDR_T * addrs, int flags,
		     FS_DENT_WALK_FN action, void *ptr)
{
    unsigned int idx, i;
    INUM_T inode, ibase;
    fatfs_dentry *dep;
    FS_INFO *fs = (FS_INFO *) & fatfs->fs_info;
    int sectalloc;
    FS_DENT *fs_dent;
    FATFS_LFN lfninfo;

    if (buf == NULL)
	error("fatfs_dent_parse_buf: buffer is NULL");

    dep = (fatfs_dentry *) buf;


    fs_dent = fs_dent_alloc(FATFS_MAXNAMLEN);
    fs_dent->fsi = fs_inode_alloc(FATFS_NDADDR, FATFS_NIADDR);
    memset(&lfninfo, 0, sizeof(FATFS_LFN));


    for (i = 0; i < (unsigned int) (len / 512); i++) {

	/* Get the base inode for this sector */
	ibase = FATFS_SECT_2_INODE(fatfs, addrs[i]);
	if (ibase > fs->last_inum)
	    error("parse error: inode address is too large");

	if (verbose)
	    fprintf(logfp,
		    "fatfs_dent_parse_buf: Parsing sector %" PRIuDADDR
		    "\n", addrs[i]);


	sectalloc = is_sectalloc(fatfs, addrs[i]);

	/* cycle through the directory entries */
	for (idx = 0; idx < fatfs->dentry_cnt_se; idx++, dep++) {

	    int myflags = 0;

	    /* is it a valid dentry? */
	    if (0 == fatfs_isdentry(fatfs, dep))
		continue;

	    inode = ibase + idx;

	    /* Copy the entry
	     * if this is LFN, then the name will be copied into lfninfo */
	    fatfs_dent_copy(fatfs, dinfo, &lfninfo, (char *) dep, fs_dent,
			    inode, addrs[i]);


	    /* If it is a long file name, then keep on going until the
	     * final small name is reached */
	    if ((dep->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN)
		continue;

	    /* Handle the . and .. entries specially
	     * The current inode 'address' they have is for the current
	     * slot in the cluster, but it needs to refer to the original
	     * slot 
	     */
	    if (dep->name[0] == '.') {

		/* dinfo->curdir_inode is always set and we can copy it in */
		if (dep->name[1] == ' ')
		    inode = fs_dent->inode = dinfo->curdir_inode;

		/* dinfo->pardir_inode is not always set, so we may have to search */
		else if (dep->name[1] == '.') {

		    /* dinfo->save_state is set to 0 when we are already looking
		     * for a parent by its cluster */
		    if ((!dinfo->pardir_inode) && (!dinfo->find_clust))
			dinfo->pardir_inode = find_parent(fatfs, fs_dent);

		    inode = fs_dent->inode = dinfo->pardir_inode;

		    /* If the .. entry is for the root directory, then make
		     * up the data
		     */
		    if (inode == fs->root_inum)
			fatfs_make_root(fatfs, fs_dent->fsi);
		}
	    }


	    /* The allocation status of an entry is based on the allocation
	     * status of the sector it is in and the flag.  Deleted directories
	     * do not always clear the flags of each entry
	     */
	    if (sectalloc == 1) {
		myflags = (dep->name[0] == FATFS_SLOT_DELETED) ?
		    FS_FLAG_NAME_UNALLOC : FS_FLAG_NAME_ALLOC;
	    }
	    else {
		myflags = FS_FLAG_NAME_UNALLOC;
	    }

	    if ((flags & myflags) == myflags) {
		if (WALK_STOP == action(fs, fs_dent, myflags, ptr)) {
		    return;
		}
	    }


	    /* if we have a directory and need to recurse then do it */
	    if (((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR) &&
		(flags & FS_FLAG_NAME_RECURSE)
		&& (!ISDOT(fs_dent->name))) {

		INUM_T back_p = 0;
		uint8_t back_recdel = 0;


		/* we are going to append only the short name */
		if (dinfo->depth < MAX_DEPTH) {
		    dinfo->didx[dinfo->depth] =
			&dinfo->dirs[strlen(dinfo->dirs)];
		    strncpy(dinfo->didx[dinfo->depth], fs_dent->name,
			    DIR_STRSZ - strlen(dinfo->dirs));
		    strncat(dinfo->dirs, "/", DIR_STRSZ);
		}

		/* save the .. inode value */
		back_p = dinfo->pardir_inode;
		dinfo->pardir_inode = dinfo->curdir_inode;
		dinfo->depth++;


		/* This will prevent errors from being generated from the invalid
		 * deleted files.  save the current setting and set it to del */
		if (myflags & FS_FLAG_NAME_ALLOC) {
		    back_recdel = dinfo->recdel;
		    dinfo->recdel = 1;
		}

		fatfs_dent_walk_lcl(&(fatfs->fs_info), dinfo,
				    fs_dent->inode, flags, action, ptr);

		dinfo->depth--;
		dinfo->curdir_inode = dinfo->pardir_inode;
		dinfo->pardir_inode = back_p;

		if (dinfo->depth < MAX_DEPTH)
		    *dinfo->didx[dinfo->depth] = '\0';

		/* Restore the recursion setting */
		if (myflags & FS_FLAG_NAME_ALLOC) {
		    dinfo->recdel = back_recdel;
		}
	    }
	}
    }
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
    DADDR_T *curaddrbuf;

    /* num of entries allocated to curaddrbuf */
    size_t addrsize;

    /* The current index in the curaddrbuf stack */
    size_t addridx;

} FATFS_LOAD_DIR;



/* 
 * file_walk callback action to load directory contents 
 */
static uint8_t
fatfs_dent_action(FS_INFO * fs, DADDR_T addr, char *buf,
		  unsigned int size, int flags, void *ptr)
{
    FATFS_LOAD_DIR *load = (FATFS_LOAD_DIR *) ptr;

    /* how much of the buffer are we copying */
    int len = (load->dirleft < size) ? load->dirleft : size;

    /* Copy the sector into a buffer and increment the pointers */
    memcpy(load->curdirptr, buf, len);
    load->curdirptr = (char *) ((uintptr_t) load->curdirptr + len);
    load->dirleft -= len;

    /* fill in the stack of addresses of sectors 
     *
     * if we are at the last entry, then realloc more */
    if (load->addridx == load->addrsize) {
	if (verbose)
	    fprintf(logfp, "fatfs_dent_action: realloc curaddrbuf");

	load->addrsize += 512;
	load->curaddrbuf = (DADDR_T *) myrealloc((char *) load->curaddrbuf,
						 load->addrsize *
						 sizeof(DADDR_T));
    }

    /* Add this sector to the stack */
    load->curaddrbuf[load->addridx++] = addr;

    if (load->dirleft)
	return WALK_CONT;
    else
	return WALK_STOP;
}


/* 
** The main function to do directory entry walking
**
** action is called for each entry with flags set to FS_FLAG_NAME_ALLOC for
** active entries
**
** Use the following flags: FS_FLAG_NAME_ALLOC, FS_FLAG_NAME_UNALLOC, 
** FS_FLAG_NAME_RECURSE
*/
void
fatfs_dent_walk(FS_INFO * fs, INUM_T inode, int flags,
		FS_DENT_WALK_FN action, void *ptr)
{
    FATFS_DINFO dinfo;

    memset(&dinfo, 0, sizeof(FATFS_DINFO));
    fatfs_dent_walk_lcl(fs, &dinfo, inode, flags, action, ptr);
}


static void
fatfs_dent_walk_lcl(FS_INFO * fs, FATFS_DINFO * dinfo, INUM_T inode,
		    int flags, FS_DENT_WALK_FN action, void *ptr)
{
    OFF_T size, len;
    FS_INODE *fs_inode;
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    char *dirbuf;
    DADDR_T *addrbuf;
    FATFS_LOAD_DIR load;

    if ((inode < fs->first_inum) || (inode > fs->last_inum))
	error("invalid inode value: %" PRIuINUM "\n", inode);

    fs_inode = fs->inode_lookup(fs, inode);
    if (!fs_inode)
	error("%" PRIuINUM " is not a valid inode", inode);

    size = fs_inode->size;
    len = roundup(size, 512);

    if (verbose)
	fprintf(logfp,
		"fatfs_dent_walk: Processing directory %" PRIuINUM "\n",
		inode);

    /* Save the current inode value ('.') */
    dinfo->curdir_inode = inode;

    /* Make a copy of the directory contents using file_walk */
    dirbuf = mymalloc(len);
    memset(dirbuf, 0, len);
    load.curdirptr = dirbuf;
    load.dirleft = size;

    /* We are going to save the address of each sector in the directory
     * in a stack - they are needed to determine the inode address */
    load.addrsize = 512;
    addrbuf = (DADDR_T *) mymalloc(load.addrsize * sizeof(DADDR_T));

    /* Set the variables that are used during the copy */
    load.addridx = 0;
    load.curaddrbuf = addrbuf;

    /* save the directory contents into dirbuf */
    if (dinfo->recdel == 0) {
	fs->file_walk(fs, fs_inode, 0, 0,
		      FS_FLAG_FILE_SLACK | FS_FLAG_FILE_NOID,
		      fatfs_dent_action, (void *) &load);

	if (load.dirleft > 0) {
	    error
		("fatfs_dent_walk: Entire directory was not loaded (%Zd left)",
		 load.dirleft);
	}
    }
    else {
	fs->file_walk(fs, fs_inode, 0, 0,
		      FS_FLAG_FILE_SLACK | FS_FLAG_FILE_RECOVER |
		      FS_FLAG_FILE_NOID, fatfs_dent_action,
		      (void *) &load);

	/* We did not copy the entire directory, but it was a deleted dir. 
	 * During recovery of a deleted file, the FAT code will only
	 * return content if it can recover the entire file
	 */
	if (load.dirleft > 0) {

	    /* Free the local buffers */
	    free(load.curaddrbuf);
	    free(load.curdirptr);
	    fs_inode_free(fs_inode);

	    return;
	}
    }

    /* Reset the local pointer because we could have done a realloc */
    addrbuf = load.curaddrbuf;

    fatfs_dent_parse_buf(fatfs, dinfo, dirbuf, len, addrbuf, flags,
			 action, ptr);

    fs_inode_free(fs_inode);
    free(dirbuf);
    free(addrbuf);
}
