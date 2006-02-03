/*
** ffs_dent
** The  Sleuth Kit 
**
** $Date: 2005/10/13 04:15:21 $
**
** Human Interface Layer Support for a FFS image 
**
** Brian Carrier [carrier@sleuthkit.org]
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

#include <ctype.h>
#include "fs_tools.h"
#include "ffs.h"


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

} FFS_DINFO;

static void ffs_dent_walk_lcl(FS_INFO *, FFS_DINFO *, INUM_T, int,
			      FS_DENT_WALK_FN, void *);


/* 
** copy OS specific directory inode to generic FS_DENT
*/
static void
ffs_dent_copy(FFS_INFO * ffs, FFS_DINFO * dinfo, char *ffs_dent,
	      FS_DENT * fs_dent)
{
    FS_INFO *fs = &(ffs->fs_info);

    /* this one has the type field */
    if ((fs->ftype == FFS_1) || (fs->ftype == FFS_2)) {
	ffs_dentry1 *dir = (ffs_dentry1 *) ffs_dent;

	fs_dent->inode = getu32(fs, dir->d_ino);

	if (fs_dent->name_max != FFS_MAXNAMLEN)
	    fs_dent_realloc(fs_dent, FFS_MAXNAMLEN);

	/* ffs null terminates so we can strncpy */
	strncpy(fs_dent->name, dir->d_name, fs_dent->name_max);

	/* generic types are same as FFS */
	fs_dent->ent_type = dir->d_type;

    }
    else if (fs->ftype == FFS_1B) {
	ffs_dentry2 *dir = (ffs_dentry2 *) ffs_dent;

	fs_dent->inode = getu32(fs, dir->d_ino);

	if (fs_dent->name_max != FFS_MAXNAMLEN)
	    fs_dent_realloc(fs_dent, FFS_MAXNAMLEN);

	/* ffs null terminates so we can strncpy */
	strncpy(fs_dent->name, dir->d_name, fs_dent->name_max);

	fs_dent->ent_type = FS_DENT_UNDEF;
    }
    else {
	error("dent_copy: Unknown FFS Type");
    }

    /* copy the path data */
    fs_dent->path = dinfo->dirs;
    fs_dent->pathdepth = dinfo->depth;

    if ((fs != NULL) && (fs_dent->inode)) {
	/* Get inode */
	if (fs_dent->fsi)
	    fs_inode_free(fs_dent->fsi);
	fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);
    }
    else {
	fs_dent->fsi = NULL;
    }
}


/* Scan the buffer for directory entries and call action on each.
** Flags will be
** set to FS_FLAG_NAME_ALLOC for acive entires and FS_FLAG_NAME_UNALLOC for
** deleted ones
**
** len is size of buf
**
** return how much was read this time, or 0 if action said to stop
*/
static int
ffs_dent_parse_block(FFS_INFO * ffs, FFS_DINFO * dinfo, char *buf,
		     unsigned int len, int flags, FS_DENT_WALK_FN action,
		     void *ptr)
{
    unsigned int idx;
    unsigned int inode = 0, dellen = 0, reclen = 0;
    unsigned int minreclen = 4;
    FS_INFO *fs = &(ffs->fs_info);

    char *dirPtr;
    FS_DENT *fs_dent;

    fs_dent = fs_dent_alloc(FFS_MAXNAMLEN + 1, 0);

    /* update each time by the actual length instead of the
     ** recorded length so we can view the deleted entries 
     */
    for (idx = 0; idx <= len - FFS_DIRSIZ_lcl(1); idx += minreclen) {
	unsigned int namelen = 0;
	int myflags = 0;

	dirPtr = (char *) &buf[idx];

	/* copy to local variables */
	if ((fs->ftype == FFS_1) || (fs->ftype == FFS_2)) {
	    ffs_dentry1 *dir = (ffs_dentry1 *) dirPtr;
	    inode = getu32(fs, dir->d_ino);
	    namelen = dir->d_namlen;
	    reclen = getu16(fs, dir->d_reclen);
	}
	/* FFS_1B */
	else if (fs->ftype == FFS_1B) {
	    ffs_dentry2 *dir = (ffs_dentry2 *) dirPtr;
	    inode = getu32(fs, dir->d_ino);
	    namelen = getu16(fs, dir->d_namlen);
	    reclen = getu16(fs, dir->d_reclen);
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
	    dellen -= 4;
	    continue;
	}

	/* the entry is valid */
	ffs_dent_copy(ffs, dinfo, dirPtr, fs_dent);

	myflags = 0;
	/* Do we have a deleted entry? (are we in a deleted space) */
	if ((dellen > 0) || (inode == 0)) {
	    myflags |= FS_FLAG_NAME_UNALLOC;
	    dellen -= minreclen;
	    if (flags & FS_FLAG_NAME_UNALLOC) {
		if (WALK_STOP == action(fs, fs_dent, myflags, ptr)) {
		    fs_dent_free(fs_dent);
		    return 0;
		}
	    }
	}
	else {
	    myflags |= FS_FLAG_NAME_ALLOC;
	    if (flags & FS_FLAG_NAME_ALLOC) {
		if (WALK_STOP == action(fs, fs_dent, myflags, ptr)) {
		    fs_dent_free(fs_dent);
		    return 0;
		}
	    }
	}

	/* If we have some slack, the set dellen */
	if ((reclen != minreclen) && (dellen <= 0))
	    dellen = reclen - minreclen;


	/* if we have a directory and the RECURSE flag is set, then
	 * lets do it
	 */
	if ((myflags & FS_FLAG_NAME_ALLOC) &&
	    (flags & FS_FLAG_NAME_RECURSE) &&
	    (!ISDOT(fs_dent->name)) &&
	    ((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR)) {

	    /* save the path */
	    if (dinfo->depth < MAX_DEPTH) {
		dinfo->didx[dinfo->depth] =
		    &dinfo->dirs[strlen(dinfo->dirs)];
		strncpy(dinfo->didx[dinfo->depth], fs_dent->name,
			DIR_STRSZ - strlen(dinfo->dirs));
		strncat(dinfo->dirs, "/", DIR_STRSZ);
	    }
	    dinfo->depth++;

	    /* Call ourselves again */
	    ffs_dent_walk_lcl(&(ffs->fs_info), dinfo, fs_dent->inode,
			      flags, action, ptr);

	    dinfo->depth--;
	    if (dinfo->depth < MAX_DEPTH)
		*dinfo->didx[dinfo->depth] = '\0';
	}

    }				/* end for size */

    fs_dent_free(fs_dent);
    return len;

}				/* end ffs_dent_parse_block */



/* Process _inode_ as a directory inode and process the data blocks
** as file entries.  Call action on all entries with the flags set to
** FS_FLAG_NAME_ALLOC for active entries
**
**
** Use the following flags: FS_FLAG_NAME_ALLOC, FS_FLAG_NAME_UNALLOC, 
** FS_FLAG_NAME_RECURSE
*/
void
ffs_dent_walk(FS_INFO * fs, INUM_T inode, int flags,
	      FS_DENT_WALK_FN action, void *ptr)
{
    FFS_DINFO dinfo;
    memset(&dinfo, 0, sizeof(FFS_DINFO));

    ffs_dent_walk_lcl(fs, &dinfo, inode, flags, action, ptr);
}

static void
ffs_dent_walk_lcl(FS_INFO * fs, FFS_DINFO * dinfo, INUM_T inode, int flags,
		  FS_DENT_WALK_FN action, void *ptr)
{
    OFF_T size;
    FS_INODE *fs_inode;
    FFS_INFO *ffs = (FFS_INFO *) fs;
    char *dirbuf;
    int nchnk, cidx;
    FS_LOAD_FILE load_file;

    if (inode < fs->first_inum || inode > fs->last_inum)
	error("invalid inode value: %" PRIuINUM "\n", inode);

    if (verbose)
	fprintf(stderr,
		"fffs_dent_walk: Processing directory %" PRIuINUM "\n",
		inode);

    fs_inode = fs->inode_lookup(fs, inode);

    /* make a copy of the directory contents that we can process */
    /* round up cause we want the slack space too */
    size = roundup(fs_inode->size, FFS_DIRBLKSIZ);
    dirbuf = mymalloc(size);

    load_file.total = load_file.left = size;
    load_file.base = load_file.cur = dirbuf;

    fs->file_walk(fs, fs_inode, 0, 0,
		  FS_FLAG_FILE_SLACK | FS_FLAG_FILE_NOID |
		  FS_FLAG_FILE_NOABORT, load_file_action,
		  (void *) &load_file);

    /* Not all of the directory was copied, so we exit */
    if (load_file.left > 0) {
	free(dirbuf);
	fs_inode_free(fs_inode);

	if (dinfo->depth == 0)
	    error("Error reading directory contents: %" PRIuINUM "\n",
		  inode);

	return;
    }

    /* Directory entries are written in chunks of DIRBLKSIZ
     ** determine how many chunks of this size we have to read to
     ** get a full block
     **
     ** Entries do not cross over the DIRBLKSIZ boundary
     */
    nchnk = (size) / (FFS_DIRBLKSIZ) + 1;

    for (cidx = 0; cidx < nchnk && size > 0; cidx++) {
	int len = (FFS_DIRBLKSIZ < size) ? FFS_DIRBLKSIZ : size;
	int retval;

	retval =
	    ffs_dent_parse_block(ffs, dinfo, dirbuf + cidx * FFS_DIRBLKSIZ,
				 len, flags, action, ptr);

	size -= retval;

	/* zero is returned when the action wants to stop */
	if (!retval)
	    break;
    }

    fs_inode_free(fs_inode);
    free(dirbuf);
    return;
}
