/*
** ffs_dent
** The  Sleuth Kit 
**
** Human Interface Layer Support for a FFS image 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** TCTUTILs
** Brian Carrier [carrier@cerias.purdue.edu]
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**
** 1. Redistributions of source code must retain the above copyright notice,
**    this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote
**    products derived from this software without specific prior written
**    permission.     
**
**
** THIS SOFTWARE IS NOT AFFILIATED WITH PURDUE UNIVERSITY OR THE CENTER FOR
** EDUCATION IN INFORMATION ASSURANCE AND SECURITY (CERIAS) AND THEY BEAR
** NO RESPONSIBILITY FOR ITS USE OR MISUSE.
**
**
** THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
** WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR ANY PARTICULAR PURPOSE.
**
** IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
** INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS OR
** BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
** WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
** OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
** ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/

#include "fs_tools.h"
#include "ffs.h"

#include "mymalloc.h"
#include "error.h"


/* Recursive path stuff */
static unsigned int depth = 0;  /* how deep in the directory tree are we */
#define MAX_DEPTH   64
static char *didx[MAX_DEPTH];  /* pointer in dirs string to where '/' is for
                        ** given depth */
#define DIR_STRSZ   2048
static char dirs[DIR_STRSZ];    /* The current directory name string */


/* 
** copy OS specific directory inode to generic FS_DENT
*/
static void 
ffs_dent_copy(FFS_INFO *ffs, char *ffs_dent, FS_DENT *fs_dent) 
{
	FS_INFO *fs = &(ffs->fs_info);

	/* this one has the type field */
	if (fs->ftype == FFS_1) {
		ffs_dentry1  *dir = (ffs_dentry1 *)ffs_dent;

		fs_dent->inode = getu32(fs, dir->d_ino);
		fs_dent->nextLink = getu16(fs, dir->d_reclen);

		/* NOTE: d_namlen is 8 bits in this structure, not 16 */
		fs_dent->namlen = dir->d_namlen;
		fs_dent->reclen = FFS_DIRSIZ_lcl(dir->d_namlen);

		if (fs_dent->maxnamlen != FFS_MAXNAMLEN) 
			fs_dent_realloc(fs_dent, FFS_MAXNAMLEN);

		/* ffs null terminates so we can strncpy */
		strncpy(fs_dent->name, dir->d_name, fs_dent->maxnamlen);

		/* generic types are same as FFS */
		fs_dent->ent_type = dir->d_type;

	}
	/* FFS_2 */
	else {
		ffs_dentry2  *dir = (ffs_dentry2 *)ffs_dent;

		fs_dent->inode = getu32(fs, dir->d_ino);
		fs_dent->nextLink = getu16(fs, dir->d_reclen);
		fs_dent->namlen = getu16(fs, dir->d_namlen);
		fs_dent->reclen = FFS_DIRSIZ_lcl(getu16(fs, dir->d_namlen));

		if (fs_dent->maxnamlen != FFS_MAXNAMLEN) 
			fs_dent_realloc(fs_dent, FFS_MAXNAMLEN);

		/* ffs null terminates so we can strncpy */
		strncpy(fs_dent->name, dir->d_name, fs_dent->maxnamlen);

		fs_dent->ent_type = FS_DENT_UNDEF;
	}

	/* copy the path data */
	fs_dent->path = dirs;
	fs_dent->pathdepth = depth;

	if ((fs != NULL)  && (fs_dent->inode)) {
		/* Get inode */
		if (fs_dent->fsi)
			free(fs_dent->fsi);
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
ffs_dent_parse_block (FFS_INFO *ffs, char *buf, int len,
  int flags, FS_DENT_WALK_FN action, char *ptr) 
{
	unsigned int idx;
	int inode, dellen = 0, reclen = 0;
	int minreclen = 4;
	FS_INFO *fs = &(ffs->fs_info);

	char *dirPtr;
	FS_DENT *fs_dent;

	fs_dent = fs_dent_alloc(FFS_MAXNAMLEN + 1);

	/* update each time by the actual length instead of the
	** recorded length so we can view the deleted entries 
	*/
	for (idx = 0; idx <= len - FFS_DIRSIZ_lcl(1); idx += minreclen) {
		int namelen, myflags;

		dirPtr = (char *)&buf[idx];

		/* copy to local variables */
		if (fs->ftype == FFS_1) {
			ffs_dentry1 *dir = (ffs_dentry1 *)dirPtr;
			inode = getu32(fs, dir->d_ino);
			namelen = dir->d_namlen;
			reclen = getu16(fs, dir->d_reclen);
		}
		/* FFS_2 */
		else {
			ffs_dentry2 *dir = (ffs_dentry2 *)dirPtr;
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
		   (reclen < minreclen) ||
		   (reclen % 4) ||
		   (reclen > FFS_DIRBLKSIZ) ) {
	
			/* we don't have a valid entry, so skip ahead 4 */
			minreclen = 4;
			if (dellen > 0)
				dellen -= 4;
			continue;
		}

		/* the entry is valid */
		ffs_dent_copy(ffs, dirPtr, fs_dent);


		myflags = 0;
		/* Do we have a deleted entry? (are we in a deleted space) */
		if ((dellen > 0) || (inode == 0)) {
			myflags |= FS_FLAG_NAME_UNALLOC;
			dellen -= minreclen;
			if (flags & FS_FLAG_NAME_UNALLOC) {
				if (WALK_STOP == action (fs, fs_dent, myflags, ptr)) {
					return 0;
				}
			}
		} 
		else {
			myflags |= FS_FLAG_NAME_ALLOC;
			if (flags & FS_FLAG_NAME_ALLOC) {
				if (WALK_STOP == action (fs, fs_dent, myflags, ptr)) {
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
		  (flags & FS_FLAG_NAME_RECURSE)  &&
		  (!ISDOT(fs_dent->name)) &&
		  ((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR)) {

			/* save the path */
			if (depth < MAX_DEPTH) {
				didx[depth] = &dirs[strlen(dirs)];
				strncpy(didx[depth], fs_dent->name, DIR_STRSZ - strlen(dirs));
				strncat(dirs, "/", DIR_STRSZ);
			}
			depth++;

			/* Call ourselves again */
			ffs_dent_walk(&(ffs->fs_info), fs_dent->inode, flags, action, ptr);

			depth--;
			if (depth < MAX_DEPTH)
				*didx[depth] = '\0';
		}

	} /* end for size */

	return len;

} /* end ffs_dent_parse_block */



/*
 * Action for dent_walk
 *
 * This will save a copy of the directory contents into a buffer
 * The buffer will then be passed to the parsing function 
 */

static char *curdirptr = NULL;
static int dirleft = 0;

static u_int8_t 
ffs_dent_action(FS_INFO *fs, DADDR_T addr, char *buf, int size, 
  int flags, char *ptr)
{ 
	int len = (dirleft < size) ? dirleft : size;
	memcpy (curdirptr, buf, len);
	curdirptr = (char *) ((int)curdirptr + len);
	dirleft -= len;
	return (dirleft) ? WALK_CONT : WALK_STOP;
}


/* Process _inode_ as a directory inode and process the data blocks
** as file entries.  Call action on all entries with the flags set to
** FS_FLAG_NAME_ALLOC for active entries
**
**
** Use the following flags: FS_FLAG_NAME_ALLOC, FS_FLAG_NAME_UNALLOC, 
** FS_FLAG_NAME_RECURSE
*/
void 
ffs_dent_walk(FS_INFO *fs, INUM_T inode, int flags, 
  FS_DENT_WALK_FN action, char *ptr) 
{
	OFF_T  		size;
	FS_INODE 	*fs_inode;
	FFS_INFO	*ffs = (FFS_INFO *)fs;
	char 		*dirbuf;
	int 		nchnk, cidx;

	if (inode < fs->first_inum || inode > fs->last_inum)
		error("invalid inode value: %i\n", inode);

	fs_inode = fs->inode_lookup(fs, inode);

	/* make a copy of the directory contents that we can process */
	if (curdirptr != NULL)
		error ("ffs_dent_walk: Curdirptr is set! recursive?");

	/* round up cause we want the slack space too */
	size = roundup (fs_inode->size, FFS_DIRBLKSIZ);

	curdirptr = dirbuf = mymalloc(size);
	dirleft = size;

	fs->file_walk(fs, fs_inode, 0, 0, 
	  FS_FLAG_FILE_SLACK | FS_FLAG_FILE_NOID,
	  ffs_dent_action, "");

	curdirptr = NULL;

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

	   	retval = ffs_dent_parse_block(ffs, dirbuf + cidx*FFS_DIRBLKSIZ, 
		  len, flags, action, ptr);

		size -= retval;

		/* zero is returned when the action wants to stop */
		if (!retval)
			break;
	}

	free(dirbuf);
	return;
}

