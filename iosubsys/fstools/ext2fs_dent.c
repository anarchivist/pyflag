/*
** ext2fs_dent
** The Sleuth Kit 
**
** Human Interface Layer Support for an EXT2FS image
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** TCTUTILS
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
*/

#include "fs_tools.h"
#include "ext2fs.h"
#include "mymalloc.h"
#include "error.h"



/* Recursive path stuff */
static unsigned int depth = 0;  /* how deep in the directory tree are we */
#define MAX_DEPTH   64
static char *didx[MAX_DEPTH];  /* pointer in dirs string to where '/' is for
                        ** given depth */
#define DIR_STRSZ  2048 
static char dirs[DIR_STRSZ];    /* The current directory name string */


static void 
ext2fs_dent_copy(EXT2FS_INFO *ext2fs, char *ext2_dent, FS_DENT *fs_dent) 
{
	FS_INFO *fs = &(ext2fs->fs_info);
	
	if (fs->ftype == EXT2FS_1) {
		ext2fs_dentry1 *dir = (ext2fs_dentry1 *)ext2_dent;

		fs_dent->inode = getu32(fs, dir->inode);
		fs_dent->nextLink = getu16(fs, dir->rec_len);
		fs_dent->namlen = getu16(fs, dir->name_len);
		fs_dent->reclen = EXT2FS_DIRSIZ_lcl(getu16(fs, dir->name_len));

		/* ext2 does not null terminate */
		if (fs_dent->namlen >= fs_dent->maxnamlen) 
			error("ext2fs_dent_copy: Name Space too Small %d %d", 
			  fs_dent->namlen, fs_dent->maxnamlen);

		/* Copy and Null Terminate */
		strncpy(fs_dent->name, dir->name, fs_dent->namlen); 
		fs_dent->name[fs_dent->namlen] = '\0';	

		fs_dent->ent_type = FS_DENT_UNDEF;

	}
	else {
		ext2fs_dentry2 *dir = (ext2fs_dentry2 *)ext2_dent;

		fs_dent->inode = getu32(fs, dir->inode);
		fs_dent->nextLink = getu16(fs, dir->rec_len);
		fs_dent->namlen = dir->name_len;
		fs_dent->reclen = EXT2FS_DIRSIZ_lcl(dir->name_len);

		/* ext2 does not null terminate */
		if (fs_dent->namlen >= fs_dent->maxnamlen) 
			error("ext2_dent_copy: Name Space too Small %d %d", 
			  fs_dent->namlen, fs_dent->maxnamlen);

		/* Copy and Null Terminate */
		strncpy(fs_dent->name, dir->name, fs_dent->namlen); 
		fs_dent->name[fs_dent->namlen] = '\0';	

		switch(dir->type) {
		case EXT2_DE_REG_FILE:
			fs_dent->ent_type = FS_DENT_REG;
			break;
		case EXT2_DE_DIR:
			fs_dent->ent_type = FS_DENT_DIR;
			break;
		case EXT2_DE_CHRDEV:
			fs_dent->ent_type = FS_DENT_CHR;
			break;
		case EXT2_DE_BLKDEV:
			fs_dent->ent_type = FS_DENT_BLK;
			break;
		case EXT2_DE_FIFO:
			fs_dent->ent_type = FS_DENT_FIFO;
			break;
		case EXT2_DE_SOCK:
			fs_dent->ent_type = FS_DENT_SOCK;
			break;
		case EXT2_DE_SYMLINK:
			fs_dent->ent_type = FS_DENT_LNK;
			break;
		case EXT2_DE_UNKNOWN:
		default:
			fs_dent->ent_type = FS_DENT_UNDEF;
			break;
		}

	}

	fs_dent->path = dirs;
	fs_dent->pathdepth = depth;

	if ((fs != NULL) && (fs_dent->inode)) {
		/* Get inode */

		if (fs_dent->fsi)
			free(fs_dent->fsi);

		fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);

	} 
	else {
		fs_dent->fsi = NULL;
	}
}


/* 
**
** Read contents of directory block
**
** if entry is active call action with myflags set to FS_FLAG_NAME_ALLOC, if 
** it is deleted then call action with FS_FLAG_NAME_UNALLOC.
** len is the size of buf
**
** return how much was read this time or 0 if action wanted to stop
*/
static int 
ext2fs_dent_parse_block(EXT2FS_INFO *ext2fs, char *buf, int len,
  int flags, FS_DENT_WALK_FN action, char *ptr) 
{
	FS_INFO *fs = &(ext2fs->fs_info);

	int idellen = 0;
	int idx;
	u_int16_t reclen;
	u_int32_t inode;
	char *dirPtr;
	FS_DENT *fs_dent;
	int minreclen = 4;

	fs_dent = fs_dent_alloc(EXT2FS_MAXNAMLEN + 1);

	/* update each time by the actual length instead of the
	** recorded length so we can view the deleted entries 
	*/
	for (idx = 0; idx <= len - EXT2FS_DIRSIZ_lcl(1); idx += minreclen)  {

		unsigned int namelen;
		dirPtr = &buf[idx];

		if (fs->ftype == EXT2FS_1) {
			ext2fs_dentry1 *dir = (ext2fs_dentry1 *)dirPtr;
			inode =  getu32(fs, dir->inode);
			namelen = getu16(fs, dir->name_len);
			reclen = getu16(fs, dir->rec_len);
		}
		else {
			ext2fs_dentry2 *dir = (ext2fs_dentry2 *)dirPtr;
			inode =  getu32(fs, dir->inode);
			namelen = dir->name_len;
			reclen = getu16(fs, dir->rec_len);
		}

		minreclen = EXT2FS_DIRSIZ_lcl(namelen);

		/* 
		** Check if we may have a valid direct entry.  If we don't
		** then increment to the next word and try again.  
		**
		** although inodes can really only be >= 2, we have to check
		** for >= 0 to find deleted ones
		**
		*/
		if ((inode > fs->last_inum) || 
		   (inode < 0) || 
		   (namelen > EXT2FS_MAXNAMLEN) || 
		   (namelen <= 0) || 
		   (reclen < minreclen) ||
		   (reclen % 4) ||
		   (reclen > fs->block_size) ) {

			/* we don't have a valid entry, skip ahead 4 */
			minreclen = 4;
			if (idellen > 0)
				idellen -= 4;
			continue;
		}

		/* If the inode value is 0 and it is the first entry, then 
		** it has been deleted so print it out.
		** Otherwise inodes of 0 should not be in the middle of
		** the block with FFS.  They will exist for deleted entries
		** under EXT2FS though, so make a special conditional 
		** using name length for it
		*/
		if ((inode > 1) || ((inode == 0) && 
		  ((idx == 0) || (namelen > 0)) ) )  {

			int myflags = 0;

			ext2fs_dent_copy(ext2fs, dirPtr, fs_dent);

			myflags = 0;
			/* Do we have a deleted entry? */
			if ((idellen > 0) || (inode == 0)) {
				myflags |= FS_FLAG_NAME_UNALLOC;
				idellen -= minreclen;
				if (flags & FS_FLAG_NAME_UNALLOC)
					if (WALK_STOP == action(fs, fs_dent, myflags, ptr))
						return 0;
			}
			/* We have a non-deleted entry */
			else {
				myflags |= FS_FLAG_NAME_ALLOC;
				if (flags & FS_FLAG_NAME_ALLOC)
					if (WALK_STOP == action(fs, fs_dent, myflags, ptr))
						return 0;
			}

			/* If the actual length is shorter then the 
			** recorded length, then the next entry(ies) have been 
			** deleted.  Set idellen to the length of data that 
			** has been deleted
			**
			** Because we aren't guaranteed with Ext2FS that the next
			** entry begins right after this one, we will check to
			** see if the difference is less than a possible entry
			** before we waste time searching it
			*/
			if ((reclen - minreclen >= EXT2FS_DIRSIZ_lcl(1)) 
			  && (idellen <= 0))
				idellen = reclen - minreclen;


		
			/* we will be recursing directories */
			if ((myflags & FS_FLAG_NAME_ALLOC) &&
			  (flags & FS_FLAG_NAME_RECURSE)  &&
			  (!ISDOT(fs_dent->name)) &&
			  ((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR)) {

				if (depth < MAX_DEPTH) {
 					didx[depth] = &dirs[strlen(dirs)];
					strncpy(didx[depth], fs_dent->name, 
					  DIR_STRSZ - strlen(dirs));
					strncat(dirs, "/", DIR_STRSZ);
				}
        	    depth++;
				ext2fs_dent_walk(&(ext2fs->fs_info), fs_dent->inode, 
				  flags, action, ptr);

				depth--;
				if (depth < MAX_DEPTH)
					*didx[depth] = '\0';
        	}

		} /* end of if for inode == 0 etc */
		else {
			/* We are here because the inode was 0 and namelen was 0
			** increment to next word and try again
			*/
			minreclen = 4;
		}

	} /* end for */
	return len;

} /* end ext2fs_dent_parse_block() */



static char *curdirptr = NULL;
static int dirleft = 0;
  
static u_int8_t
ext2fs_dent_action(FS_INFO *fs, DADDR_T addr, char *buf, int size,
  int flags, char *ptr)
{
    int len = (dirleft < size) ? dirleft : size;
    memcpy (curdirptr, buf, len); 
    curdirptr = (char *) ((int)curdirptr + len);
    dirleft -= len;
    if (dirleft)
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
** this calls ext2fs_dent_walk_direct and _indirect
**
** Use the following flags: FS_FLAG_NAME_ALLOC, FS_FLAG_NAME_UNALLOC, 
** FS_FLAG_NAME_RECURSE
*/
void 
ext2fs_dent_walk(FS_INFO *fs, INUM_T inode, int flags, 
  FS_DENT_WALK_FN action, char *ptr) 
{
	FS_INODE 	*fs_inode;
	EXT2FS_INFO	*ext2fs = (EXT2FS_INFO *)fs;
	char		*dirbuf, *dirptr;
	OFF_T		size;

    if (inode < fs->first_inum || inode > fs->last_inum)
		error("invalid inode value: %i\n", inode);

	fs_inode = fs->inode_lookup(fs, inode);
	size = roundup (fs_inode->size, fs->block_size);

    /* make a copy of the directory contents that we can process */
    if (curdirptr != NULL)
        error ("ext2fs_dent_walk: Curdirptr is set! recursive?"); 
  
    curdirptr = dirbuf = mymalloc(size); 
    dirleft = size;
    
    fs->file_walk(fs, fs_inode, 0, 0, FS_FLAG_FILE_SLACK,
	  ext2fs_dent_action, "");

    curdirptr = NULL;
	dirptr = dirbuf;

	while (size > 0) {
		int len = (fs->block_size < size) ? fs->block_size : size;
		int retval;

		retval = ext2fs_dent_parse_block(ext2fs, dirptr, len, flags, 
		  action, ptr);

		/* if 0, then the action wants to stop */
		if (retval)
			size -= retval;
		else
			break;

		dirptr = (char *)((int)dirptr + len);
	}

	free (dirbuf);
	return;
}

