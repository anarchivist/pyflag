/*
** fatfs_dent
** The Sleuth Kit 
**
** Human interface Layer support for the FAT file system
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
*/

#include "fs_tools.h"
#include "fatfs.h"
#include "mymalloc.h"
#include "error.h"

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

/* Recursive path stuff */
#define DIR_STRSZ   2048
static char g_dirs[DIR_STRSZ];    /* The current directory name string */

#define MAX_DEPTH   64
static char *g_didx[MAX_DEPTH];  /* pointer in g_dirs string to where '/' is for
                        ** given depth */
static unsigned int g_depth = 0;  /* how deep in the directory tree are we */
static char lfn[1024];

/* as FAT does not use inode numbers, we are making them up.  This causes
 * minor problems with the . and .. entries.  These global variables help
 * us out with that
 */
static u_int32_t	g_curdir_inode = 0;	/* the . inode */
static u_int32_t	g_pardir_inode = 0;	/* the .. inode */
static DADDR_T		g_pardir_clust = 0;		/* the first cluster that .. uses */


/* when set to 1, save data such as parent inodes and directory paths
 * in the global variables.  When set to 0 do not.  It is set to 0
 * when we have to do a search for the inode of '..' and we are doing
 * a dent_walk within a dent_walk.  
 *
 * Yes, I know this is a poor design 
 */
static u_int8_t		g_save_state = 1;		



/* Set to 1 when we are recursing down a deleted directory.  This will
 * supress the errors that may occur from invalid data
 */
static u_int8_t		g_recdel = 0;


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
 * We handle this by copying the LFN values into the FATFS_INFO structure
 * and then when we get the 8.3 entry the long name is copied in.  Therefore,
 * FATFS_INFO keeps state between calls to this function.
 *
 *
 * Ideally, we should print out the partial lfn when we find one with a
 * new checksum, but that does not work because this is supposed to return
 * only one entry and that case may cause two entries to be returned.
 */
static void 
fatfs_dent_copy(FATFS_INFO *fatfs, char *fatfs_dent, FS_DENT *fs_dent, 
   INUM_T inum) 
{
	FS_INFO *fs = &(fatfs->fs_info);
	int i;
	
	fatfs_dentry 		*dir = (fatfs_dentry *)fatfs_dent;
	fatfs_dentry_lfn 	*dirl = (fatfs_dentry_lfn *)fatfs_dent;

	fs_dent->inode = inum;
	fs_dent->reclen = fs_dent->nextLink = sizeof(fatfs_dentry);

	/* Name */
	if ((dir->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
		/* Store the name in FATFS until we get the 8.3 name */

		/* Is this a new sequence?  The checksum is the same for all entries
		 * in the same sequence 
		 */

		if (dirl->chksum != fatfs->lfn_chk) { 
			fatfs->lfn_seq = dirl->seq;
			fatfs->lfn_chk = dirl->chksum;
			fatfs->lfn_len = 0;
		}

		/* we are only going to support ASCII - not full UNICODE */	
		for (i = 2; i >=0; i-=2) {
			if ((dirl->part3[i] != 0) && (dirl->part3[i] != 0xff)) {
				if (fatfs->lfn_len < FATFS_MAXNAMLEN)
					fatfs->lfn[fatfs->lfn_len++] = dirl->part3[i];
			}
		}	
		for (i = 10; i >= 0 ; i-=2) {
			if ((dirl->part2[i] != 0) && (dirl->part2[i] != 0xff)) {
				if (fatfs->lfn_len < FATFS_MAXNAMLEN)
					fatfs->lfn[fatfs->lfn_len++] = dirl->part2[i];
			}
		}
		for (i = 8; i >= 0; i-=2) {
			if ((dirl->part1[i] != 0) && (dirl->part1[i] != 0xff)) {
				if (fatfs->lfn_len < FATFS_MAXNAMLEN)
					fatfs->lfn[fatfs->lfn_len++] = dirl->part1[i];
			}
		}
	}
	/* Special case for volume label, where name does not have an
	 * extension and we add a note at the end that it is a label */
	else if ((dir->attrib & FATFS_ATTR_VOLUME) == FATFS_ATTR_VOLUME) {
		fs_dent->namlen = 0;
		for (i = 0 ; i < 8; i++) {
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
			strncat (fs_dent->name, volstr, FATFS_MAXNAMLEN - fs_dent->namlen);
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
		if (fatfs->lfn_len != 0) {
			for (i = 0; i < fatfs->lfn_len; i++) 
				fs_dent->name[fs_dent->namlen++] = 
				  fatfs->lfn[fatfs->lfn_len-1-i]; 

			/* we will have the short name appended as (xxxxxxx.xxx) */
			//if (fs_dent->namlen + 2 < FATFS_MAXNAMLEN) {
			//	fs_dent->name[fs_dent->namlen++] = ' ';	
			//	fs_dent->name[fs_dent->namlen++] = '(';	
			//}

		} else {

		if (fs_dent->namlen + 12 < FATFS_MAXNAMLEN) {
			/* copy in the short name, skipping spaces and putting in the . */
			for (i = 0 ; i < 8; i++) {
				if ((dir->name[i] != 0) && (dir->name[i] != 0xff) &&
				  (dir->name[i] != 0x20)) {

					if ((i == 0) && (dir->name[0] == FATFS_SLOT_DELETED))
						fs_dent->name[fs_dent->namlen++] = '_';
        			else if ((dir->lowercase & FATFS_CASE_LOWER_BASE) &&
				  	  (dir->name[i] >= 'A') && (dir->name[i] <= 'Z'))
						  fs_dent->name[fs_dent->namlen++] = dir->name[i] + 32;
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
						  fs_dent->name[fs_dent->namlen++] = dir->ext[i] + 32;
					else
						fs_dent->name[fs_dent->namlen++] = dir->ext[i];
				}
			}
			fs_dent->name[fs_dent->namlen] = '\0';	
		}
		}

		/* If we put the LFN and the short in () then add ) */
		if (fatfs->lfn_len != 0) {
		//	if (fs_dent->namlen + 1 < FATFS_MAXNAMLEN) 
		//		fs_dent->name[fs_dent->namlen++] = ')';	
			fs_dent->name[fs_dent->namlen] = '\0';	

			/* reset the stored length */
			fatfs->lfn_len = 0;
		}
	}


	/* append the path data */
	fs_dent->path = g_dirs;
	fs_dent->pathdepth = g_depth;


	/* file type: FAT only knows DIR and FILE */
	if ((dir->attrib & FATFS_ATTR_DIRECTORY) == FATFS_ATTR_DIRECTORY)
		fs_dent->ent_type = FS_DENT_DIR;
	else
		fs_dent->ent_type = FS_DENT_REG;

	if (fs_dent->fsi) {
		free(fs_dent->fsi);
		fs_dent->fsi = NULL;
	}

	/* Get inode */
	if ((fs != NULL) && (inum))  
		fs_dent->fsi = fs->inode_lookup(fs, inum);

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
 * g_save_state should be 0 when this is running
 */
static u_int8_t
find_parent_act(FS_INFO *fs, FS_DENT *fsd, int flags, char *ptr)
{
	/* we found the directory entry that has allocated the cluster 
	 * we are looking for */
	if (fsd->fsi->direct_addr[0] == g_pardir_clust) {
		g_pardir_inode = fsd->inode;
		return WALK_STOP;
	}
	return WALK_CONT;
}

/*
 * this function will find the parent inode of a given directory
 * as specified in fs_dent. It works by walking the directory tree
 * starting at the root.  
 *
 * Set g_save_state to 0, so that no global variables are overwritten.  I do
 * not like the design of this, but this is much more efficient than
 * an inode walk
 *
 * return the inode
 */
static u_int32_t
find_parent (FATFS_INFO *fatfs, FS_DENT *fs_dent) 
{
	FS_INFO *fs = (FS_INFO *)&fatfs->fs_info;	

	if (g_save_state == 0)
		error ("save_state is already 0, recursion?");


	/* set the global value that the action function will use */
	g_pardir_inode = 0;
	g_pardir_clust = fs_dent->fsi->direct_addr[0];


	/* is the root directory being called for? 
	 * we won't find it by searching as it does not exist
	 */
	if (fs->ftype == MS32_FAT) {
		OFF_T clust = FATFS_SECT_2_CLUST (fatfs, fatfs->rootsect);

		if ((clust == g_pardir_clust) || (g_pardir_clust == 0)) {
			g_pardir_inode = fs->root_inum;
			return g_pardir_inode;
		}
	}	
	else {
		if ((g_pardir_clust == 1) || (g_pardir_clust == 0)) {
			g_pardir_inode = fs->root_inum;
			return g_pardir_inode;
		}
	}

	if ((fs_dent->fsi->mode & FS_INODE_FMT) != FS_INODE_DIR) {
		remark ("find_parent called on a non-directory");
		return 2;
	}


	/* walk the inodes - looking for an inode that has allocated the
	 * same first sector 
	 */
	g_save_state = 0;
	fatfs_dent_walk(fs, fs->root_inum, 
	  FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_RECURSE,
	  find_parent_act, "find_parent");
	g_save_state = 1;

	/* if we didn't find anything then 0 will be returned */
	return g_pardir_inode;
}

/* 
**
** Read contents of directory sector (in buf) with length len and
** original address of addr.  
**
** The length read is returned or 0 if the action wanted to stop.  
**
** flags: FS_FLAG_NAME_ALLOC, FS_FLAG_NAME_UNALLOC, FS_FLAG_NAME_RECURSE
*/
static int 
fatfs_dent_parse_block(FATFS_INFO *fatfs, char *buf, int len, DADDR_T addr, 
  int flags, FS_DENT_WALK_FN action, char *ptr) 
{
	int 		idx;
	u_int32_t 	inode, ibase;
	fatfs_dentry	*dep;
	FS_DENT 	*fs_dent;
	FS_INFO 	*fs = (FS_INFO *)&fatfs->fs_info;
	int			sectalloc;

	fs_dent = fs_dent_alloc(FATFS_MAXNAMLEN);

	dep = (fatfs_dentry *)buf;

	/* Get the base inode for this sector */
	ibase = FATFS_SECT_2_INODE(fatfs, addr);
	if (ibase > fs->last_inum)
		error("parse error: inode address is too large");

	sectalloc = is_sectalloc (fatfs, addr);

	/* cycle through the directory entries */
	for (idx = 0; idx < fatfs->dentry_cnt_se; idx++, dep++)  {

		int myflags = 0;

		/* is it a valid dentry? */
		if (0 == fatfs_isdentry(fatfs, dep))
			continue;

		inode = ibase + idx;

		/* Copy the entry
		 * if this is LFN, then all that will happen is that it will
		 * be copied into FATFS_INFO 
		 */
		fatfs_dent_copy(fatfs, (char *)dep, fs_dent, inode);


		/* If it is a long file name, then keep on going until the
		 * final small name is reached */
		if ((dep->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
			if (fatfs->lfn_len != 0) {
				int i;
				for (i = 0; i < fatfs->lfn_len; i++) 
					lfn[i] = fatfs->lfn[fatfs->lfn_len-1-i]; 
				lfn[i] = '\0';
			}
		continue;
		}

		/* Handle the . and .. entries specially
		 * The current inode 'address' they have is for the current
		 * slot in the cluster, but it needs to refer to the original
		 * slot 
		 */
		if (dep->name[0] == '.') {

			/* g_curdir_inode is always set and we can copy it in */
			if (dep->name[1] == ' ') 
				inode = fs_dent->inode = g_curdir_inode;

			/* g_pardir_inode is not always set, so we may have to search */
			else if (dep->name[1] == '.') {

				/* g_save_state is set to 0 when we are already looking
				 * for a parent */
				if ((!g_pardir_inode) && (g_save_state))
					g_pardir_inode = find_parent(fatfs, fs_dent);

				inode = fs_dent->inode = g_pardir_inode;

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
			myflags = (dep->name[0] == FATFS_SLOT_DELETED)?
			  FS_FLAG_NAME_UNALLOC : FS_FLAG_NAME_ALLOC;
		}
		else {
			myflags = FS_FLAG_NAME_UNALLOC;
		}

		if ((flags & myflags) == myflags) {
			if (WALK_STOP == action(fs, fs_dent, myflags, ptr)) {
				fs_dent_free(fs_dent);
				return 0;
			}
		}


		/* if we have a directory and need to recurse then do it */
		if (((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR) && 
		  (flags & FS_FLAG_NAME_RECURSE)  &&
		  (!ISDOT(fs_dent->name)) ) {

			u_int32_t back_p = 0;
			u_int8_t back_recdel = 0;


			/* we are going to append only the short name */
			if ((g_save_state) && (g_depth < MAX_DEPTH)) {
				char tmpname[13];
					
				if ((strlen(fs_dent->name) > 12) && 
				  (strrchr(fs_dent->name, '('))) {
					int i;
					char *ptr;

					ptr = strrchr (fs_dent->name, '(');
					ptr++;

					for (i = 0; i < 12 && ptr[i] != ')'; i++) 
						tmpname[i] = ptr[i];
				
					tmpname[i] = '\0';

				}
				else {
					strncpy (tmpname, fs_dent->name, 13);
				}
				if(lfn[0] != '\0') {
                    g_didx[g_depth] = &g_dirs[strlen(g_dirs)];
					strncpy(g_didx[g_depth], lfn, DIR_STRSZ - strlen(g_dirs));
					strncat(g_dirs, "/", DIR_STRSZ);
				}
				else {
					g_didx[g_depth] = &g_dirs[strlen(g_dirs)];
					strncpy(g_didx[g_depth], tmpname, DIR_STRSZ - strlen(g_dirs));
					strncat(g_dirs, "/", DIR_STRSZ);
				}
			}

			/* save the .. inode value */
			if (g_save_state) {
				back_p = g_pardir_inode;
				g_pardir_inode = g_curdir_inode;
				g_depth++;
			}

			/* This will prevent errors from being generated from the invalid
			 * deleted files.  save the current setting and set it to del */
			if (myflags & FS_FLAG_NAME_ALLOC)  {
				back_recdel = g_recdel;
				g_recdel = 1;
			}

			fatfs_dent_walk(&(fatfs->fs_info), fs_dent->inode, 
			  flags, action, ptr);

			if (g_save_state) {
				g_depth--;
				g_curdir_inode = g_pardir_inode;
				g_pardir_inode = back_p; 
			}

			if ((g_save_state) && (g_depth < MAX_DEPTH))
				 *g_didx[g_depth] = '\0';

			/* Restore the recursion setting */
			if (myflags & FS_FLAG_NAME_ALLOC)  {
				g_recdel = back_recdel;
			}

		} /* end of recurse */

	} /* end for dentries */

	fs_dent_free(fs_dent);
	return len;

} /* end fatfs_dent_parse_block() */



/**************************************************************************
 *
 * dent_walk
 *
 *************************************************************************/

/* values used to copy the directory contents into a buffer */

/* ptr to the current location in a local buffer */
static char *g_curdirptr = NULL;		

/* number of bytes left in g_curdirptr */
static int g_dirleft = 0;				


/* ptr to a local buffer for the stack of sector addresses */
static DADDR_T *g_curaddrbuf = NULL;

/* num of entries allocated to g_curaddrbuf */
static int g_addrsize = 0;

/* The current index in the g_curaddrbuf stack */
static int g_addridx = 0;


/* 
 * file_walk callback action to load directory contents 
 */
static u_int8_t 
fatfs_dent_action(FS_INFO *fs, DADDR_T addr, char *buf, int size,
  int flags, char *ptr)
{       
	/* how much of the buffer are we copying */
    int len = (g_dirleft < size) ? g_dirleft : size;

	/* Copy the sector into a buffer and increment the pointers */
    memcpy (g_curdirptr, buf, len);
    g_curdirptr = (char *) ((int)g_curdirptr + len);
    g_dirleft -= len;

	/* fill in the stack of addresses of sectors 
	 *
	 * if we are at the last entry, then realloc more */
	if (g_addridx == g_addrsize) {
		g_addrsize += 512;
		g_curaddrbuf = (DADDR_T *)myrealloc ((char *)g_curaddrbuf, 
		  g_addrsize * sizeof(DADDR_T));
	}

	/* Add this sector to the stack */
	g_curaddrbuf[g_addridx++] = addr;

    if (g_dirleft)
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
fatfs_dent_walk(FS_INFO *fs, INUM_T inode, int flags, 
  FS_DENT_WALK_FN action, char *ptr) 
{
	OFF_T size;
	FS_INODE *fs_inode;
	FATFS_INFO	*fatfs = (FATFS_INFO *)fs;
	char *dirbuf, *dirptr;
	DADDR_T *addrbuf;
	int addrmax;
	int i;

	if ((inode < fs->first_inum) || (inode > fs->last_inum))
		error("invalid inode value: %i\n", inode);

	fs_inode = fs->inode_lookup(fs, inode);
	if (!fs_inode)
		error ("%lu is not a valid inode", (ULONG)inode);
		
	size = fs_inode->size;

	/* If we are saving state, save the current inode value ('.') */
	if (g_save_state)
		g_curdir_inode = inode;

	/* Allocate a buffer for the lfn support */
	if (fatfs->lfn == NULL) {
		fatfs->lfn = mymalloc(FATFS_MAXNAMLEN);
		fatfs->lfn_len = 0;
		fatfs->lfn_chk = 0;
		fatfs->lfn_seq = 0;
	}


	/* Make a copy of the directory contents.  This will use
	 * the file_walk functionality 
	 */


	/* Allocate a buffer for the directory contents */
    if (g_curdirptr != NULL)
        error ("fatfs_dent_walk: g_curdirptr is set! recursive?");

	dirbuf = mymalloc(size);

	/* Set the global variables that are used during the copy */
    g_curdirptr = dirbuf;
    g_dirleft = size;


	/* We are going to save the address of each sector in the directory
	 * in a stack - they are needed to determine the inode address */
	if (g_curaddrbuf != NULL)
		error ("fatfs_dent_walk: g_curaddrbuf is set! recursive?");

	g_addrsize = 512;
	addrbuf = (DADDR_T *)mymalloc(g_addrsize * sizeof(DADDR_T));

	/* Set the global variables that are used during the copy */
	g_addridx = 0;			
	g_curaddrbuf = addrbuf;	
  

	/* save the directory contents into dirbuf */
	if (g_recdel == 0) {
    	fs->file_walk(fs, fs_inode, 0, 0, FS_FLAG_FILE_SLACK,
		  fatfs_dent_action, "");

		if (g_dirleft > 0) {
			error ("fatfs_dent_walk: Entire directory was not loaded (%d left)",
			  g_dirleft);
		}
	} 
	else { 
    	fs->file_walk(fs, fs_inode, 0, 0, 
		  FS_FLAG_FILE_SLACK | FS_FLAG_FILE_RECOVER,
		  fatfs_dent_action, "");

		/* We did not copy the entire directory 
		 * If we are recursing on a deleted directory, then exit now.
		 * during recovery of a deleted file, the FAT code will only
		 * return content if it can recover the entire file
		 */
		if (g_dirleft > 0) {
			return;
		}
	}


	/* How many sector addresses do we have? */
	addrmax = g_addridx;

	/* Reset the local pointer because we could have done a realloc */
	addrbuf = g_curaddrbuf;

	/* Reset the global pointers */
    g_curdirptr = NULL;
 	g_curaddrbuf = NULL;

	/* cycle through the directory and parse the contents */
    dirptr = dirbuf;
	for (i = 0; size > 0; i++) {
        int len = (fatfs->ssize < size) ? fatfs->ssize : size;
		int retval;

		/* This should never happen because we wouldn't have been able
		 * to load the directory, but it never hurts ... */
		if (addrbuf[i] > fs->last_block)
			error ("fatfs_dent_walk: block too large");

		lfn[0] = '\0';
		retval = fatfs_dent_parse_block(fatfs, dirptr, len, addrbuf[i], flags,
          action, ptr);

		/* zero is returned when the action wanted to stop */
		if (retval)
			size -= retval;
		else
			break;

		if (len != retval) {
			if (g_recdel == 1)
				return;

			error ("fatfs_dent_parse: returned non-zero size: %lu %lu",
			  (ULONG)len, (ULONG)retval);
		}

        dirptr = (char *)((int)dirptr + len);
    }

	free (dirbuf);
	free(addrbuf);
}

