/*
** ntfs_dent
** The Sleuth Kit
**
** name layer support for the NTFS file system
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
*/
#include "fs_tools.h"
#include "fs_data.h"
#include "ntfs.h"

#include "mymalloc.h"
#include "error.h"


/* recursive path stuff */
static unsigned int depth = 0;  /* how deep in the directory tree are we */
#define MAX_DEPTH   64
static char *didx[MAX_DEPTH];  /* pointer in dirs string to where '/' is for
				** given depth */
#define DIR_STRSZ  2048 
static char dirs[DIR_STRSZ];    /* The current directory name string */


/* 
 * copy the index (directory) entry into the generic structure
 *
 * uses the global variables 'dirs' and 'depth'
 */
static void
ntfs_dent_copy(NTFS_INFO *ntfs, ntfs_idxentry *idxe, FS_DENT *fs_dent)
{
	ntfs_attr_fname *fname = (ntfs_attr_fname *)&idxe->stream;
	FS_INFO *fs = (FS_INFO *)&ntfs->fs_info;

	fs_dent->inode = getu48(fs, idxe->file_ref);

	/* Copy the name */
	fs_dent->namlen = fname->nlen;
	uni2ascii((char *)&fname->name, fname->nlen, 
	  fs_dent->name, fs_dent->maxnamlen);

	/* copy the path data */
	fs_dent->path = dirs;
	fs_dent->pathdepth = depth;

	/* Get the actual inode */
	if (fs_dent->fsi != NULL)
		fs_inode_free (fs_dent->fsi);

	fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);

	if (getu64(fs, fname->flags) & NTFS_FNAME_FLAGS_DIR)
		fs_dent->ent_type = FS_DENT_DIR;
	else
		fs_dent->ent_type = FS_DENT_REG;

	return;
}



/* 
 * This loads the contents of idxalloc into the global variables
 * curbuf and bufleft
 *
 * This function can not be called recursively due to its usage of
 * global variables 
 *
 */

static char *curbuf = NULL;
static int bufleft = 0;

static u_int8_t
idxalloc_action(FS_INFO *fs, DADDR_T addr, char *buf, int size, 
  int flags, char *ptr)
{
	int len;

	if (!curbuf)
		error("curbuf is NULL");

	len = ((size < bufleft) ? size : bufleft);

	memcpy(curbuf, buf, len);
	curbuf = (char *)((int)curbuf + len);
	bufleft -= len;

	return ((bufleft > 0) ? WALK_CONT : WALK_STOP);
}


/* This is a sanity check to see if the time is valid
 * it is divided by 100 to keep it in a 32-bit integer 
 */

static u_int8_t
is_time(u_int64_t t)
{
#define SEC_BTWN_1601_1970_DIV100 ((369*365 + 89) * 24 * 36)
#define SEC_BTWN_1601_2010_DIV100 (SEC_BTWN_1601_1970_DIV100 + (40*356 + 6) * 24 * 36)

	t /= 1000000000;	/* put the time in seconds div by additional 100 */

	if (!t)
		return 0;

	if (t < SEC_BTWN_1601_1970_DIV100)
		return 0;

	if (t > SEC_BTWN_1601_2010_DIV100)
		return 0;

	return 1;
}

/* 
 * Process a list of directory entries, starting at idxe with a length
 * of _size_ bytes.  _len_ is the length that is reported in the 
 * idxelist header.  in other words, everything after _len_ bytes is
 * considered unallocated area and therefore deleted content 
 *
 * The only flag that we care about is ALLOC (no UNALLOC entries exist
 * in the tree)
 */
static void
ntfs_dent_idxentry(NTFS_INFO *ntfs, ntfs_idxentry *idxe,
  int size, int len, int flags, FS_DENT_WALK_FN action, char *ptr)
{
	DADDR_T endaddr, endaddr_alloc;
	int myflags = 0;
	FS_DENT *fs_dent = fs_dent_alloc(NTFS_MAXNAMLEN);
	FS_INFO *fs = (FS_INFO *)&ntfs->fs_info;

	if (verbose)
		fprintf(logfp,
		  "ntfs_dent_idxentry: Processing entry: %lu  Size: %lu  Len: %lu\n",
		  (ULONG)idxe, (ULONG)size, (ULONG)len);

	/* where is the end of the buffer */
	endaddr = ((int)idxe + size);

	/* where is the end of the allocated data */
	endaddr_alloc = ((int)idxe + len);

	/* cycle through the index entries, based on provided size */
	while (((int)&(idxe->stream) + sizeof(ntfs_attr_fname)) < endaddr) {

		ntfs_attr_fname *fname = (ntfs_attr_fname *)&idxe->stream;


		if (verbose)
			fprintf(logfp,
			  "ntfs_dent_idxentry: New IdxEnt: %lu $FILE_NAME Entry: %lu  File Ref: %lu  IdxEnt Len: %lu  StrLen: %lu\n",
			  (ULONG)idxe, (ULONG)fname, (ULONG)getu48(fs, idxe->file_ref), 
			  (ULONG)getu16(fs, idxe->idxlen), (ULONG)getu16(fs, idxe->strlen));

		/* perform some sanity checks on index buffer head
		 * and advance by 4-bytes if invalid
		 */
		if ((getu48(fs, idxe->file_ref) > fs->last_inum) || 
		   (getu48(fs, idxe->file_ref) < fs->first_inum) ||
		   (getu16(fs, idxe->idxlen) <= getu16(fs, idxe->strlen) ) ||
		   (getu16(fs, idxe->idxlen) % 4) || 
		   (getu16(fs, idxe->idxlen) > size) )
		{
			idxe = (ntfs_idxentry *)((int)idxe + 4);
			continue;
		}

		/* do some sanity checks on the deleted entries
		 */
		if  ( (getu16(fs, idxe->strlen) == 0) ||
		  (((int)idxe + getu16(fs, idxe->idxlen)) > endaddr_alloc)) {

			/* name space checks */
			if ((fname->nspace != NTFS_FNAME_POSIX) &&
			  (fname->nspace != NTFS_FNAME_WIN32) &&
			  (fname->nspace != NTFS_FNAME_DOS) &&
			  (fname->nspace != NTFS_FNAME_WINDOS) ) {
				idxe = (ntfs_idxentry *)((int)idxe + 4);
				continue;
			}

			if (
			  ((int)getu64(fs, fname->alloc_fsize) < (int)getu64(fs, fname->real_fsize)) ||
			  (fname->nlen == 0) ||
			  (*(u_int8_t *)&fname->name == 0)) {

				idxe = (ntfs_idxentry *)((int)idxe + 4);
				continue;
			}

			if ((is_time(getu64(fs, fname->crtime)) == 0) ||
			  (is_time(getu64(fs, fname->atime)) == 0) ||
			  (is_time(getu64(fs, fname->mtime)) == 0) ) { 

				idxe = (ntfs_idxentry *)((int)idxe + 4);
				continue;

			}
		}
		
		/* For all fname entries, there will exist a DOS style 8.3 
		 * entry.  We don't process those because we already processed
		 * them before in their full version.  If the type is 
		 * full POSIX or WIN32 that does not satisfy DOS, then a 
		 * type NTFS_FNAME_DOS will exist.  If the name is WIN32,
		 * but already satisfies DOS, then a type NTFS_FNAME_WINDOS
		 * will exist 
		 *
		 * Note that we could be missing some info from deleted files
		 * if the windows version was deleted and the DOS wasn't...
		 */

		if (fname->nspace == NTFS_FNAME_DOS)  {
			if (verbose)
				fprintf(logfp,
				  "ntfs_dent_idxentry: Skipping because of name space: %d\n",
				  fname->nspace);

			goto incr_entry;
		}
		

		/* Copy it into the generic form */
		ntfs_dent_copy(ntfs, idxe, fs_dent);

		if (verbose)
			fprintf(logfp,
			  "ntfs_dent_idxentry: Deletion Check Details of %s: Str Len: %lu  Len to end after current: %lu\n",
			  fs_dent->name, 
			  (ULONG)getu16(fs, idxe->strlen), 
			  (ULONG)(endaddr_alloc - (int)idxe - getu16(fs, idxe->idxlen)));
			  
		/* 
		 * Check if this entry is deleted
		 *
		 * The final check is to see if the end of this entry is 
		 * within the space that the idxallocbuf claimed was valid
		 */
		if ((getu16(fs, idxe->strlen) == 0) || 
		  (((int)idxe + getu16(fs, idxe->idxlen)) > endaddr_alloc)) {

			/* we know deleted entries with an inode of 0 are not legit because
			 * that is the MFT value.  Free it so it does not confuse
			 * people with invalid data
			 */
			if (fs_dent->inode == 0) {
				fs_inode_free(fs_dent->fsi);
				fs_dent->fsi = NULL;
			}
			myflags = FS_FLAG_NAME_UNALLOC;
		}
		else
			myflags = FS_FLAG_NAME_ALLOC;


		if ((flags & myflags) == myflags) {
			if (WALK_STOP == action (fs, fs_dent, myflags, "")) { 
				return;
			}
		}

		/* Recurse if we need to */
		if ((myflags & FS_FLAG_NAME_ALLOC) &&
		   (flags & FS_FLAG_NAME_RECURSE) &&
		   (!ISDOT(fs_dent->name)) &&
		   ((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR) &&
		   (fs_dent->inode)) {

			if (depth < MAX_DEPTH) {
				didx[depth] = &dirs[strlen(dirs)];
				strncpy(didx[depth], fs_dent->name, DIR_STRSZ - strlen(dirs));
				strncat(dirs, "/", DIR_STRSZ);
			}
			depth++;

			ntfs_dent_walk(&(ntfs->fs_info), fs_dent->inode, flags,
			  action, ptr);

			depth--;
			if (depth < MAX_DEPTH)
				*didx[depth] = '\0';

		} /* end of recurse */

incr_entry:

		/* the theory here is that deleted entries have strlen == 0 and
		 * have been found to have idxlen == 16
		 *
		 * if the strlen is 0, then guess how much the indexlen was
		 * before it was deleted
		 */

		/* 16: size of idxentry before stream
		 * 66: size of fname before name
		 * 2*nlen: size of name (in unicode)
		 */
		if (getu16(fs, idxe->strlen) == 0)
			idxe = (ntfs_idxentry *)((((int)idxe + 16 + 66 + 2*fname->nlen + 3)/4)*4);
		else
			idxe = (ntfs_idxentry *)((int)idxe + getu16(fs, idxe->idxlen));

	} /* end of loop of index entries */

	fs_dent_free(fs_dent);

	return;

}




/*
 * remove the update sequence values that are changed in the last two 
 * bytes of each sector 
 *
 */
static void
ntfs_fix_idxrec(NTFS_INFO *ntfs, ntfs_idxrec *idxrec, u_int32_t len)
{
	int i;
	u_int16_t	orig_seq;
	FS_INFO		*fs = (FS_INFO *)&ntfs->fs_info;
	ntfs_upd	*upd;

	if (verbose)
		fprintf(logfp,
		  "ntfs_fix_idxrec: Fixing idxrec: %lu  Len: %lu\n",
		  (ULONG)idxrec, (ULONG)len);

	/* sanity check so we don't run over in the next loop */
	if ((getu16(fs, idxrec->upd_cnt) - 1) * ntfs->ssize_b > len)
		error ("More Update Sequence Entries than idx record size");

	/* Apply the update sequence structure template */
	upd = (ntfs_upd *)((int)idxrec + getu16(fs, idxrec->upd_off));
   
	/* Get the sequence value that each 16-bit value should be */
	orig_seq = getu16(fs, upd->upd_val);

	/* cycle through each sector */
	for (i = 1; i < getu16(fs, idxrec->upd_cnt); i++) {

		/* The offset into the buffer of the value to analyze */
		int offset = i * ntfs->ssize_b - 2;
		u_int8_t *new, *old;

		/* get the current sequence value */
		u_int16_t cur_seq = getu16(fs, (int)idxrec + offset);

		if (cur_seq != orig_seq) {
			/* get the replacement value */
		  	u_int16_t cur_repl = getu16(fs, &upd->upd_seq + (i-1) * 2);

			error ("Incorrect update sequence value in index buffer\nUpdate Value: 0x%x Actual Value: 0x%x Replacement Value: 0x%x\nThis is typically because of a corrupted entry",
			  orig_seq, cur_seq, cur_repl);
		}

		new = &upd->upd_seq + (i-1) * 2;
		old = (u_int8_t *)(int)idxrec + offset;

		if (verbose)
			fprintf(logfp,
			  "ntfs_fix_idxrec: upd_seq %i   Replacing: %.4x   With: %.4x\n",
			  i, getu16(fs, old), getu16(fs, new));

		*old++ = *new++;	
		*old = *new;	
	}

	return;
}





/* 
 * This function looks up the inode and processes its tree
 *
 */
void
ntfs_dent_walk(FS_INFO *fs, INUM_T inum, int flags,
  FS_DENT_WALK_FN action, char *ptr)
{
	NTFS_INFO 	*ntfs = (NTFS_INFO *)fs;
	FS_INODE 	*fs_inode;
	FS_DATA 	*fs_data_root, *fs_data_alloc;
	char 		*idxalloc;
	ntfs_idxentry 	*idxe;
	ntfs_idxroot 	*idxroot;
	ntfs_idxelist 	*idxelist;
	ntfs_idxrec 	*idxrec_p, *idxrec;
	int 		off, idxalloc_len;

	/* sanity check */
	if (inum < fs->first_inum || inum > fs->last_inum)
		error("invalid inode value: %i\n", inum);

	if (verbose)
		fprintf(logfp, "ntfs_dent_walk: Processing directory %lu\n", 
			(ULONG)inum);

	/* Get the inode and verify it has attributes */
	fs_inode = fs->inode_lookup(fs, inum);
	if (!fs_inode->attr)
		error("Error: Directory MFT has no attributes");


	/* 
	 * NTFS does not have "." and ".." entries in the index trees
	 * (except for a "." entry in the root directory)
	 * 
	 * So, we'll make 'em up by making a FS_DENT structure for
	 * a '.' and '..' entry and call the action
	 */
	if ((inum != fs->root_inum) && (flags & FS_FLAG_NAME_ALLOC)) {
		FS_DENT *fs_dent = fs_dent_alloc(16);
		FS_NAME *fs_name;
		int myflags = FS_FLAG_NAME_ALLOC;

		if (verbose)
			fprintf (logfp, "ntfs_dent_walk: Creating . and .. entries\n");

		/* 
		 * "." 
		 */
		fs_dent->inode = inum; 
		fs_dent->namlen = 1;
		strcpy(fs_dent->name, ".");

		/* copy the path data */
		fs_dent->path = dirs;
		fs_dent->pathdepth = depth;

		/* this is probably a waste, but just in case the action mucks
		 * with it ...
		 */
		fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);
		fs_dent->ent_type = FS_DENT_DIR;

		if (WALK_STOP == action (fs, fs_dent, myflags, "")) { 
			fs_dent_free(fs_dent);
			fs_inode_free(fs_inode);
			return;
		}



		/*
		 * ".."
		 */
		fs_dent->namlen = 2;
		strcpy(fs_dent->name, "..");
		fs_dent->ent_type = FS_DENT_DIR;

		/* The fs_name structure holds the parent inode value, so we 
		 * just cycle using those
		 */
		for (fs_name = fs_inode->name; fs_name != NULL; 
		  fs_name = fs_name->next) {
			if (fs_dent->fsi) {
				fs_inode_free(fs_dent->fsi);
				fs_dent->fsi = NULL;
			}
			
			fs_dent->inode = fs_name->par_inode;
			fs_dent->fsi = fs->inode_lookup(fs, fs_dent->inode);
			if (WALK_STOP == action (fs, fs_dent, myflags, "")) { 
				fs_dent_free(fs_dent);
				fs_inode_free (fs_inode);
				return;
			}
			
		}

		fs_dent_free(fs_dent);
		fs_dent = NULL;
	 }


	/* 
	 * Read & process the Index Root Attribute 
	 */
	fs_data_root = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_IDXROOT);
	if (!fs_data_root)
		error ("$IDX_ROOT not found in MFT %d", inum);

	if (fs_data_root->flags & FS_DATA_NONRES)
		error ("$IDX_ROOT is not resident - it should be");

	idxroot = (ntfs_idxroot *)fs_data_root->buf;

	/* Verify that the attribute type is $FILE_NAME */
	if (getu32(fs, idxroot->type) == 0)
		return;
	else if (getu32(fs, idxroot->type) != NTFS_ATYPE_FNAME)
		error ("ERROR: Directory index is sorted by type: %d.\nOnly $FNAME is currently supported", getu32(fs, idxroot->type));

	/* Get the header of the index entry list */
	idxelist = &idxroot->list;

	/* Get the offset to the start of the index entry list */
	idxe = (ntfs_idxentry *)((int)idxelist +
		  getu32(fs, idxelist->begin_off));

	/* Process $IDX_ROOT  */
	ntfs_dent_idxentry (ntfs, idxe, 
	  getu32(fs, idxelist->buf_off) - getu32(fs, idxelist->begin_off),
	  getu32(fs, idxelist->end_off) - getu32(fs, idxelist->begin_off), 
	  flags, action, ptr);

	/* 
	 * get the index allocation attribute if it exists (it doesn't for 
	 * small directories 
	 */
	fs_data_alloc = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_IDXALLOC);


	/* if we don't have an index alloc then return, we have processed
	 * all of the entries 
	 */
	if (!fs_data_alloc) {
		if (getu32(fs, idxelist->flags) & NTFS_IDXELIST_CHILD)
			error("Error: $IDX_ROOT says there should be children, but there isn't");

		return;
	}


	if (fs_data_alloc->flags & FS_DATA_RES) 
		error ("$IDX_ALLOC is Resident - it shouldn't be");

	/* 
	 * Copy the index allocation run into a big buffer
	 */
	if (curbuf != NULL) 
		error ("global idxalloc buffer is not NULL - recursive?");
	

	bufleft = idxalloc_len = (int)fs_data_alloc->runlen;
	curbuf = idxalloc = mymalloc (bufleft);

	if (verbose)
		fprintf (logfp, "ntfs_dent_walk: Copying $IDX_ALLOC into buffer\n");

	ntfs_data_walk(ntfs, fs_data_alloc,
	   FS_FLAG_FILE_SLACK, idxalloc_action, "index alloc");

	if (bufleft > 0)
		error ("ntfs_dent_walk: Buffer not filled when copying $IDX_ALLOC (%d)",
		  bufleft);

	/* reset the global variable */
	curbuf = NULL;


	/*
	 * The idxalloc is a big buffer that contains one or more
	 * idx buffer structures.  Each idxrec is a node in the B-Tree.  
	 * We do not process the tree as a tree because then we could
	 * not find the deleted file names.
	 *
	 * Therefore, we scan the big buffer looking for the index record
	 * structures.  We save a pointer to the known beginning (idxrec_p).
	 * Then we scan for the beginning of the next one (idxrec) and process
	 * everything in the middle as an ntfs_idxrec.  We can't use the
	 * size given because then we wouldn't see the deleted names
	 */

	/* Set the previous pointer to NULL */
	idxrec_p = idxrec = NULL;

	/* Loop by cluster size */
	for (off = 0; off < idxalloc_len; off += ntfs->csize_b) {
		int list_len, rec_len;

		idxrec = (ntfs_idxrec *)&idxalloc[off];

		if (verbose)
			fprintf (logfp, 
			  "ntfs_dent_walk: Index Buffer Offset: %d  Magic: %x\n",
			  off, getu32(fs, idxrec->magic));

		/* Is this the begining of an index record? */
		if (getu32(fs, idxrec->magic) != NTFS_IDXREC_MAGIC) 
			continue;


		/* idxrec_p is only NULL for the first time 
		 * Set it and start again to find the next one */
		if (idxrec_p == NULL) {
			idxrec_p = idxrec;
			continue;
		}

		/* Process the previous structure */

		/* idxrec points to the next idxrec structure, idxrec_p
		 * points to the one we are going to process
		 */
		rec_len = ((int)idxrec - (int)idxrec_p);

		if (verbose)
			fprintf (logfp, 
			  "ntfs_dent_walk: Processing previous index record (len: %lu)\n",
			  (ULONG)rec_len);

		/* remove the update sequence in the index record */
		ntfs_fix_idxrec(ntfs, idxrec_p, rec_len);

		/* Locate the start of the index entry list */
		idxelist = &idxrec_p->list;
		idxe = (ntfs_idxentry *)((int)idxelist +
		  getu32(fs, idxelist->begin_off));

		/* the length from the start of the next record to where our
		 * list starts.
		 * This should be the same as buf_off in idxelist, but we don't
		 * trust it.
		 */
		list_len = (int)idxrec - (int)idxe;

		/* process the list of index entries */
		ntfs_dent_idxentry (ntfs, idxe, list_len,
		  getu32(fs, idxelist->end_off) - getu32(fs, idxelist->begin_off),
		  flags, action, ptr);

		/* reset the pointer to the next record */
		idxrec_p = idxrec;

	} /* end of cluster loop */
 

	/* Process the final record */
	if (idxrec_p) {
		int list_len, rec_len;

		/* Length from end of attribute to start of this */
		rec_len = idxalloc_len - ((int)idxrec_p - (int)idxalloc);

		if (verbose)
			fprintf (logfp, 
			  "ntfs_dent_walk: Processing final index record (len: %lu)\n",
			  (ULONG)rec_len);

		/* remove the update sequence */
		ntfs_fix_idxrec(ntfs, idxrec_p, rec_len);

		idxelist = &idxrec_p->list;
		idxe = (ntfs_idxentry *)((int)idxelist + 
		  getu32(fs, idxelist->begin_off));

		/* This is the length of the idx entries */
		list_len = ((int)idxalloc + idxalloc_len) - (int)idxe;

		/* process the list of index entries */
		ntfs_dent_idxentry (ntfs, idxe, list_len, 
		  getu32(fs, idxelist->end_off) - getu32(fs, idxelist->begin_off),
		  flags, action, ptr);
	}

	fs_inode_free (fs_inode);
	free(idxalloc);

	return;

} /* end of dent_walk */




/****************************************************************************
 * FIND_FILE ROUTINES
 *
 */


/* 
 * Looks up the parent inode described in fs_name.  
 * myflags are the flags from the original inode lookup
 *
 * fs_dent was filled in by ntfs_find_file and will get the final path
 * added to it before action is called
 */
static void
ntfs_find_file_rec (FS_INFO *fs, FS_DENT *fs_dent, FS_NAME *fs_name, 
  int myflags, int flags, FS_DENT_WALK_FN action, char *ptr)
{
	FS_INODE *fs_inode_par;
	FS_NAME *fs_name_par;
	u_int8_t decrem = 0;
	int len = 0, i;
	char *begin = NULL;

    if (fs_name->par_inode < fs->first_inum || 
	  fs_name->par_inode > fs->last_inum)
		error("invalid inode value: %i\n", fs_name->par_inode);

    fs_inode_par = fs->inode_lookup(fs, fs_name->par_inode);

	/* 
	 * Orphan File
	 * This occurs when the file is deleted and either:
	 * - The parent is no longer a directory 
	 * - The sequence number of the parent is no longer correct
	 */
	if (((fs_inode_par->mode & FS_INODE_FMT) != FS_INODE_DIR) ||
	  (fs_inode_par->seq != fs_name->par_seq)) {
		char *str = ORPHAN_STR; 
		len = strlen(str);

		/* @@@ There should be a sanity check here to verify that the 
		 * previous name was unallocated ... but how do I get it again?
		 */

		if ((((int)didx[depth-1] - len) >= (int)&dirs[0] ) &&
		  (depth < MAX_DEPTH)) {
			begin = didx[depth] = (char *)((int)didx[depth-1] - len);

			depth++;
			decrem = 1;

			for (i = 0; i < len; i++) 
				begin[i] = str[i];
		}

		fs_dent->path = begin;
		fs_dent->pathdepth = depth;
		action (fs, fs_dent, myflags, ptr);

		if (decrem)
			depth--;

		fs_inode_free(fs_inode_par);
		return;
	}

	for (fs_name_par = fs_inode_par->name; fs_name_par != NULL; 
	  fs_name_par = fs_name_par->next) {

		len = strlen (fs_name_par->name);	

		/* do some length checks on the dir structure 
		 * if we can't fit it then forget about it */
		if ((((int)didx[depth-1] - len - 1) >= (int)&dirs[0] ) &&
		  (depth < MAX_DEPTH)) {
			begin = didx[depth] = (char *)((int)didx[depth-1] - len - 1);

			depth++;
			decrem = 1;

			*begin = '/';
			for (i = 0; i < len; i++) 
				begin[i+1] = fs_name_par->name[i];
		}
		else {
			begin = didx[depth];
			decrem = 0;
		}

	
		/* if we are at the root, then fill out the rest of fs_dent with
		 * the full path and call the action 
		 */
		if (fs_name_par->par_inode == NTFS_ROOTINO) {
			/* increase the path by one so that we do not pass the '/'
			 * if we do then the printed result will have '//' at 
			 * the beginning
			 */
			fs_dent->path = (char *)(int)begin + 1;
			fs_dent->pathdepth = depth;
			action (fs, fs_dent, myflags, ptr);
		}

		/* otherwise, recurse some more */
		else {
			ntfs_find_file_rec(fs, fs_dent, fs_name_par, myflags, flags, 
			  action, ptr);
		}

		/* if we incremented before, then decrement the depth now */
		if (decrem)
			depth--;
	}
	fs_inode_free (fs_inode_par);
}

/* 
 * this is a much faster way of doing it in NTFS 
 *
 * the inode that is passed in this case is the one to find the name
 * for
 *
 * This can not be called with dent_walk because the path
 * structure will get messed up!
 */

void
ntfs_find_file (FS_INFO *fs, INUM_T inode_toid, u_int32_t type_toid, 
  u_int32_t id_toid, int flags, FS_DENT_WALK_FN action, char *ptr)
{

	FS_INODE *fs_inode;
	FS_NAME *fs_name;
	FS_DENT *fs_dent = fs_dent_alloc(NTFS_MAXNAMLEN);
	int myflags;
	NTFS_INFO *ntfs = (NTFS_INFO *)fs;
	char *attr = NULL;

	/* sanity check */
	if (inode_toid < fs->first_inum || inode_toid > fs->last_inum)
		error("invalid inode value: %i\n", inode_toid);

	/* in this function, we use the dirs array in the opposite order.
	 * we set the end of it to NULL and then prepend the
	 * directories to it
	 *
	 * didx[depth] will point to where the current level started their
	 * dir name
	 */
	dirs[DIR_STRSZ - 2] = '/';    
	dirs[DIR_STRSZ - 1] = '\0';    
	didx[0] = &dirs[DIR_STRSZ - 2];
	depth = 1;


	/* lookup the inode and get its allocation status */
	fs_dent->inode = inode_toid;
	fs_dent->fsi = fs_inode = fs->inode_lookup(fs, inode_toid);
	myflags = ((getu16(fs, ntfs->mft->flags) & NTFS_MFT_INUSE) ?
		  FS_FLAG_NAME_ALLOC : FS_FLAG_NAME_UNALLOC);

	/* Get the name for the attribute - if specified */
	if (type_toid != 0) {
		FS_DATA *fs_data = fs_data_lookup(fs_inode->attr, type_toid, id_toid);
		if (!fs_data) {
			error ("Type %d Id %d not found in MFT %d", type_toid, id_toid,
			  inode_toid);
		}

		/* only add the attribute name if it is the non-default data stream */
		if (strcmp (fs_data->name, "$Data") != 0)
			attr = fs_data->name;
	}


	/* loop through all the names it may have */
	for (fs_name = fs_inode->name; fs_name != NULL; fs_name = fs_name->next) {

		/* Append on the attribute name, if it exists */
		if (attr != NULL) {
			snprintf(fs_dent->name, fs_dent->maxnamlen, "%s:%s", 
			  fs_name->name, attr);
		}
		else {
			strncpy(fs_dent->name, fs_name->name, fs_dent->maxnamlen);
		}
		fs_dent->namlen = strlen (fs_dent->name);

		/* if this is in the root directory, then call back */
		if (fs_name->par_inode == NTFS_ROOTINO) {
			fs_dent->path = didx[0];
			fs_dent->pathdepth = depth;
			action (fs, fs_dent, myflags, ptr);
		}
		/* call the recursive function on the parent */
		else {
			ntfs_find_file_rec(fs, fs_dent, fs_name, myflags, flags, 
			  action, ptr);
		}

	} /* end of name loop */

	fs_dent_free(fs_dent);
	
	return;
}
