/*
** ntfs
** The Sleuth Kit 
**
** $Date: 2005/10/13 04:15:22 $
**
** Content and meta data layer support for the NTFS file system
**
** Brian Carrier [carrier@sleuthkit.org]
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
#include "fs_tools.h"
#include "fs_data.h"
#include "ntfs.h"
#include "fs_unicode.h"

#include <ctype.h>

/*
 * NOTES TO SELF:
 *
 * - multiple ".." entries may exist
 */

/* 
 * How are we to handle the META flag? Is the MFT $Data Attribute META?
 */


/* needs to be predefined for proc_attrseq */
static void
 ntfs_proc_attrlist(NTFS_INFO *, FS_INODE *, FS_DATA *);



/* mini-design note:
 * The MFT has entries for every file and dir in the fs.
 * The first entry ($MFT) is for the MFT itself and it is used to find
 * the location of the entire table because it can become fragmented.
 * Therefore, the $Data attribute of $MFT is saved in the NTFS_INFO
 * structure for easy access.  We also use the size of the MFT as
 * a way to calculate the maximum MFT entry number (last_inum).
 *
 * Ok, that is simple, but getting the full $Data attribute can be tough
 * because $MFT may not fit into one MFT entry (i.e. an attribute list). 
 * We need to process the attribute list attribute to find out which
 * other entries to process.  But, the attribute list attribute comes
 * before any $Data attribute (so it could refer to an MFT that has not
 * yet been 'defined').  Although, the $Data attribute seems to always 
 * exist and define at least the run for the entry in the attribute list.
 *
 * So, the way this is solved is that generic mft_lookup is used to get
 * any MFT entry, even $MFT.  If $MFT is not cached then we calculate 
 * the address of where to read based on mutliplication and guessing.  
 * When we are loading the $MFT, we set 'loading_the_MFT' to 1 so
 * that we can update things as we go along.  When we read $MFT we
 * read all the attributes and save info about the $Data one.  If
 * there is an attribute list, we will have the location of the
 * additional MFT in the cached $Data location, which will be 
 * updated as we process the attribute list.  After each MFT
 * entry that we process while loading the MFT, the 'final_inum'
 * value is updated to reflect what we can currently load so 
 * that the sanity checks still work.
 */


/**********************************************************************
 *
 *  MISC FUNCS
 *
 **********************************************************************/

/* convert the NT Time (UTC hundred nanoseconds from 1/1/1601)
 * to UNIX (UTC seconds from 1/1/1970)
 *
 * The basic calculation is to remove the nanoseconds and then
 * subtract the number of seconds between 1601 and 1970
 * i.e. TIME - DELTA
 *
 */
uint32_t
nt2unixtime(uint64_t ntdate)
{
// (369*365 + 89) * 24 * 3600 * 10000000
#define	NSEC_BTWN_1601_1970	(uint64_t)(116444736000000000ULL)

    ntdate -= (uint64_t) NSEC_BTWN_1601_1970;
    ntdate /= (uint64_t) 10000000;

    return (uint32_t) ntdate;
}



/**********************************************************************
 *
 * Lookup Functions
 *
 **********************************************************************/




/*
 * Lookup up a given MFT entry (mftnum) in the MFT and save it in its
 * raw format in *mft.
 *
 * NOTE: This will remove the update sequence integrity checks in the
 * structure
 */
static void
ntfs_dinode_lookup(NTFS_INFO * ntfs, ntfs_mft * mft, INUM_T mftnum)
{
    OFF_T mftaddr_b, mftaddr2_b, offset;
    unsigned int mftaddr_len = 0;
    int i;
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;
    FS_DATA_RUN *data_run;
    ntfs_upd *upd;
    uint16_t sig_seq;

    /* sanity checks */
    if (!mft)
	error("mft_lookup: null mft buffer");

    if (mftnum < fs->first_inum)
	error("inode number is too small (%" PRIuINUM ")", mftnum);
    if (mftnum > fs->last_inum)
	error("inode number is too large (%" PRIuINUM ")", mftnum);


    if (verbose)
	fprintf(stderr,
		"ntfs_dinode_lookup: Processing MFT %" PRIuINUM "\n",
		mftnum);

    /* If mft_data (the cached $Data attribute of $MFT) is not there yet, 
     * then we have not started to load $MFT yet.  In that case, we will
     * 'cheat' and calculate where it goes.  This should only be for
     * $MFT itself, in which case the calculation is easy
     */
    if (!ntfs->mft_data) {

	/* This is just a random check with the assumption being that
	 * we don't want to just do a guess calculation for a very large
	 * MFT entry
	 */
	if (mftnum > NTFS_LAST_DEFAULT_INO)
	    error
		("Error trying to load a high MFT entry when the MFT itself has not been loaded (%"
		 PRIuINUM ")", mftnum);

	mftaddr_b = ntfs->root_mft_addr + mftnum * ntfs->mft_rsize_b;
	mftaddr2_b = 0;
    }
    else {
	/* The MFT may not be in consecutive clusters, so we need to use its
	 * data attribute run list to find out what address to read
	 *
	 * This is why we cached it
	 */

	// will be set to the address of the MFT entry
	mftaddr_b = mftaddr2_b = 0;

	/* The byte offset within the $Data stream */
	offset = mftnum * ntfs->mft_rsize_b;

	/* NOTE: data_run values are in clusters 
	 *
	 * cycle through the runs in $Data and identify which
	 * has the MFT entry that we want
	 */
	for (data_run = ntfs->mft_data->run;
	     data_run != NULL; data_run = data_run->next) {

	    /* The length of this specific run */
	    OFF_T run_len = data_run->len * ntfs->csize_b;

	    /* Is our MFT entry is in this run somewhere ? */
	    if (offset < run_len) {

		if (verbose)
		    fprintf(stderr,
			    "ntfs_dinode_lookup: Found in offset: %"
			    PRIuDADDR "  size: %" PRIuDADDR " at offset: %"
			    PRIuOFF "\n", data_run->addr, data_run->len,
			    offset);

		/* special case where the MFT entry crosses
		 * a run (only happens when cluster size is 512-bytes
		 * and there are an odd number of clusters in the run)
		 */
		if (run_len < offset + ntfs->mft_rsize_b) {

		    if (verbose)
			fprintf(stderr,
				"ntfs_dinode_lookup: Entry crosses run border\n");

		    if (data_run->next == NULL)
			error
			    ("MFT entry crosses a cluster and there are no more clusters!");

		    /* Assign address where the remainder of the entry is */
		    mftaddr2_b = data_run->next->addr * ntfs->csize_b;

		    /* this should always be 512, but just in case */
		    mftaddr_len = run_len - offset;
		}

		/* Assign address of where the MFT entry starts */
		mftaddr_b = data_run->addr * ntfs->csize_b + offset;
		if (verbose)
		    fprintf(stderr,
			    "ntfs_dinode_lookup: Entry address at: %"
			    PRIuOFF "\n", mftaddr_b);
		break;
	    }

	    /* decrement the offset we are looking for */
	    offset -= run_len;
	}

	/* Did we find it? */
	if (!mftaddr_b)
	    error("Error finding MFT entry %" PRIuINUM " in $MFT", mftnum);
    }


    /* can we do just one read or do we need multiple? */
    if (mftaddr2_b) {
	/* read the first part into mft */
	if (fs_read_random(&ntfs->fs_info, (char *) mft,
			   mftaddr_len, mftaddr_b) != mftaddr_len) {
	    error
		("ntfs_dinode_lookup: Error reading MFT Entry (part 1) at %"
		 PRIuOFF ": %m", mftaddr_b);
	}

	/* read the second part into mft */
	if (fs_read_random
	    (&ntfs->fs_info, (char *) ((uintptr_t) mft + mftaddr_len),
	     ntfs->mft_rsize_b - mftaddr_len,
	     mftaddr2_b) != ntfs->mft_rsize_b - mftaddr_len) {
	    error
		("ntfs_dinode_lookup: Error reading MFT Entry (part 2) at %"
		 PRIuOFF ": %m", mftaddr2_b);
	}
    }
    else {
	/* read the raw entry into mft */
	if (fs_read_random(&ntfs->fs_info, (char *) mft,
			   ntfs->mft_rsize_b,
			   mftaddr_b) != ntfs->mft_rsize_b) {
	    error("ntfs_dinode_lookup: Error reading MFT Entry at %"
		  PRIuOFF ": %m", mftaddr_b);
	}
    }

    /* if we are saving into the NTFS_INFO structure, assign mnum too */
    if ((uintptr_t) mft == (uintptr_t) ntfs->mft)
	ntfs->mnum = mftnum;

    /* Sanity Check */
#if 0
    /* This is no longer applied because it caused too many problems
     * with images that had 0 and 1 etc. as values.  Testing shows that
     * even Windows XP doesn't care if entries have an invalid entry, so
     * this is no longer checked.  The update sequence check should find
     * corrupt entries
     * */
    if ((getu32(fs, mft->magic) != NTFS_MFT_MAGIC) &&
	(getu32(fs, mft->magic) != NTFS_MFT_MAGIC_BAAD) &&
	(getu32(fs, mft->magic) != NTFS_MFT_MAGIC_ZERO))
	error("entry %d has an invalid MFT magic: %x", mftnum,
	      getu32(fs, mft->magic));
#endif

    /* The MFT entries have error and integrity checks in them
     * called update sequences.  They must be checked and removed
     * so that later functions can process the data as normal. 
     * They are located in the last 2 bytes of each 512-byte sector
     *
     * We first verify that the the 2-byte value is a give value and
     * then replace it with what should be there
     */

    /* sanity check so we don't run over in the next loop */
    if ((getu16(fs, mft->upd_cnt) - 1) * ntfs->ssize_b > ntfs->mft_rsize_b)
	error("More Update Sequence Entries than MFT size");

    /* Apply the update sequence structure template */
    upd = (ntfs_upd *) ((uintptr_t) mft + getu16(fs, mft->upd_off));

    /* Get the sequence value that each 16-bit value should be */
    sig_seq = getu16(fs, upd->upd_val);

    /* cycle through each sector */
    for (i = 1; i < getu16(fs, mft->upd_cnt); i++) {
	uint8_t *new_val, *old_val;

	/* The offset into the buffer of the value to analyze */
	size_t offset = i * ntfs->ssize_b - 2;

	/* get the current sequence value */
	uint16_t cur_seq = getu16(fs, (uintptr_t) mft + offset);

	if (cur_seq != sig_seq) {
	    /* get the replacement value */
	    uint16_t cur_repl = getu16(fs, &upd->upd_seq + (i - 1) * 2);
	    error
		("Incorrect update sequence value in MFT entry\nSignature Value: 0x%"
		 PRIx16 " Actual Value: 0x%" PRIx16
		 " Replacement Value: 0x%" PRIx16
		 "\nThis is typically because of a corrupted entry",
		 sig_seq, cur_seq, cur_repl);
	}

	new_val = &upd->upd_seq + (i - 1) * 2;
	old_val = (uint8_t *) ((uintptr_t) mft + offset);

	if (verbose)
	    fprintf(stderr,
		    "ntfs_dinode_lookup: upd_seq %i   Replacing: %.4"
		    PRIx16 "   With: %.4" PRIx16 "\n", i, getu16(fs,
								 old_val),
		    getu16(fs, new_val));

	*old_val++ = *new_val++;
	*old_val = *new_val;
    }

    return;
}



/*
 * given a cluster, return the allocation status 
 */
static int
is_clust_alloc(NTFS_INFO * ntfs, DADDR_T addr)
{
    int bits_p_clust, b;
    DADDR_T base;
    bits_p_clust = 8 * ntfs->fs_info.block_size;

    /* While we are loading the MFT, assume that everything
     * is allocated.  This should only be needed when we are
     * dealing with an attribute list ... 
     */
    if (ntfs->loading_the_MFT == 1)
	return 1;
    else if (ntfs->bmap == NULL)
	error("Bitmap pointer is null: %" PRIuDADDR "\n", addr);

    /* Is the cluster too big? */
    if (addr > ntfs->fs_info.last_block)
	error("is_clust_alloc: cluster too large");

    /* identify the base cluster in the bitmap file */
    base = addr / bits_p_clust;
    b = addr % bits_p_clust;

    /* is this the same as in the cached buffer? */
    if (base != ntfs->bmap_buf_off) {
	DADDR_T c = base;
	FS_DATA_RUN *run;
	DADDR_T fsaddr = 0;


	/* get the file system address of the bitmap cluster */
	for (run = ntfs->bmap; run; run = run->next) {
	    if (run->len <= c) {
		c -= run->len;
	    }
	    else {
		fsaddr = run->addr + c;
		break;
	    }
	}

	if (fsaddr == 0)
	    error("is_clust_alloc: cluster not found in bitmap: %"
		  PRIuDADDR "", c);

	if (fsaddr > ntfs->fs_info.last_block)
	    error
		("is_clust_alloc: Cluster in bitmap too large for image: %"
		 PRIuDADDR, fsaddr);

	ntfs->bmap_buf_off = base;

	if (fs_read_block
	    (&ntfs->fs_info, ntfs->bmap_buf, ntfs->fs_info.block_size,
	     fsaddr)
	    != ntfs->fs_info.block_size) {
	    error("is_clust_alloc: Error reading bitmap at %" PRIuDADDR
		  ": %m", fsaddr);
	}
    }

    /* identify if the cluster is allocated or not */
    return (isset(ntfs->bmap_buf->data, b)) ? 1 : 0;
}



/**********************************************************************
 *
 *  FS_DATA functions
 *
 **********************************************************************/


/* 
 * turn a non-resident runlist into the generic fs_data_run
 * structure
 *
 * The return value is a list of FS_DATA_RUN entries of len
 * runlen bytes (only set if non-NULL)
 */
static FS_DATA_RUN *
ntfs_make_data_run(NTFS_INFO * ntfs, ntfs_runlist * runlist,
		   OFF_T * runlen)
{
    ntfs_runlist *run;
    FS_DATA_RUN *data_run, *data_run_head = NULL, *data_run_prev = NULL;
    unsigned int i, idx;
    DADDR_T prev_addr = 0;

    run = runlist;

    /* initialize of non-NULL */
    if (runlen)
	*runlen = 0;

    /* Cycle through each run in the runlist 
     * We go until we find an entry with no length
     * An entry with offset of 0 is for a sparse run
     */
    while (NTFS_RUNL_LENSZ(run) != 0) {
	int64_t offset = 0;

	/* allocate a new fs_data_run */
	data_run = fs_data_run_alloc();

	/* make the list, unless its the first pass & then we set the head */
	if (data_run_prev)
	    data_run_prev->next = data_run;
	else
	    data_run_head = data_run;
	data_run_prev = data_run;


	/* These fields are a variable number of bytes long
	 * these for loops are the equivalent of the getuX macros
	 */
	idx = 0;

	/* Get the length of this run */
	for (i = 0, data_run->len = 0; i < NTFS_RUNL_LENSZ(run); i++) {
	    data_run->len |= (run->buf[idx++] << (i * 8));
	    if (verbose)
		fprintf(stderr,
			"ntfs_make_data_run: Len idx: %i cur: %" PRIu8
			" (%" PRIx8 ") tot: %" PRIuDADDR " (%" PRIxDADDR
			")\n", i, run->buf[idx - 1], run->buf[idx - 1],
			data_run->len, data_run->len);
	}

	/* Update the length if we were passed a value */
	if (runlen)
	    *runlen += (data_run->len * ntfs->csize_b);


	/* Get the address of this run */
	for (i = 0, data_run->addr = 0; i < NTFS_RUNL_OFFSZ(run); i++) {
	    //data_run->addr |= (run->buf[idx++] << (i * 8));
	    offset |= (run->buf[idx++] << (i * 8));
	    if (verbose)
		fprintf(stderr,
			"ntfs_make_data_run: Off idx: %i cur: %" PRIu8
			" (%" PRIx8 ") tot: %" PRIuDADDR " (%" PRIxDADDR
			")\n", i, run->buf[idx - 1], run->buf[idx - 1],
			offset, offset);
	}

	/* offset value is signed so extend it to 64-bits */
	if ((int8_t) run->buf[idx - 1] < 0) {
	    for (; i < sizeof(offset); i++)
		offset |= (int64_t) ((int64_t) 0xff << (i * 8));
	}

	if (verbose)
	    fprintf(stderr,
		    "ntfs_make_data_run: Signed offset: %" PRIdDADDR
		    " Previous address: %" PRIdDADDR "\n", offset,
		    prev_addr);


	/* The NT 4.0 version of NTFS uses an offset of -1 to represent
	 * a hole, so add the sparse flag and make it look like the 2K
	 * version with a offset of 0
	 *
	 * A user reported an issue where the $Bad file started with
	 * its offset as -1 and it was not NT (maybe a conversion)
	 * Change the check now to not limit to NT, but make sure
	 * that it is the first run
	 */
	if (((offset == -1) && (prev_addr == 0)) ||
	    ((offset == -1) && (ntfs->ver == NTFS_VINFO_NT))) {
	    data_run->flags |= FS_DATA_SPARSE;
	    data_run->addr = 0;
	    if (verbose)
		fprintf(stderr, "ntfs_make_data_run: Sparse Run\n");
	}

	/* A Sparse file has a run with an offset of 0
	 * there is a special case though of the BOOT MFT entry which
	 * is the super block and has a legit offset of 0.
	 *
	 * The value given is a delta of the previous offset, so add 
	 * them for non-sparse files
	 *
	 * For sparse files the next run will have its offset relative 
	 * to the current "prev_addr" so skip that code
	 */
	else if ((offset) || (ntfs->mnum == NTFS_MFT_BOOT)) {
	    data_run->addr = prev_addr + offset;
	    prev_addr = data_run->addr;
	}
	else {
	    data_run->flags |= FS_DATA_SPARSE;
	    if (verbose)
		fprintf(stderr, "ntfs_make_data_run: Sparse Run\n");
	}


	/* Advance run */
	run = (ntfs_runlist *) ((uintptr_t) run +
				(1 + NTFS_RUNL_LENSZ(run) +
				 NTFS_RUNL_OFFSZ(run)));

    }

    /* special case for $BADCLUST, which is a sparse file whose size is
     * the entire file system.
     *
     * If there is only one run entry and it is sparse, then there are no
     * bad blocks, so get rid of it.
     */
    if ((data_run_head != NULL) && (data_run_head->next == NULL) &&
	(data_run_head->flags & FS_DATA_SPARSE)) {
	free(data_run_head);
	data_run_head = NULL;
    }

    return data_run_head;
}



/*
 * Perform a walk on a given FS_DATA list.  The _action_ function is
 * called on each cluster of the run.  
 *
 * This gives us an interface to call an action on data and not care if
 * it is resident or not.
 *
 * used flag values: FS_FLAG_FILE_AONLY, FS_FLAG_FILE_SLACK, 
 * FS_FLAG_FILE_NOSPARSE, FS_FLAG_FILE_NOAOBRT
 *
 * Action uses: FS_FLAG_DATA_CONT
 *
 * No notion of META
 */
void
ntfs_data_walk(NTFS_INFO * ntfs, INUM_T inum, FS_DATA * fs_data,
	       int flags, FS_FILE_WALK_FN action, void *ptr)
{
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;
    int myflags;

    if (verbose)
	fprintf(stderr, "ntfs_data_walk: Processing file %" PRIuINUM "\n",
		inum);

    /* Process the resident buffer 
     */
    if (fs_data->flags & FS_DATA_RES) {
	char *buf = NULL;

	if ((flags & FS_FLAG_FILE_AONLY) == 0) {
	    buf = mymalloc(fs_data->size);
	    memcpy(buf, fs_data->buf, fs_data->size);
	}

	myflags = FS_FLAG_DATA_CONT | FS_FLAG_DATA_ALLOC;
	action(fs, ntfs->root_mft_addr, buf, fs_data->size, myflags, ptr);

	if (buf)
	    free(buf);
    }
    /* non-resident */
    else {
	unsigned int a, bufsize;
	DADDR_T addr;
	DATA_BUF *data_buf = NULL;
	char *buf = NULL;
	OFF_T fsize;
	FS_DATA_RUN *fs_data_run;


	if (fs_data->flags & FS_DATA_COMP) {
	    if ((flags & FS_FLAG_FILE_NOABORT) == 0) {
		error
		    ("ERROR: TSK Cannot uncompress NTFS compressed files - aborting");
	    }
	    else {
		if (verbose)
		    fprintf(stderr,
			    "ERROR: TSK Cannot uncompress NTFS compressed files - aborting");
		return;
	    }
	}


	/* if we want the slack space too, then use the runlen  */
	if (flags & FS_FLAG_FILE_SLACK)
	    fsize = fs_data->runlen;
	else
	    fsize = fs_data->size;

	if ((flags & FS_FLAG_FILE_AONLY) == 0) {
	    data_buf = data_buf_alloc(fs->block_size);
	    buf = data_buf->data;
	}

	fs_data_run = fs_data->run;

	/* cycle through the number of runs we have */
	while (fs_data_run) {

	    /* We may get a FILLER entry at the beginning of the run
	     * if we are processing a non-base file record because
	     * this $DATA attribute could not be the first in the bigger
	     * attribute. Therefore, do not error if it starts at 0
	     */
	    if (fs_data_run->flags & FS_DATA_FILLER) {
		if (fs_data_run->addr != 0)
		    error("Filler Entry exists in fs_data_run %" PRIuDADDR
			  "@%" PRIuDADDR " - type: %d  id: %d",
			  fs_data_run->len, fs_data_run->addr,
			  fs_data->type, fs_data->id);
		else
		    fs_data_run = fs_data_run->next;
	    }

	    addr = fs_data_run->addr;

	    /* cycle through each cluster in the run */
	    for (a = 0; a < fs_data_run->len; a++) {

		/* If the address is too large then give an error unless
		 * the no abort flag is set */
		if (addr > fs->last_block) {
		    if (flags & FS_FLAG_FILE_NOABORT) {
			if (verbose) {
			    fprintf(stderr,
				    "Invalid address in run (too large): %"
				    PRIuDADDR "", addr);
			}
			return;
		    }
		    else {
			error("Invalid address in run (too large): %"
			      PRIuDADDR "", addr);
		    }
		}

		if ((flags & FS_FLAG_FILE_AONLY) == 0) {
		    /* sparse files just get 0s */
		    if (fs_data_run->flags & FS_DATA_SPARSE)
			memset(buf, 0, fs->block_size);
		    else if (fs_read_block
			     (fs, data_buf, fs->block_size,
			      addr) != fs->block_size) {
			error("ntfs_data_walk: Error reading block at %"
			      PRIuDADDR ": %m", addr);
		    }
		}

		/* Do we read a full block, or just the remainder? */
		if ((OFF_T) fs->block_size < fsize)
		    bufsize = fs->block_size;
		else
		    bufsize = (int) fsize;

		myflags = FS_FLAG_DATA_CONT;
		myflags |= is_clust_alloc(ntfs, addr) ?
		    FS_FLAG_DATA_ALLOC : FS_FLAG_DATA_UNALLOC;

		/* Only do sparse clusters if NOSPARSE is not set */
		if ((fs_data_run->flags & FS_DATA_SPARSE) &&
		    (0 == (flags & FS_FLAG_FILE_NOSPARSE))) {
		    if (WALK_STOP ==
			action(fs, addr, buf, bufsize, myflags, ptr)) {
			if ((flags & FS_FLAG_FILE_AONLY) == 0)
			    data_buf_free(data_buf);
			return;
		    }
		}

		else if ((fs_data_run->flags & FS_DATA_SPARSE) == 0) {
		    if (WALK_STOP ==
			action(fs, addr, buf, bufsize, myflags, ptr)) {
			if ((flags & FS_FLAG_FILE_AONLY) == 0)
			    data_buf_free(data_buf);
			return;
		    }
		}

		if ((OFF_T) fs->block_size >= fsize)
		    break;

		fsize -= (OFF_T) fs->block_size;

		/* If it is a sparse run, don't increment the addr so that
		 * it always reads 0
		 */
		if ((fs_data_run->flags & FS_DATA_SPARSE) == 0)
		    addr++;
	    }

	    /* advance to the next run */
	    fs_data_run = fs_data_run->next;
	}

	if ((flags & FS_FLAG_FILE_AONLY) == 0)
	    data_buf_free(data_buf);

    }				/* end of non-res */

    return;
}



/* 
 * An attribute sequence is a linked list of the attributes in an MFT entry
 * 
 * This function takes a pointer to the beginning of the sequence,
 * examines each attribute and adds the data to the appropriate fields
 * of fs_inode
 *
 * len is the length of the attrseq buffer
 *
 * This is called by copy_inode and proc_attrlist
 *
 */
static void
ntfs_proc_attrseq(NTFS_INFO * ntfs, FS_INODE * fs_inode,
		  ntfs_attr * attrseq, size_t len)
{
    ntfs_attr *attr = attrseq;
    FS_DATA *fs_data_attrl = NULL, *fs_data = NULL;
    char name[NTFS_MAXNAMLEN_UTF8 + 1];
    OFF_T runlen;
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;

    if (verbose)
	fprintf(stderr,
		"ntfs_proc_attrseq: Processing entry %" PRIuINUM
		"\n", fs_inode->addr);

    /* Cycle through the list of attributes */
    for (; ((uintptr_t) attr >= (uintptr_t) attrseq) &&
	 ((uintptr_t) attr <= ((uintptr_t) attrseq + len)) &&
	 (getu32(fs, attr->len) > 0 &&
	  (getu32(fs, attr->type) != 0xffffffff));
	 attr = (ntfs_attr *) ((uintptr_t) attr + getu32(fs, attr->len))) {

	UTF16 *name16;
	UTF8 *name8;
	int retVal;

	/* Get the type of this attribute */
	uint32_t type = getu32(fs, attr->type);

	/* Copy the name and convert it to UTF8 */
	if (attr->nlen) {

	    name16 =
		(UTF16 *) ((uintptr_t) attr + getu16(fs, attr->name_off));
	    name8 = (UTF8 *) name;

	    retVal = fs_UTF16toUTF8(fs, (const UTF16 **) &name16,
				    (UTF16 *) ((uintptr_t) name16 +
					       attr->nlen * 2), &name8,
				    (UTF8 *) ((uintptr_t) name8 +
					      sizeof(name)),
				    lenientConversion);

	    if (retVal != conversionOK) {
		error
		    ("Error converting NTFS attribute name to UTF8: %d %d",
		     retVal, fs_inode->addr);
	    }

	    /* Make sure it is NULL Terminated */
	    if ((uintptr_t) name8 > (uintptr_t) name + sizeof(name))
		name[sizeof(name)] = '\0';
	    else
		*name8 = '\0';
	}
	/* Call the unnamed $Data attribute, $Data */
	else if (type == NTFS_ATYPE_DATA) {
	    strncpy(name, "$Data", NTFS_MAXNAMLEN_UTF8 + 1);
	}
	else {
	    strncpy(name, "N/A", NTFS_MAXNAMLEN_UTF8 + 1);
	}


	/* 
	 * For resident attributes, we will copy the buffer into
	 * a FS_DATA buffer, which is stored in the FS_INODE
	 * structure
	 */
	if (attr->res == NTFS_MFT_RES) {

	    if (verbose)
		fprintf(stderr,
			"ntfs_proc_attrseq: Resident Attribute in %"
			PRIuINUM " Type: %" PRIu32 " Id: %" PRIu16
			" Name: %s\n", ntfs->mnum, type, getu16(fs,
								attr->id),
			name);


	    /* Add this resident stream to the fs_inode->attr list */
	    fs_inode->attr = fs_data_put_str(fs_inode->attr, name,
					     type, getu16(fs, attr->id),
					     (void *) ((uintptr_t) attr +
						       getu16(fs,
							      attr->c.r.
							      soff)),
					     getu32(fs, attr->c.r.ssize));

	}
	/* For non-resident attributes, we will copy the runlist
	 * to the generic form and then save it in the FS_INODE->attr
	 * list
	 */
	else {
	    FS_DATA_RUN *fs_data_run;
	    uint8_t data_flag = 0;
	    uint16_t id = getu16(fs, attr->id);

	    if (verbose)
		fprintf(stderr,
			"ntfs_proc_attrseq: Non-Resident Attribute in %"
			PRIuINUM " Type: %" PRIu32 " Id: %" PRIu16
			" Name: %s  Start VCN: %" PRIu64 "\n", ntfs->mnum,
			type, id, name, getu64(fs, attr->c.nr.start_vcn));


	    /* convert the run to generic form */
	    fs_data_run = ntfs_make_data_run(ntfs,
					     (ntfs_runlist *) ((uintptr_t)
							       attr +
							       getu16(fs,
								      attr->
								      c.nr.
								      run_off)),
					     &runlen);


	    /* Determine the flags based on compression and stuff */
	    data_flag = 0;
	    if (getu16(fs, attr->flags) & NTFS_ATTR_FLAG_COMP)
		data_flag |= FS_DATA_COMP;
	    if (getu16(fs, attr->flags) & NTFS_ATTR_FLAG_ENC)
		data_flag |= FS_DATA_ENC;
	    if (getu16(fs, attr->flags) & NTFS_ATTR_FLAG_SPAR)
		data_flag |= FS_DATA_SPAR;

	    /* SPECIAL CASE 
	     * We are in non-res section, so we know this
	     * isn't $STD_INFO and $FNAME
	     *
	     * When we are processing a non-base entry, we may
	     * find an attribute with an id of 0 and it is an
	     * extention of a previous run (i.e. non-zero start VCN)
	     * 
	     * We will lookup if we already have such an attribute
	     * and get its ID
	     *
	     * We coudl also check for a start_vcn if this does
	     * not fix the problem
	     */
	    if (id == 0) {
		FS_DATA *fs_data2 = fs_inode->attr;

		while ((fs_data2) && (fs_data2->flags & FS_DATA_INUSE)) {

		    /* We found an attribute with the same name and type */
		    if ((fs_data2->type == type) &&
			(strcmp(fs_data2->name, name) == 0)) {
			id = fs_data2->id;
			if (verbose)
			    fprintf(stderr,
				    "ntfs_proc_attrseq: Updating id from 0 to %"
				    PRIu16 "\n", id);

			break;
		    }
		    fs_data2 = fs_data2->next;
		}
	    }

	    /* Add the run to the list */
	    fs_inode->attr = fs_data_put_run(fs_inode->attr,
					     getu64(fs,
						    attr->c.nr.start_vcn),
					     runlen, fs_data_run, name,
					     type, id, getu64(fs,
							      attr->c.nr.
							      ssize),
					     data_flag);
	}


	/* 
	 * Special Cases, where we grab additional information
	 * regardless if they are resident or not
	 */

	/* Standard Information (is always resident) */
	if (type == NTFS_ATYPE_SI) {
	    ntfs_attr_si *si;

	    if (attr->res != NTFS_MFT_RES)
		error("Standard Information Attribute is not resident!");

	    si = (ntfs_attr_si *) ((uintptr_t) attr +
				   getu16(fs, attr->c.r.soff));

	    fs_inode->mtime = nt2unixtime(getu64(fs, si->mtime));
	    fs_inode->atime = nt2unixtime(getu64(fs, si->atime));
	    fs_inode->ctime = nt2unixtime(getu64(fs, si->ctime));
	    fs_inode->crtime = nt2unixtime(getu64(fs, si->crtime));

	    fs_inode->uid = getu32(fs, si->own_id);

	    fs_inode->mode |= (MODE_IXUSR | MODE_IXGRP | MODE_IXOTH);

	    if ((getu32(fs, si->dos) & NTFS_SI_RO) == 0)
		fs_inode->mode |= (MODE_IRUSR | MODE_IRGRP | MODE_IROTH);

	    if ((getu32(fs, si->dos) & NTFS_SI_HID) == 0)
		fs_inode->mode |= (MODE_IWUSR | MODE_IWGRP | MODE_IWOTH);
	}

	/* File Name (always resident) */
	else if (type == NTFS_ATYPE_FNAME) {
	    ntfs_attr_fname *fname;
	    FS_NAME *fs_name;
	    UTF16 *name16;
	    UTF8 *name8;

	    if (attr->res != NTFS_MFT_RES)
		error("File Name Attribute is not resident!");

	    fname =
		(ntfs_attr_fname *) ((uintptr_t) attr +
				     getu16(fs, attr->c.r.soff));

	    if (fname->nspace == NTFS_FNAME_DOS)
		continue;

	    /* Seek to the end of the fs_name structures in FS_INODE */
	    if (fs_inode->name) {
		for (fs_name = fs_inode->name;
		     (fs_name) && (fs_name->next != NULL);
		     fs_name = fs_name->next) {
		}

		/* add to the end of the existing list */
		fs_name->next = (FS_NAME *) mymalloc(sizeof(FS_NAME));
		fs_name = fs_name->next;
		fs_name->next = NULL;
	    }
	    else {
		/* First name, so we start a list */
		fs_inode->name = fs_name =
		    (FS_NAME *) mymalloc(sizeof(FS_NAME));
		fs_name->next = NULL;
	    }

	    name16 = (UTF16 *) & fname->name;
	    name8 = (UTF8 *) fs_name->name;

	    retVal = fs_UTF16toUTF8(fs, (const UTF16 **) &name16,
				    (UTF16 *) ((uintptr_t) name16 +
					       fname->nlen * 2), &name8,
				    (UTF8 *) ((uintptr_t) name8 +
					      sizeof(fs_name->name)),
				    lenientConversion);

	    if (retVal != conversionOK) {
		error("Error converting NTFS name to UTF8: %d", retVal);
	    }

	    /* Make sure it is NULL Terminated */
	    if ((uintptr_t) name8 >
		(uintptr_t) fs_name->name + sizeof(fs_name->name))
		fs_name->name[sizeof(fs_name->name)] = '\0';
	    else
		*name8 = '\0';

	    fs_name->par_inode = getu48(fs, fname->par_ref);
	    fs_name->par_seq = getu16(fs, fname->par_seq);

	}

	/* If this is an attribute list than we need to process
	 * it to get the list of other entries to read.  But, because
	 * of the wierd scenario of the $MFT having an attribute list
	 * and not knowing where the other MFT entires are yet, we wait 
	 * until the end of the attrseq to processes the list and then
	 * we should have the $Data attribute loaded
	 */
	else if (type == NTFS_ATYPE_ATTRLIST) {
	    if (fs_data_attrl) {
		printf
		    ("Multiple instances of attribute lists in the same MFT\n");
		error
		    ("I didn't realize that could happen, contact the developers");
	    }
	    fs_data_attrl = fs_data_lookup(fs_inode->attr,
					   NTFS_ATYPE_ATTRLIST, getu16(fs,
								       attr->
								       id));
	}

    }				/* end of for loop */



    /* we recalc our size everytime through here.  It is not the most
     * effecient, but easiest with all of the processing of attribute
     * lists and such
     */
    fs_inode->size = 0;
    for (fs_data = fs_inode->attr;
	 fs_data != NULL; fs_data = fs_data->next) {

	if ((fs_data->flags & FS_DATA_INUSE) == 0)
	    continue;

	/* we account for the size of $Data, and directory locations */
	if ((fs_data->type == NTFS_ATYPE_DATA) ||
	    (fs_data->type == NTFS_ATYPE_IDXROOT) ||
	    (fs_data->type == NTFS_ATYPE_IDXALLOC))
	    fs_inode->size += fs_data->size;
    }

    /* Are we currently in the process of loading $MFT? */
    if (ntfs->loading_the_MFT == 1) {

	/* If we don't even have a mini cached version, get it now 
	 * Even if we are not done because of attribute lists, then we
	 * should at least have the head of the list 
	 */
	if (!ntfs->mft_data) {

	    for (fs_data = fs_inode->attr;
		 fs_data != NULL; fs_data = fs_data->next) {

		if ((fs_data->flags & FS_DATA_INUSE) &&
		    (fs_data->type == NTFS_ATYPE_DATA) &&
		    (strcmp(fs_data->name, "$Data") == 0)) {
		    ntfs->mft_data = fs_data;
		    break;
		}
	    }
	    // @@@ Is this needed here -- maybe it should be only in _open
	    if (!ntfs->mft_data) {
		error("$Data not found while loading the MFT");
	    }
	}

	/* Update the inode count based on the current size 
	 * IF $MFT has an attribute list, this value will increase each
	 * time
	 */
	fs->inum_count = ntfs->mft_data->size / ntfs->mft_rsize_b;
	fs->last_inum = fs->inum_count - 1;
    }

    /* If there was an attribute list, process it now, we wait because
     * the list can contain MFT entries that are described in $Data
     * of this MFT entry.  For example, part of the $DATA attribute
     * could follow the ATTRLIST entry, so we read it first and then 
     * process the attribute list
     */
    if (fs_data_attrl)
	ntfs_proc_attrlist(ntfs, fs_inode, fs_data_attrl);

    return;
}



/********   Attribute List Action and Function ***********/


/*
 * Attribute lists are used when all of the attribute  headers can not
 * fit into one MFT entry.  This contains an entry for every attribute
 * and where they are located.  We process this to get the locations
 * and then call proc_attrseq on each of those, which adds the data
 * to the fs_inode structure.
 */
static void
ntfs_proc_attrlist(NTFS_INFO * ntfs, FS_INODE * fs_inode,
		   FS_DATA * fs_data_attrlist)
{
    ntfs_attrlist *list;
    char *buf;
    uintptr_t endaddr;
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;
    ntfs_mft *mft = (ntfs_mft *) mymalloc(ntfs->mft_rsize_b);
    FS_LOAD_FILE load_file;

    INUM_T hist[256];
    uint16_t histcnt = 0;

    if (verbose)
	fprintf(stderr,
		"ntfs_proc_attrlist: Processing entry %" PRIuINUM "\n",
		fs_inode->addr);

    /* Clear the contents of the history buffer */
    memset(hist, 0, sizeof(hist));

    /* add ourselves to the history */
    hist[histcnt++] = ntfs->mnum;


    /* Get a copy of the attribute list stream using the above action */
    load_file.left = load_file.total = (size_t) fs_data_attrlist->size;
    load_file.base = load_file.cur = buf =
	mymalloc(fs_data_attrlist->size);
    endaddr = (uintptr_t) buf + fs_data_attrlist->size;

    ntfs_data_walk(ntfs, ntfs->mnum, fs_data_attrlist, 0, load_file_action,
		   (void *) &load_file);

    /* this value should be zero, if not then we didn't read all of the
     * buffer
     */
    if (load_file.left > 0)
	error("proc_attrlist: listleft > 0");


    /* Process the list & and call ntfs_proc_attr */
    for (list = (ntfs_attrlist *) buf;
	 (list) && ((uintptr_t) list < endaddr)
	 && (getu16(fs, list->len) > 0);
	 list =
	 (ntfs_attrlist *) ((uintptr_t) list + getu16(fs, list->len))) {
	INUM_T mftnum;
	uint32_t type;
	uint16_t id, i;


	/* Which MFT is this attribute in? */
	mftnum = getu48(fs, list->file_ref);

	/* Check the history to see if we have already processed this
	 * one before (if we have then we can skip it as we grabbed all
	 * of them last time
	 */
	for (i = 0; i < histcnt; i++) {
	    if (hist[i] == mftnum)
		break;
	}

	if (hist[i] == mftnum)
	    continue;

	/* This is a new one, add it to the history, and process it */
	if (histcnt < 256)
	    hist[histcnt++] = mftnum;


	type = getu32(fs, list->type);
	id = getu16(fs, list->id);

	if (verbose)
	    fprintf(stderr,
		    "ntfs_proc_attrlist: mft: %" PRIuINUM " type %" PRIu32
		    " id %" PRIu16 "  VCN: %" PRIu64 "\n", mftnum, type,
		    id, getu64(fs, list->start_vcn));

	/* 
	 * Read the MFT entry 
	 */

	/* Sanity check. */
	if (mftnum < ntfs->fs_info.first_inum ||
	    mftnum > ntfs->fs_info.last_inum) {

	    /* Only make a message if it is allocated */
	    if ((getu16(fs, ntfs->mft->flags) & NTFS_MFT_INUSE) != 0) {
		remark("Invalid MFT file reference (%" PRIuINUM
		       ") in the attribute list of MFT %" PRIuINUM "",
		       mftnum, ntfs->mnum);
	    }
	    else if (verbose) {
		/* this case can easily occur if the attribute list was non-resident and the cluster has been reallocated */

		fprintf(stderr,
			"Invalid MFT file reference (%" PRIuINUM
			") in the unallocated attribute list of MFT %"
			PRIuINUM "", mftnum, ntfs->mnum);
	    }

	    continue;
	}

	ntfs_dinode_lookup(ntfs, mft, mftnum);

	/* verify that this entry refers to the original one */
	if (getu48(fs, mft->base_ref) != ntfs->mnum) {

	    /* Before we raise alarms, check if the original was
	     * unallocated.  If so, then the list entry could 
	     * have been reallocated, so we will just ignore it
	     */
	    if ((getu16(fs, ntfs->mft->flags) & NTFS_MFT_INUSE) == 0)
		continue;
	    else
		error("Extension record %" PRIuINUM " (file ref = %"
		      PRIuINUM ") is not for attribute list of %" PRIuINUM
		      "", mftnum, getu48(fs, mft->base_ref), ntfs->mnum);

	}
	/* 
	 * Process the attribute seq for this MFT entry and add them
	 * to the FS_INODE structure
	 */

	ntfs_proc_attrseq(ntfs, fs_inode,
			  (ntfs_attr *) ((uintptr_t) mft +
					 getu16(fs, mft->attr_off)),
			  ntfs->mft_rsize_b - getu16(fs, mft->attr_off));
    }

    free(mft);
    free(buf);

    return;
}



/*
 * Copy the MFT entry saved in ntfs->mft into the generic structure 
 */
static void
ntfs_dinode_copy(NTFS_INFO * ntfs, FS_INODE * fs_inode)
{
    ntfs_mft *mft = ntfs->mft;
    ntfs_attr *attr;
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;

    /* if the attributes list has been used previously, then make sure the 
     * flags are cleared 
     */
    if (fs_inode->attr)
	fs_data_clear_list(fs_inode->attr);

    /* If there are any name structures allocated, then free 'em */
    if (fs_inode->name) {
	FS_NAME *fs_name1, *fs_name2;
	fs_name1 = fs_inode->name;
	while (fs_name1) {
	    fs_name2 = fs_name1->next;
	    free(fs_name1);
	    fs_name1 = fs_name2;
	}
	fs_inode->name = NULL;
    }

    /* Set the fs_inode values from mft */
    fs_inode->nlink = getu16(fs, mft->link);
    fs_inode->seq = getu16(fs, mft->seq);

    fs_inode->addr = ntfs->mnum;

    /* Set the mode for file or directory */
    if (getu16(fs, ntfs->mft->flags) & NTFS_MFT_DIR)
	fs_inode->mode = FS_INODE_DIR;
    else
	fs_inode->mode = FS_INODE_REG;


    /* the following will be changed once we find the correct attribute,
     * but initialize them now just in case 
     */
    fs_inode->uid = 0;
    fs_inode->gid = 0;
    fs_inode->size = 0;
    fs_inode->mtime = 0;
    fs_inode->atime = 0;
    fs_inode->ctime = 0;
    fs_inode->dtime = 0;
    fs_inode->crtime = 0;

    /* add the flags */
    fs_inode->flags = ((getu16(fs, ntfs->mft->flags) & NTFS_MFT_INUSE) ?
		       FS_FLAG_META_ALLOC : FS_FLAG_META_UNALLOC);

    fs_inode->flags |= (getu16(fs, ntfs->mft->link) ?
			FS_FLAG_META_LINK : FS_FLAG_META_UNLINK);

    /* MFT entries are only allocated when needed, so it has been used */
    fs_inode->flags |= FS_FLAG_META_USED;

    /* Process the attribute sequence to fill in the fs_inode->attr
     * list and the other info such as size and times
     */
    attr = (ntfs_attr *) ((uintptr_t) mft + getu16(fs, mft->attr_off));
    ntfs_proc_attrseq(ntfs, fs_inode, attr,
		      ntfs->mft_rsize_b - getu16(fs, mft->attr_off));

    return;
}


/*
 * Read the mft entry and put it into the ntfs->mft structure
 * Also sets the ntfs->mnum value
 */
void
ntfs_dinode_load(NTFS_INFO * ntfs, INUM_T mftnum)
{
    /* mft_lookup does a sanity check, so we can skip it here */
    ntfs_dinode_lookup(ntfs, ntfs->mft, mftnum);
    ntfs->mnum = mftnum;

    return;
}


/*
 * return the MFT entry in the generic FS_INODE format
 */
static FS_INODE *
ntfs_inode_lookup(FS_INFO * fs, INUM_T mftnum)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    FS_INODE *fs_inode = fs_inode_alloc(NTFS_NDADDR, NTFS_NIADDR);

    /* Lookup inode and store it in the ntfs structure */
    ntfs_dinode_load(ntfs, mftnum);

    /* Copy the structure in ntfs to generic fs_inode */
    ntfs_dinode_copy(ntfs, fs_inode);

    return (fs_inode);
}




/**********************************************************************
 *
 *  Load special MFT structures into the NTFS_INFO structure
 *
 **********************************************************************/

/* The attrdef structure defines the types of attributes and gives a 
 * name value to the type number.
 *
 * We currently do not use this during the analysis (Because it has not
 * historically changed, but we do display it in fsstat 
 */
static void
ntfs_load_attrdef(NTFS_INFO * ntfs)
{
    FS_INODE *fs_inode;
    FS_DATA *fs_data;
    FS_INFO *fs = &ntfs->fs_info;
    FS_LOAD_FILE load_file;

    /* if already loaded, return now */
    if (ntfs->attrdef)
	return;

    fs_inode = ntfs_inode_lookup(fs, NTFS_MFT_ATTR);
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_DATA);
    if (!fs_data)
	error("Data attribute not found in $Attr");


    /* Get a copy of the attribute list stream using the above action */
    load_file.left = load_file.total = (size_t) fs_data->size;
    load_file.base = load_file.cur = mymalloc(fs_data->size);
    ntfs->attrdef = (ntfs_attrdef *) load_file.base;

    ntfs_data_walk(ntfs, fs_inode->addr, fs_data, 0, load_file_action,
		   (void *) &load_file);

    if (load_file.left > 0)
	error("space still left after walking $Attr data");

    fs_inode_free(fs_inode);
    return;
}


/* 
 * return the name of the attribute type.  If the attribute has not
 * been loaded yet, it will be.
 */
void
ntfs_attrname_lookup(FS_INFO * fs, uint16_t type, char *name, int len)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    ntfs_attrdef *attrdef;

    if (!ntfs->attrdef)
	ntfs_load_attrdef(ntfs);

    attrdef = ntfs->attrdef;

    while (getu32(fs, attrdef->type)) {
	if (getu32(fs, attrdef->type) == type) {

	    UTF16 *name16 = (UTF16 *) attrdef->label;
	    UTF8 *name8 = (UTF8 *) name;
	    int retVal;

	    retVal = fs_UTF16toUTF8(fs, (const UTF16 **) &name16,
				    (UTF16 *) ((uintptr_t) name16 +
					       sizeof(attrdef->label)),
				    &name8,
				    (UTF8 *) ((uintptr_t) name8 + len),
				    lenientConversion);

	    if (retVal != conversionOK) {
		error
		    ("Error converting NTFS attribute def label to UTF8: %d",
		     retVal);
	    }

	    /* Make sure it is NULL Terminated */
	    if ((uintptr_t) name8 > (uintptr_t) name + len)
		name[len] = '\0';
	    else
		*name8 = '\0';

	    return;
	}
	attrdef++;
    }
    /* If we didn't find it, then call it '?' */
    snprintf(name, len, "?");
}


/* Load the block bitmap $Data run  and allocate a buffer for a cache */
static void
ntfs_load_bmap(NTFS_INFO * ntfs)
{
    ntfs_attr *attr;
    FS_INFO *fs = &ntfs->fs_info;

    /* Get data on the bitmap */
    ntfs_dinode_load(ntfs, NTFS_MFT_BMAP);

    attr = (ntfs_attr *) ((uintptr_t) ntfs->mft +
			  getu16(fs, ntfs->mft->attr_off));

    /* cycle through them */
    while (((uintptr_t) attr >= (uintptr_t) ntfs->mft) &&
	   ((uintptr_t) attr <=
	    ((uintptr_t) ntfs->mft + (uintptr_t) ntfs->mft_rsize_b))
	   && (getu32(fs, attr->len) > 0
	       && (getu32(fs, attr->type) != 0xffffffff)
	       && (getu32(fs, attr->type) != NTFS_ATYPE_DATA))) {
	attr = (ntfs_attr *) ((uintptr_t) attr + getu32(fs, attr->len));
    }

    /* did we get it? */
    if (getu32(fs, attr->type) != NTFS_ATYPE_DATA)
	error("Error Finding Bitmap Data Attribute");

    /* convert to generic form */
    ntfs->bmap = ntfs_make_data_run(ntfs,
				    (ntfs_runlist *) ((uintptr_t) attr +
						      getu16(fs,
							     attr->c.nr.
							     run_off)),
				    NULL);

    ntfs->bmap_buf = data_buf_alloc(fs->block_size);

    /* Load the first cluster so that we have something there */
    ntfs->bmap_buf_off = 0;

    if (ntfs->bmap->addr > fs->last_block) {
	error("ntfs_load_bmap: Bitmap too large for image size: %"
	      PRIuDADDR "", ntfs->bmap->addr);
    }
    if (fs_read_block(fs, ntfs->bmap_buf, fs->block_size, ntfs->bmap->addr)
	!= fs->block_size) {
	error("ntfs_load_bmap: Error reading block at %" PRIuDADDR ": %m",
	      ntfs->bmap->addr);
    }
}


/*
 * Load the VOLUME MFT entry and the VINFO attribute so that we
 * can identify the volume version of this.  
 */
static void
ntfs_load_ver(NTFS_INFO * ntfs)
{
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;
    FS_INODE *fs_inode;
    FS_DATA *fs_data;

    fs_inode = ntfs_inode_lookup(fs, NTFS_MFT_VOL);

    /* cache the data attribute */
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_VINFO);

    if (!fs_data)
	error("Volume Info attribute not found in $Volume");

    if ((fs_data->flags & FS_DATA_RES) && (fs_data->size)) {
	ntfs_attr_vinfo *vinfo = (ntfs_attr_vinfo *) fs_data->buf;
	if ((vinfo->maj_ver == 1) && (vinfo->min_ver == 2))
	    ntfs->ver = NTFS_VINFO_NT;
	else if ((vinfo->maj_ver == 3) && (vinfo->min_ver == 0))
	    ntfs->ver = NTFS_VINFO_2K;
	else if ((vinfo->maj_ver == 3) && (vinfo->min_ver == 1))
	    ntfs->ver = NTFS_VINFO_XP;
	else
	    error("unknown version: %d.%d\n", vinfo->maj_ver,
		  vinfo->min_ver);
    }
    else {
	error("VINFO is a non-resident attribute");
    }

    fs_inode_free(fs_inode);
    return;
}


/**********************************************************************
 *
 *  Exported Walk Functions
 *
 **********************************************************************/

/*
 *
 * flag values: FS_FLAG_FILE_AONLY, FS_FLAG_FILE_SLACK, FS_FLAG_FILE_NOSPARSE
 *  FS_FLAG_FILE_NOABORT, FS_FLAG_FILE_NOID
 * 
 * nothing special is done for FS_FLAG_FILE_RECOVER
 *
 * action uses: FS_FLAG_DATA_CONT
 *
 * No notion of meta with NTFS
 *
 * a type of 0 will use $Data for files and IDXROOT for directories
 * an id of 0 will ignore the id and just find the first entry with the type
 */
void
ntfs_file_walk(FS_INFO * fs, FS_INODE * fs_inode, uint32_t type,
	       uint16_t id, int flags, FS_FILE_WALK_FN action, void *ptr)
{
    FS_DATA *fs_data;
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;

    /* no data */
    if (fs_inode->attr == NULL)
	return;

    /* if no type was given, then use DATA for files and IDXROOT for dirs */
    if (type == 0) {
	if ((fs_inode->mode & FS_INODE_FMT) == FS_INODE_DIR)
	    type = NTFS_ATYPE_IDXROOT;
	else
	    type = NTFS_ATYPE_DATA;
    }

    /* 
     * Find the record with the correct type value 
     */
    if (flags & FS_FLAG_FILE_NOID) {
	fs_data = fs_data_lookup_noid(fs_inode->attr, type);
	if (!fs_data)
	    error("type %" PRIu32 " not found in file", type);
    }
    else {
	fs_data = fs_data_lookup(fs_inode->attr, type, id);
	if (!fs_data)
	    error("type %" PRIu32 "-%" PRIu16 " not found in file", type,
		  id);
    }


    /* process the content */
    ntfs_data_walk(ntfs, fs_inode->addr, fs_data, flags, action, ptr);

    return;
}





/*
 * flags: FS_FLAG_DATA_ALLOC and FS_FLAG_UNALLOC
 *
 * @@@ We should probably consider some data META, but it is tough with
 * the NTFS design ...
 */
void
ntfs_block_walk(FS_INFO * fs, DADDR_T start_blk, DADDR_T end_blk,
		int flags, FS_BLOCK_WALK_FN action, void *ptr)
{
    char *myname = "ntfs_block_walk";
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    DADDR_T addr;
    DATA_BUF *data_buf = data_buf_alloc(fs->block_size);	/* allocate a cluster */
    int myflags;

    /*
     * Sanity checks.
     */
    if (start_blk < fs->first_block || start_blk > fs->last_block)
	error("%s: invalid start block number: %" PRIuDADDR "", myname,
	      start_blk);
    if (end_blk < fs->first_block || end_blk > fs->last_block)
	error("%s: invalid last block number: %" PRIuDADDR "", myname,
	      end_blk);


    /* Cycle through the blocks */
    for (addr = start_blk; addr <= end_blk; addr++) {

	/* identify if the cluster is allocated or not */
	myflags = is_clust_alloc(ntfs, addr) ?
	    FS_FLAG_DATA_ALLOC : FS_FLAG_DATA_UNALLOC;

	if (flags & myflags) {
	    if (fs_read_block(fs, data_buf, fs->block_size, addr) !=
		fs->block_size) {
		error("ntfs_block_walk: Error reading block at %" PRIuDADDR
		      ": %m", addr);
	    }

	    if (WALK_STOP ==
		action(fs, addr, data_buf->data, myflags, ptr)) {
		data_buf_free(data_buf);
		return;
	    }
	}
    }

    data_buf_free(data_buf);
    return;
}



/*
 * inode_walk
 *
 * Flags: FS_FLAG_META_ALLOC, FS_FLAG_META_UNALLOC, FS_FLAG_META_LINK,
 * FS_FLAG_META_UNLINK, FS_FLAG_META_USED
 *
 * Not used: FS_FLAG_META_UNUSED (Only allocated when needed)
 */
void
ntfs_inode_walk(FS_INFO * fs, INUM_T start_inum, INUM_T end_inum,
		int flags, FS_INODE_WALK_FN action, void *ptr)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    int myflags;
    INUM_T mftnum;
    FS_INODE *fs_inode = fs_inode_alloc(NTFS_NDADDR, NTFS_NIADDR);

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum)
	error("Starting inode number is too small (%" PRIuINUM ")",
	      start_inum);
    if (start_inum > fs->last_inum)
	error("Starting inode number is too large (%" PRIuINUM ")",
	      start_inum);

    if (end_inum < fs->first_inum)
	error("Ending inode number is too small (%" PRIuINUM ")",
	      end_inum);
    if (end_inum > fs->last_inum)
	error("Ending inode number is too large (%" PRIuINUM ")",
	      end_inum);


    for (mftnum = start_inum; mftnum <= end_inum; mftnum++) {

	/* read MFT entry in to NTFS_INFO */
	ntfs_dinode_load(ntfs, mftnum);

	/* we only want to look at base file records 
	 * (extended are because the base could not fit into one)
	 */
	if (getu48(fs, ntfs->mft->base_ref) != NTFS_MFT_BASE)
	    continue;

	/* NOTE: We could add a sanity check here with the MFT bitmap
	 * to validate of the INUSE flag and bitmap are in agreement
	 */

	/* check flags */
	myflags = ((getu16(fs, ntfs->mft->flags) & NTFS_MFT_INUSE) ?
		   FS_FLAG_META_ALLOC : FS_FLAG_META_UNALLOC);

	myflags |= (getu16(fs, ntfs->mft->link) ?
		    FS_FLAG_META_LINK : FS_FLAG_META_UNLINK);

	/* MFT entries are only allocated when needed, so it must have 
	 * been used
	 */
	myflags |= FS_FLAG_META_USED;

	if ((flags & myflags) != myflags)
	    continue;

	/* copy into generic format */
	ntfs_dinode_copy(ntfs, fs_inode);

	/* call action */
	if (WALK_STOP == action(fs, fs_inode, myflags, ptr)) {
	    fs_inode_free(fs_inode);
	    return;
	}
    }

    fs_inode_free(fs_inode);
    return;
}


static void
ntfs_fscheck(FS_INFO * fs, FILE * hFile)
{
    error("fscheck not implemented for NTFS yet");
}


static void
ntfs_fsstat(FS_INFO * fs, FILE * hFile)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    FS_INODE *fs_inode;
    FS_DATA *fs_data;
    char asc[512];
    ntfs_attrdef *attrdeftmp;

    fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    fprintf(hFile, "--------------------------------------------\n");

    fprintf(hFile, "File System Type: NTFS\n");

    fprintf(hFile, "Volume Serial Number: %.16" PRIX64 "\n",
	    getu64(fs, ntfs->fs->serial));


    fprintf(hFile, "OEM Name: %c%c%c%c%c%c%c%c\n",
	    ntfs->fs->oemname[0],
	    ntfs->fs->oemname[1], ntfs->fs->oemname[2],
	    ntfs->fs->oemname[3], ntfs->fs->oemname[4],
	    ntfs->fs->oemname[5], ntfs->fs->oemname[6],
	    ntfs->fs->oemname[7]);


    /*
     * Volume 
     */
    fs_inode = ntfs_inode_lookup(fs, NTFS_MFT_VOL);
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_VNAME);
    if (!fs_data)
	error("Volume Name attribute not found in $Volume");

    if ((fs_data->flags & FS_DATA_RES) && (fs_data->size)) {

	UTF16 *name16 = (UTF16 *) fs_data->buf;
	UTF8 *name8 = (UTF8 *) asc;
	int retVal;

	retVal = fs_UTF16toUTF8(fs, (const UTF16 **) &name16,
				(UTF16 *) ((uintptr_t) name16 +
					   (int) fs_data->size), &name8,
				(UTF8 *) ((uintptr_t) name8 + sizeof(asc)),
				lenientConversion);

	if (retVal != conversionOK) {
	    error("Error converting NTFS Volume label to UTF8: %d",
		  retVal);
	}

	/* Make sure it is NULL Terminated */
	if ((uintptr_t) name8 > (uintptr_t) asc + sizeof(asc))
	    asc[sizeof(asc)] = '\0';
	else
	    *name8 = '\0';

	fprintf(hFile, "Volume Name: %s\n", asc);
    }

    fs_inode_free(fs_inode);
    fs_inode = NULL;
    fs_data = NULL;


    if (ntfs->ver == NTFS_VINFO_NT)
	fprintf(hFile, "Version: Windows NT\n");
    else if (ntfs->ver == NTFS_VINFO_2K)
	fprintf(hFile, "Version: Windows 2000\n");
    else if (ntfs->ver == NTFS_VINFO_XP)
	fprintf(hFile, "Version: Windows XP\n");


    fprintf(hFile, "\nMETADATA INFORMATION\n");
    fprintf(hFile, "--------------------------------------------\n");

    fprintf(hFile, "First Cluster of MFT: %" PRIu64 "\n",
	    getu64(fs, ntfs->fs->mft_clust));

    fprintf(hFile, "First Cluster of MFT Mirror: %" PRIu64 "\n",
	    getu64(fs, ntfs->fs->mftm_clust));

    fprintf(hFile, "Size of MFT Entries: %" PRIu16 " bytes\n",
	    ntfs->mft_rsize_b);
    fprintf(hFile, "Size of Index Records: %" PRIu16 " bytes\n",
	    ntfs->idx_rsize_b);

    fprintf(hFile, "Range: %" PRIuINUM " - %" PRIuINUM "\n",
	    fs->first_inum, fs->last_inum);
    fprintf(hFile, "Root Directory: %" PRIuINUM "\n", fs->root_inum);


    fprintf(hFile, "\nCONTENT INFORMATION\n");
    fprintf(hFile, "--------------------------------------------\n");
    fprintf(hFile, "Sector Size: %" PRIu16 "\n", ntfs->ssize_b);
    fprintf(hFile, "Cluster Size: %" PRIu16 "\n", ntfs->csize_b);

    fprintf(hFile,
	    "Total Cluster Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
	    fs->first_block, fs->last_block);

    fprintf(hFile, "Total Sector Range: 0 - %" PRIu64 "\n",
	    getu64(fs, ntfs->fs->vol_size_s) - 1);

    /* 
     * Attrdef Info 
     */
    fprintf(hFile, "\n$AttrDef Attribute Values:\n");

    if (!ntfs->attrdef)
	ntfs_load_attrdef(ntfs);

    attrdeftmp = ntfs->attrdef;

    while (getu32(fs, attrdeftmp->type)) {
	UTF16 *name16 = (UTF16 *) attrdeftmp->label;
	UTF8 *name8 = (UTF8 *) asc;
	int retVal;

	retVal = fs_UTF16toUTF8(fs, (const UTF16 **) &name16,
				(UTF16 *) ((uintptr_t) name16 +
					   sizeof(attrdeftmp->label)),
				&name8,
				(UTF8 *) ((uintptr_t) name8 + sizeof(asc)),
				lenientConversion);

	if (retVal != conversionOK) {
	    error("Error converting NTFS attribute def label to UTF8: %d",
		  retVal);
	}

	/* Make sure it is NULL Terminated */
	if ((uintptr_t) name8 > (uintptr_t) asc + sizeof(asc))
	    asc[sizeof(asc)] = '\0';
	else
	    *name8 = '\0';

	fprintf(hFile, "%s (%" PRIu32 ")   ",
		asc, getu32(fs, attrdeftmp->type));

	if ((getu64(fs, attrdeftmp->minsize) == 0) &&
	    (getu64(fs, attrdeftmp->maxsize) == 0xffffffffffffffffULL)) {

	    fprintf(hFile, "Size: No Limit");
	}
	else {
	    fprintf(hFile, "Size: %" PRIu64 "-%" PRIu64,
		    getu64(fs, attrdeftmp->minsize),
		    getu64(fs, attrdeftmp->maxsize));
	}

	fprintf(hFile, "   Flags: %s%s%s\n",
		(getu32(fs, attrdeftmp->flags) & NTFS_ATTRDEF_FLAGS_RES ?
		 "Resident" : ""), (getu32(fs,
					   attrdeftmp->
					   flags) &
				    NTFS_ATTRDEF_FLAGS_NONRES ?
				    "Non-resident" : ""), (getu32(fs,
								  attrdeftmp->
								  flags) &
							   NTFS_ATTRDEF_FLAGS_IDX
							   ? ",Index" :
							   ""));

	attrdeftmp++;
    }
}


/************************* istat *******************************/

#define NTFS_PRINT_WIDTH   8
typedef struct {
    FILE *hFile;
    int idx;
} NTFS_PRINT_ADDR;

static uint8_t
print_addr_act(FS_INFO * fs, DADDR_T addr, char *buf,
	       unsigned int size, int flags, void *ptr)
{
    NTFS_PRINT_ADDR *print = (NTFS_PRINT_ADDR *) ptr;
    fprintf(print->hFile, "%" PRIuDADDR " ", addr);

    if (++(print->idx) == NTFS_PRINT_WIDTH) {
	fprintf(print->hFile, "\n");
	print->idx = 0;
    }

    return WALK_CONT;
}


static void
ntfs_istat(FS_INFO * fs, FILE * hFile, INUM_T inum, int numblock,
	   int32_t sec_skew)
{
    FS_INODE *fs_inode;
    FS_DATA *fs_data;
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;

    fs_inode = ntfs_inode_lookup(fs, inum);
    fprintf(hFile, "MFT Entry Header Values:\n");
    fprintf(hFile, "Entry: %" PRIuINUM "        Sequence: %" PRIu32 "\n",
	    inum, fs_inode->seq);

    if (getu48(fs, ntfs->mft->base_ref) != 0) {
	fprintf(hFile, "Base File Record: %" PRIu64 "\n",
		(uint64_t) getu48(fs, ntfs->mft->base_ref));
    }

    fprintf(hFile, "$LogFile Sequence Number: %" PRIu64 "\n",
	    getu64(fs, ntfs->mft->lsn));

    fprintf(hFile, "%sAllocated %s\n",
	    (fs_inode->flags & FS_FLAG_META_ALLOC) ? "" : "Not ",
	    (fs_inode->mode & FS_INODE_DIR) ? "Directory" : "File");

    fprintf(hFile, "Links: %u\n", fs_inode->nlink);


    /* STANDARD_INFORMATION info */
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_SI);
    if (fs_data) {
	ntfs_attr_si *si = (ntfs_attr_si *) fs_data->buf;
	int a = 0;

	fprintf(hFile, "\n$STANDARD_INFORMATION Attribute Values:\n");

	fprintf(hFile, "Flags: ");
	if (getu32(fs, si->dos) & NTFS_SI_RO)
	    fprintf(hFile, "%sRead Only", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_HID)
	    fprintf(hFile, "%sHidden", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_SYS)
	    fprintf(hFile, "%sSystem", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_ARCH)
	    fprintf(hFile, "%sArchive", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_DEV)
	    fprintf(hFile, "%sDevice", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_NORM)
	    fprintf(hFile, "%sNormal", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_TEMP)
	    fprintf(hFile, "%sTemporary", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_SPAR)
	    fprintf(hFile, "%sSparse", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_REP)
	    fprintf(hFile, "%sReparse Point", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_COMP)
	    fprintf(hFile, "%sCompressed", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_OFF)
	    fprintf(hFile, "%sOffline", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_NOIDX)
	    fprintf(hFile, "%sNot Content Indexed", a++ == 0 ? "" : ", ");

	if (getu32(fs, si->dos) & NTFS_SI_ENC)
	    fprintf(hFile, "%sEncrypted", a++ == 0 ? "" : ", ");

	fprintf(hFile, "\n");

	fprintf(hFile,
		"Owner ID: %" PRIu32 "     Security ID: %" PRIu32 "\n",
		getu32(fs, si->own_id), getu32(fs, si->sec_id));

	if (getu32(fs, si->maxver) != 0) {
	    fprintf(hFile, "Version %" PRIu32 " of %" PRIu32 "\n",
		    getu32(fs, si->ver), getu32(fs, si->maxver));
	}

	if (getu64(fs, si->quota) != 0) {
	    fprintf(hFile, "Quota Charged: %" PRIu64 "\n",
		    getu64(fs, si->quota));
	}

	if (getu64(fs, si->usn) != 0) {
	    fprintf(hFile,
		    "Last User Journal Update Sequence Number: %" PRIu64
		    "\n", getu64(fs, si->usn));
	}


	/* Times - take it from fs_inode instead of redoing the work */

	if (sec_skew != 0) {
	    fprintf(hFile, "\nAdjusted times:\n");
	    fs_inode->mtime -= sec_skew;
	    fs_inode->atime -= sec_skew;
	    fs_inode->ctime -= sec_skew;
	    fs_inode->crtime -= sec_skew;

	    fprintf(hFile, "Created:\t%s", ctime(&fs_inode->crtime));
	    fprintf(hFile, "File Modified:\t%s", ctime(&fs_inode->mtime));
	    fprintf(hFile, "MFT Modified:\t%s", ctime(&fs_inode->ctime));
	    fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));

	    fs_inode->mtime += sec_skew;
	    fs_inode->atime += sec_skew;
	    fs_inode->ctime += sec_skew;
	    fs_inode->crtime += sec_skew;

	    fprintf(hFile, "\nOriginal times:\n");
	}

	fprintf(hFile, "Created:\t%s", ctime(&fs_inode->crtime));
	fprintf(hFile, "File Modified:\t%s", ctime(&fs_inode->mtime));
	fprintf(hFile, "MFT Modified:\t%s", ctime(&fs_inode->ctime));
	fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
    }

    /* $FILE_NAME Information */
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_FNAME);
    if (fs_data) {

	ntfs_attr_fname *fname = (ntfs_attr_fname *) fs_data->buf;
	time_t cr_time, m_time, c_time, a_time;
	uint64_t flags;
	int a = 0;

	fprintf(hFile, "\n$FILE_NAME Attribute Values:\n");


	flags = getu64(fs, fname->flags);
	fprintf(hFile, "Flags: ");

	if (flags & NTFS_FNAME_FLAGS_DIR)
	    fprintf(hFile, "%sDirectory", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_DEV)
	    fprintf(hFile, "%sDevice", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_NORM)
	    fprintf(hFile, "%sNormal", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_RO)
	    fprintf(hFile, "%sRead Only", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_HID)
	    fprintf(hFile, "%sHidden", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_SYS)
	    fprintf(hFile, "%sSystem", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_ARCH)
	    fprintf(hFile, "%sArchive", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_TEMP)
	    fprintf(hFile, "%sTemp", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_SPAR)
	    fprintf(hFile, "%sSparse", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_REP)
	    fprintf(hFile, "%sReparse Point", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_COMP)
	    fprintf(hFile, "%sCompressed", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_ENC)
	    fprintf(hFile, "%sEncrypted", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_OFF)
	    fprintf(hFile, "%sOffline", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_NOIDX)
	    fprintf(hFile, "%sNot Content Indexed", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_IDXVIEW)
	    fprintf(hFile, "%sIndex View", a++ == 0 ? "" : ", ");

	fprintf(hFile, "\n");

	/* We could look this up in the attribute, but we already did
	 * the work */
	if (fs_inode->name) {
	    FS_NAME *fs_name = fs_inode->name;
	    fprintf(hFile, "Name: ");
	    while (fs_name) {
		fprintf(hFile, "%s", fs_name->name);
		fs_name = fs_name->next;
		if (fs_name)
		    fprintf(hFile, ", ");
		else
		    fprintf(hFile, "\n");
	    }
	}

	fprintf(hFile,
		"Parent MFT Entry: %" PRIu64 " \tSequence: %" PRIu16 "\n",
		(uint64_t) getu48(fs, fname->par_ref), getu16(fs,
							      fname->
							      par_seq));

	fprintf(hFile,
		"Allocated Size: %" PRIu64 "   \tActual Size: %" PRIu64
		"\n", getu64(fs, fname->alloc_fsize), getu64(fs,
							     fname->
							     real_fsize));


	/* 
	 * Times 
	 */
	cr_time = nt2unixtime(getu64(fs, fname->crtime));
	/* altered - modified */
	m_time = nt2unixtime(getu64(fs, fname->mtime));
	/* MFT modified */
	c_time = nt2unixtime(getu64(fs, fname->ctime));
	/* Access */
	a_time = nt2unixtime(getu64(fs, fname->atime));

	if (sec_skew != 0) {
	    fprintf(hFile, "\nAdjusted times:\n");
	    cr_time -= sec_skew;
	    m_time -= sec_skew;
	    a_time -= sec_skew;
	    c_time -= sec_skew;

	    fprintf(hFile, "Created:\t%s", ctime(&cr_time));
	    fprintf(hFile, "File Modified:\t%s", ctime(&m_time));
	    fprintf(hFile, "MFT Modified:\t%s", ctime(&c_time));
	    fprintf(hFile, "Accessed:\t%s", ctime(&a_time));

	    cr_time += sec_skew;
	    m_time += sec_skew;
	    a_time += sec_skew;
	    c_time += sec_skew;

	    fprintf(hFile, "\nOriginal times:\n");
	}

	fprintf(hFile, "Created:\t%s", ctime(&cr_time));
	fprintf(hFile, "File Modified:\t%s", ctime(&m_time));
	fprintf(hFile, "MFT Modified:\t%s", ctime(&c_time));
	fprintf(hFile, "Accessed:\t%s", ctime(&a_time));

    }


    /* $OBJECT_ID Information */
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_OBJID);
    if (fs_data) {
	ntfs_attr_objid *objid = (ntfs_attr_objid *) fs_data->buf;
	uint64_t id1, id2;

	fprintf(hFile, "\n$OBJECT_ID Attribute Values:\n");

	id1 = getu64(fs, objid->objid1);
	id2 = getu64(fs, objid->objid2);

	fprintf(hFile,
		"Object Id: %.8" PRIx32 "-%.4" PRIx16 "-%.4" PRIx16 "-%.4"
		PRIx16 "-%.12" PRIx64 "\n",
		(uint32_t) (id2 >> 32) & 0xffffffff,
		(uint16_t) (id2 >> 16) & 0xffff, (uint16_t) (id2 & 0xffff),
		(uint16_t) (id1 >> 48) & 0xffff,
		(uint64_t) (id1 & (uint64_t) 0x0000ffffffffffffULL));


	/* The rest of the  fields do not always exist.  Check the attr size */
	if (fs_data->size > 16) {
	    id1 = getu64(fs, objid->orig_volid1);
	    id2 = getu64(fs, objid->orig_volid2);

	    fprintf(hFile,
		    "Birth Volume Id: %.8" PRIx32 "-%.4" PRIx16 "-%.4"
		    PRIx16 "-%.4" PRIx16 "-%.12" PRIx64 "\n",
		    (uint32_t) (id2 >> 32) & 0xffffffff,
		    (uint16_t) (id2 >> 16) & 0xffff,
		    (uint16_t) (id2 & 0xffff),
		    (uint16_t) (id1 >> 48) & 0xffff,
		    (uint64_t) (id1 & (uint64_t) 0x0000ffffffffffffULL));
	}

	if (fs_data->size > 32) {
	    id1 = getu64(fs, objid->orig_objid1);
	    id2 = getu64(fs, objid->orig_objid2);

	    fprintf(hFile,
		    "Birth Object Id: %.8" PRIx32 "-%.4" PRIx16 "-%.4"
		    PRIx16 "-%.4" PRIx16 "-%.12" PRIx64 "\n",
		    (uint32_t) (id2 >> 32) & 0xffffffff,
		    (uint16_t) (id2 >> 16) & 0xffff,
		    (uint16_t) (id2 & 0xffff),
		    (uint16_t) (id1 >> 48) & 0xffff,
		    (uint64_t) (id1 & (uint64_t) 0x0000ffffffffffffULL));
	}

	if (fs_data->size > 48) {
	    id1 = getu64(fs, objid->orig_domid1);
	    id2 = getu64(fs, objid->orig_domid2);

	    fprintf(hFile,
		    "Birth Domain Id: %.8" PRIx32 "-%.4" PRIx16 "-%.4"
		    PRIx16 "-%.4" PRIx16 "-%.12" PRIx64 "\n",
		    (uint32_t) (id2 >> 32) & 0xffffffff,
		    (uint16_t) (id2 >> 16) & 0xffff,
		    (uint16_t) (id2 & 0xffff),
		    (uint16_t) (id1 >> 48) & 0xffff,
		    (uint64_t) (id1 & (uint64_t) 0x0000ffffffffffffULL));
	}
    }

    /* Attribute List Information */
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_ATTRLIST);
    if (fs_data) {
	char *buf;
	ntfs_attrlist *list;
	uintptr_t endaddr;
	FS_LOAD_FILE load_file;

	fprintf(hFile, "\n$ATTRIBUTE_LIST Attribute Values:\n");

	/* Get a copy of the attribute list stream  */
	load_file.total = load_file.left = (size_t) fs_data->size;
	load_file.cur = load_file.base = buf = mymalloc(fs_data->size);
	endaddr = (uintptr_t) buf + fs_data->size;

	ntfs_data_walk(ntfs, fs_inode->addr, fs_data, 0, load_file_action,
		       (void *) &load_file);

	/* this value should be zero, if not then we didn't read all of the
	 * buffer
	 */
	if (load_file.left > 0) {
	    fprintf(hFile, "error reading attribute list buffer\n");
	    goto egress;
	}

	/* Process the list & print the details */
	for (list = (ntfs_attrlist *) buf;
	     (list) && ((uintptr_t) list < endaddr)
	     && (getu16(fs, list->len) > 0);
	     list =
	     (ntfs_attrlist *) ((uintptr_t) list +
				getu16(fs, list->len))) {
	    fprintf(hFile,
		    "Type: %" PRIu32 "-%" PRIu16 " \tMFT Entry: %" PRIu64
		    " \tVCN: %" PRIu64 "\n", getu32(fs, list->type),
		    getu16(fs, list->id), (uint64_t) getu48(fs,
							    list->
							    file_ref),
		    getu64(fs, list->start_vcn));
	}
      egress:
	free(buf);
    }

    /* Print all of the attributes */
    fs_data = fs_inode->attr;

    fprintf(hFile, "\nAttributes: \n");
    while ((fs_data) && (fs_data->flags & FS_DATA_INUSE)) {

	char type[512];

	ntfs_attrname_lookup(fs, fs_data->type, type, 512);

	printf("Type: %s (%" PRIu32 "-%" PRIu16
	       ")   Name: %s   %sResident%s%s%s   size: %" PRIuOFF "\n",
	       type, fs_data->type, fs_data->id, fs_data->name,
	       (fs_data->flags & FS_DATA_NONRES) ? "Non-" : "",
	       (fs_data->flags & FS_DATA_ENC) ? ", Encrypted" : "",
	       (fs_data->flags & FS_DATA_COMP) ? ", Compressed" : "",
	       (fs_data->flags & FS_DATA_SPAR) ? ", Sparse" : "",
	       fs_data->size);

	/* print the layout if it is non-resident and not "special" */
	if (fs_data->flags & FS_DATA_NONRES) {
	    NTFS_PRINT_ADDR print_addr;
	    print_addr.idx = 0;
	    print_addr.hFile = hFile;

	    fs->file_walk(fs, fs_inode, fs_data->type, fs_data->id,
			  (FS_FLAG_FILE_AONLY | FS_FLAG_FILE_SLACK |
			   FS_FLAG_FILE_NOABORT), print_addr_act,
			  (void *) &print_addr);

	    if (print_addr.idx != 0)
		printf("\n");
	}

	fs_data = fs_data->next;
    }

    fs_inode_free(fs_inode);

    return;
}



/* JOURNAL CODE - MOVE TO NEW FILE AT SOME POINT */

void
ntfs_jopen(FS_INFO * fs, INUM_T inum)
{
    fprintf(stderr, "NTFS Journal is not yet supported\n");
    exit(1);
}

void
ntfs_jentry_walk(FS_INFO * fs, int flags, FS_JENTRY_WALK_FN action,
		 void *ptr)
{
    fprintf(stderr, "NTFS Journal is not yet supported\n");
    exit(1);
}


void
ntfs_jblk_walk(FS_INFO * fs, DADDR_T start, DADDR_T end, int flags,
	       FS_JBLK_WALK_FN action, void *ptr)
{
    fprintf(stderr, "NTFS Journal is not yet supported\n");
    exit(1);
}



static void
ntfs_close(FS_INFO * fs)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    free((char *) ntfs->mft);
    free((char *) ntfs->fs);
    fs_data_run_free(ntfs->bmap);
    data_buf_free(ntfs->bmap_buf);
    fs_inode_free(ntfs->mft_inode);
    free(fs);
}




FS_INFO *
ntfs_open(IMG_INFO * img_info, unsigned char ftype, uint8_t test)
{
    char *myname = "ntfs_open";
    NTFS_INFO *ntfs = (NTFS_INFO *) mymalloc(sizeof(*ntfs));
    FS_INFO *fs = &(ntfs->fs_info);
    unsigned int len;

    ntfs->loading_the_MFT = 0;
    ntfs->bmap = NULL;
    ntfs->bmap_buf = NULL;

    if ((ftype & FSMASK) != NTFS_TYPE)
	error("Invalid FS type in ntfs_open");

    fs->ftype = ftype;
    fs->flags = FS_HAVE_SEQ;

    fs->img_info = img_info;

    /* Read the boot sector */
    len = roundup(sizeof(ntfs_sb), NTFS_DEV_BSIZE);
    ntfs->fs = (ntfs_sb *) mymalloc(len);

    if (fs_read_random(fs, (char *) ntfs->fs, len, (OFF_T) 0) != len)
	error("%s: Error reading boot sector: %m", myname);

    /* Check the magic value */
    if (guessu16(fs, ntfs->fs->magic, NTFS_FS_MAGIC)) {
	free(ntfs);
	free(ntfs->fs);
	if (test)
	    return NULL;
	else
	    error("Error: not a NTFS file system");
    }


    /*
     * block calculations : although there are no blocks in ntfs,
     * we are using a cluster as a "block"
     */

    ntfs->ssize_b = getu16(fs, ntfs->fs->ssize);
    if (ntfs->ssize_b % 512) {
	free(ntfs);
	free(ntfs->fs);
	if (test)
	    return NULL;
	else
	    error("Error: not a NTFS file system (invalid sector size)");
    }

    if ((ntfs->fs->csize != 0x01) &&
	(ntfs->fs->csize != 0x02) &&
	(ntfs->fs->csize != 0x04) &&
	(ntfs->fs->csize != 0x08) &&
	(ntfs->fs->csize != 0x10) &&
	(ntfs->fs->csize != 0x20) &&
	(ntfs->fs->csize != 0x40) && (ntfs->fs->csize != 0x80)) {

	free(ntfs);
	free(ntfs->fs);
	if (test)
	    return NULL;
	else
	    error("Error: not a NTFS file system (invalid cluster size)");
    }

    ntfs->csize_b = ntfs->fs->csize * ntfs->ssize_b;
    fs->first_block = 0;

    /* This field is defined as 64-bits but according to the
     * NTFS drivers in Linux, windows only uses 32-bits
     */
    fs->block_count =
	(DADDR_T) getu32(fs, ntfs->fs->vol_size_s) / ntfs->fs->csize;
    fs->last_block = fs->block_count - 1;
    fs->block_size = ntfs->csize_b;
    fs->dev_bsize = NTFS_DEV_BSIZE;


    if (ntfs->fs->mft_rsize_c > 0)
	ntfs->mft_rsize_b = ntfs->fs->mft_rsize_c * ntfs->csize_b;
    else
	/* if the mft_rsize_c is not > 0, then it is -log2(rsize_b) */
	ntfs->mft_rsize_b = 1 << -ntfs->fs->mft_rsize_c;

    if (ntfs->mft_rsize_b % 512) {
	free(ntfs);
	free(ntfs->fs);
	if (test)
	    return NULL;
	else
	    error
		("Error: not a NTFS file system (invalid MFT entry size)");
    }

    if (ntfs->fs->idx_rsize_c > 0)
	ntfs->idx_rsize_b = ntfs->fs->idx_rsize_c * ntfs->csize_b;
    else
	/* if the idx_rsize_c is not > 0, then it is -log2(rsize_b) */
	ntfs->idx_rsize_b = 1 << -ntfs->fs->idx_rsize_c;

    if (ntfs->idx_rsize_b % 512) {
	free(ntfs);
	free(ntfs->fs);
	if (test)
	    return NULL;
	else
	    error
		("Error: not a NTFS file system (invalid idx record size)");
    }

    ntfs->root_mft_addr = getu64(fs, ntfs->fs->mft_clust) * ntfs->csize_b;

    if (getu64(fs, ntfs->fs->mft_clust) > fs->last_block) {
	free(ntfs);
	free(ntfs->fs);
	if (test)
	    return NULL;
	else
	    error
		("Error: not a NTFS file system (invalid starting MFT clust)");
    }

    /*
     * Other initialization: caches, callbacks.
     */
    fs->inode_walk = ntfs_inode_walk;
    fs->block_walk = ntfs_block_walk;
    fs->file_walk = ntfs_file_walk;
    fs->inode_lookup = ntfs_inode_lookup;
    fs->dent_walk = ntfs_dent_walk;
    fs->fsstat = ntfs_fsstat;
    fs->fscheck = ntfs_fscheck;
    fs->istat = ntfs_istat;
    fs->close = ntfs_close;


    /*
     * inode
     */

    /* allocate the buffer to hold mft entries */

    ntfs->mft = (ntfs_mft *) mymalloc(ntfs->mft_rsize_b);
    ntfs->mnum = 0;

    fs->root_inum = NTFS_ROOTINO;
    fs->first_inum = NTFS_FIRSTINO;
    fs->last_inum = NTFS_LAST_DEFAULT_INO;
    ntfs->mft_data = NULL;


    /* load the data run for the MFT table into ntfs->mft */
    ntfs->loading_the_MFT = 1;
    ntfs_dinode_lookup(ntfs, ntfs->mft, NTFS_MFT_MFT);

    ntfs->mft_inode = fs_inode_alloc(NTFS_NDADDR, NTFS_NIADDR);
    ntfs_dinode_copy(ntfs, ntfs->mft_inode);

    /* cache the data attribute 
     *
     * This will likely be done already by proc_attrseq, but this
     * should be quick
     */
    ntfs->mft_data =
	fs_data_lookup_noid(ntfs->mft_inode->attr, NTFS_ATYPE_DATA);

    if (!ntfs->mft_data) {
	free(ntfs->mft);
	free(ntfs);
	free(ntfs->fs);
	if (test)
	    return NULL;
	else
	    error("Data Attribute not found in $MFT");
    }

    /* Get the inode count based on the table size */
    fs->inum_count = ntfs->mft_data->size / ntfs->mft_rsize_b;
    fs->last_inum = fs->inum_count - 1;

    /* reset the flag that we are no longer loading $MFT */
    ntfs->loading_the_MFT = 0;

    /* load the version of the file system */
    ntfs_load_ver(ntfs);

    /* load the data block bitmap data run into ntfs_info */
    ntfs_load_bmap(ntfs);

    /* set this to NULL and it will be loaded if needed */
    ntfs->attrdef = NULL;

    fs->jblk_walk = ntfs_jblk_walk;
    fs->jentry_walk = ntfs_jentry_walk;
    fs->jopen = ntfs_jopen;
    fs->journ_inum = 0;

    if (verbose) {
	fprintf(stderr,
		"ssize: %" PRIu16 " csize: %d serial: %" PRIx64 "\n",
		getu16(fs, ntfs->fs->ssize), ntfs->fs->csize,
		getu64(fs, ntfs->fs->serial));
	fprintf(stderr,
		"mft_rsize: %d idx_rsize: %d vol: %d mft: %" PRIu64
		" mft_mir: %" PRIu64 "\n", ntfs->mft_rsize_b,
		ntfs->idx_rsize_b, (int) fs->block_count, getu64(fs,
								 ntfs->fs->
								 mft_clust),
		getu64(fs, ntfs->fs->mftm_clust));
    }

    return fs;
}
