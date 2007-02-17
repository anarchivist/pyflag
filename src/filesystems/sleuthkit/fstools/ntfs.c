/*
** ntfs
** The Sleuth Kit 
**
** $Date: 2006/12/07 22:02:51 $
**
** Content and meta data layer support for the NTFS file system
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
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
#include "fs_tools_i.h"
#include "ntfs.h"

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
static uint8_t ntfs_proc_attrlist(NTFS_INFO *, FS_INODE *, FS_DATA *);



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
 *
 * Return 0 on success and 1 on error
 */
static uint8_t
ntfs_dinode_lookup(NTFS_INFO * ntfs, ntfs_mft * mft, INUM_T mftnum)
{
    OFF_T mftaddr_b, mftaddr2_b, offset;
    OFF_T mftaddr_len = 0;
    int i;
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;
    FS_DATA_RUN *data_run;
    ntfs_upd *upd;
    uint16_t sig_seq;

    /* sanity checks */
    if (!mft) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L, "mft_lookup: null mft buffer");
	return 1;
    }

    if (mftnum < fs->first_inum) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "mft_lookup: inode number is too small (%" PRIuINUM ")",
	    mftnum);
	return 1;
    }
    if (mftnum > fs->last_inum) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "mft_lookup: inode number is too large (%" PRIuINUM ")",
	    mftnum);
	return 1;
    }


    if (verbose)
	tsk_fprintf(stderr,
	    "ntfs_dinode_lookup: Processing MFT %" PRIuINUM "\n", mftnum);

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
	if (mftnum > NTFS_LAST_DEFAULT_INO) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_ARG;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"Error trying to load a high MFT entry when the MFT itself has not been loaded (%"
		PRIuINUM ")", mftnum);
	    return 1;
	}

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
		    tsk_fprintf(stderr,
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
			tsk_fprintf(stderr,
			    "ntfs_dinode_lookup: Entry crosses run border\n");

		    if (data_run->next == NULL) {
			tsk_error_reset();
			tsk_errno = TSK_ERR_FS_INODE_INT;
			snprintf(tsk_errstr, TSK_ERRSTR_L,
			    "mft_lookup: MFT entry crosses a cluster and there are no more clusters!");
			return 1;
		    }

		    /* Assign address where the remainder of the entry is */
		    mftaddr2_b = data_run->next->addr * ntfs->csize_b;
		    /* this should always be 512, but just in case */
		    mftaddr_len = run_len - offset;
		}

		/* Assign address of where the MFT entry starts */
		mftaddr_b = data_run->addr * ntfs->csize_b + offset;
		if (verbose)
		    tsk_fprintf(stderr,
			"ntfs_dinode_lookup: Entry address at: %"
			PRIuOFF "\n", mftaddr_b);
		break;
	    }

	    /* decrement the offset we are looking for */
	    offset -= run_len;
	}

	/* Did we find it? */
	if (!mftaddr_b) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_INODE_NUM;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"mft_lookup: Error finding MFT entry %"
		PRIuINUM " in $MFT", mftnum);
	    return 1;
	}
    }


    /* can we do just one read or do we need multiple? */
    if (mftaddr2_b) {
	SSIZE_T cnt;
	/* read the first part into mft */
	cnt =
	    fs_read_random(&ntfs->fs_info, (char *) mft,
	    mftaddr_len, mftaddr_b);
	if (cnt != mftaddr_len) {
	    if (cnt != 1) {
		tsk_error_reset();
		tsk_errno = TSK_ERR_FS_READ;
	    }
	    snprintf(tsk_errstr2, TSK_ERRSTR_L,
		"ntfs_dinode_lookup: Error reading MFT Entry (part 1) at %"
		PRIuOFF, mftaddr_b);
	    return 1;
	}

	/* read the second part into mft */
	cnt = fs_read_random
	    (&ntfs->fs_info,
	    (char *) ((uintptr_t) mft + mftaddr_len),
	    ntfs->mft_rsize_b - mftaddr_len, mftaddr2_b);
	if (cnt != ntfs->mft_rsize_b - mftaddr_len) {
	    if (cnt != 1) {
		tsk_error_reset();
		tsk_errno = TSK_ERR_FS_READ;
	    }
	    snprintf(tsk_errstr2, TSK_ERRSTR_L,
		"ntfs_dinode_lookup: Error reading MFT Entry (part 2) at %"
		PRIuOFF, mftaddr2_b);
	    return 1;
	}
    }
    else {
	SSIZE_T cnt;
	/* read the raw entry into mft */
	cnt =
	    fs_read_random(&ntfs->fs_info, (char *) mft,
	    ntfs->mft_rsize_b, mftaddr_b);
	if (cnt != ntfs->mft_rsize_b) {
	    if (cnt != 1) {
		tsk_error_reset();
		tsk_errno = TSK_ERR_FS_READ;
	    }
	    snprintf(tsk_errstr2, TSK_ERRSTR_L,
		"ntfs_dinode_lookup: Error reading MFT Entry at %"
		PRIuOFF, mftaddr_b);
	    return 1;
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
    if ((getu32(fs->endian, mft->magic) != NTFS_MFT_MAGIC)
	&& (getu32(fs->endian, mft->magic) != NTFS_MFT_MAGIC_BAAD)
	&& (getu32(fs->endian, mft->magic) != NTFS_MFT_MAGIC_ZERO)) {
	tsk_errno = TSK_ERR_FS_INODE_INT;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "entry %d has an invalid MFT magic: %x",
	    mftnum, getu32(fs->endian, mft->magic));
	return 1;
    }
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
    if ((getu16(fs->endian,
		mft->upd_cnt) - 1) * ntfs->ssize_b > ntfs->mft_rsize_b) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_GENFS;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "More Update Sequence Entries than MFT size");
	return 1;
    }

    /* Apply the update sequence structure template */
    upd =
	(ntfs_upd *) ((uintptr_t) mft + getu16(fs->endian, mft->upd_off));
    /* Get the sequence value that each 16-bit value should be */
    sig_seq = getu16(fs->endian, upd->upd_val);
    /* cycle through each sector */
    for (i = 1; i < getu16(fs->endian, mft->upd_cnt); i++) {
	uint8_t *new_val, *old_val;
	/* The offset into the buffer of the value to analyze */
	size_t offset = i * ntfs->ssize_b - 2;
	/* get the current sequence value */
	uint16_t cur_seq = getu16(fs->endian, (uintptr_t) mft + offset);
	if (cur_seq != sig_seq) {
	    /* get the replacement value */
	    uint16_t cur_repl =
		getu16(fs->endian, &upd->upd_seq + (i - 1) * 2);
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_GENFS;

	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"Incorrect update sequence value in MFT entry\nSignature Value: 0x%"
		PRIx16 " Actual Value: 0x%" PRIx16
		" Replacement Value: 0x%" PRIx16
		"\nThis is typically because of a corrupted entry",
		sig_seq, cur_seq, cur_repl);
	    return 1;
	}

	new_val = &upd->upd_seq + (i - 1) * 2;
	old_val = (uint8_t *) ((uintptr_t) mft + offset);
	if (verbose)
	    tsk_fprintf(stderr,
		"ntfs_dinode_lookup: upd_seq %i   Replacing: %.4"
		PRIx16 "   With: %.4" PRIx16 "\n", i,
		getu16(fs->endian, old_val), getu16(fs->endian, new_val));
	*old_val++ = *new_val++;
	*old_val = *new_val;
    }

    return 0;
}



/*
 * given a cluster, return the allocation status or
 * -1 if an error occurs
 */
static int
is_clustalloc(NTFS_INFO * ntfs, DADDR_T addr)
{
    int bits_p_clust, b;
    DADDR_T base;
    bits_p_clust = 8 * ntfs->fs_info.block_size;

    /* While we are loading the MFT, assume that everything
     * is allocated.  This should only be needed when we are
     * dealing with an attribute list ... 
     */
    if (ntfs->loading_the_MFT == 1) {
	return 1;
    }
    else if (ntfs->bmap == NULL) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;

	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "is_clustalloc: Bitmap pointer is null: %" PRIuDADDR
	    "\n", addr);
	return -1;
    }

    /* Is the cluster too big? */
    if (addr > ntfs->fs_info.last_block) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_INODE_INT;

	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "is_clustalloc: cluster too large");
	return -1;
    }

    /* identify the base cluster in the bitmap file */
    base = addr / bits_p_clust;
    b = (int) (addr % bits_p_clust);

    /* is this the same as in the cached buffer? */
    if (base != ntfs->bmap_buf_off) {
	DADDR_T c = base;
	FS_DATA_RUN *run;
	DADDR_T fsaddr = 0;
	SSIZE_T cnt;

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

	if (fsaddr == 0) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_BLK_NUM;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"is_clustalloc: cluster not found in bitmap: %"
		PRIuDADDR "", c);
	    return -1;
	}
	if (fsaddr > ntfs->fs_info.last_block) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_BLK_NUM;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"is_clustalloc: Cluster in bitmap too large for image: %"
		PRIuDADDR, fsaddr);
	    return -1;
	}
	ntfs->bmap_buf_off = base;
	cnt = fs_read_block
	    (&ntfs->fs_info, ntfs->bmap_buf,
	    ntfs->fs_info.block_size, fsaddr);
	if (cnt != ntfs->fs_info.block_size) {
	    if (cnt != 1) {
		tsk_error_reset();
		tsk_errno = TSK_ERR_FS_READ;
	    }
	    snprintf(tsk_errstr2, TSK_ERRSTR_L,
		"is_clustalloc: Error reading bitmap at %"
		PRIuDADDR, fsaddr);
	    return -1;
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
 *
 * Returns NULL on error and for Bad clust: Check tsk_errno to test
 */
static FS_DATA_RUN *
ntfs_make_data_run(NTFS_INFO * ntfs,
    ntfs_runlist * runlist, OFF_T * runlen)
{
    FS_INFO *fs = (FS_INFO *) ntfs;
    ntfs_runlist *run;
    FS_DATA_RUN *data_run, *data_run_head = NULL, *data_run_prev = NULL;
    unsigned int i, idx;
    DADDR_T prev_addr = 0;
    run = runlist;

    /* initialize if non-NULL */
    if (runlen)
	*runlen = 0;

    /* Cycle through each run in the runlist 
     * We go until we find an entry with no length
     * An entry with offset of 0 is for a sparse run
     */
    while (NTFS_RUNL_LENSZ(run) != 0) {
	int64_t offset = 0;

	/* allocate a new fs_data_run */
	if ((data_run = fs_data_run_alloc()) == NULL) {
	    return NULL;
	}

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
		tsk_fprintf(stderr,
		    "ntfs_make_data_run: Len idx: %i cur: %"
		    PRIu8 " (%" PRIx8 ") tot: %" PRIuDADDR
		    " (%" PRIxDADDR ")\n", i,
		    run->buf[idx - 1], run->buf[idx - 1],
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
		tsk_fprintf(stderr,
		    "ntfs_make_data_run: Off idx: %i cur: %"
		    PRIu8 " (%" PRIx8 ") tot: %" PRIuDADDR
		    " (%" PRIxDADDR ")\n", i,
		    run->buf[idx - 1], run->buf[idx - 1], offset, offset);
	}

	/* offset value is signed so extend it to 64-bits */
	if ((int8_t) run->buf[idx - 1] < 0) {
	    for (; i < sizeof(offset); i++)
		offset |= (int64_t) ((int64_t) 0xff << (i * 8));
	}

	if (verbose)
	    tsk_fprintf(stderr,
		"ntfs_make_data_run: Signed offset: %"
		PRIdDADDR " Previous address: %"
		PRIdDADDR "\n", offset, prev_addr);

	/* The NT 4.0 version of NTFS uses an offset of -1 to represent
	 * a hole, so add the sparse flag and make it look like the 2K
	 * version with a offset of 0
	 *
	 * A user reported an issue where the $Bad file started with
	 * its offset as -1 and it was not NT (maybe a conversion)
	 * Change the check now to not limit to NT, but make sure
	 * that it is the first run
	 */
	if (((offset == -1) && (prev_addr == 0)) || ((offset == -1)
		&& (ntfs->ver == NTFS_VINFO_NT))) {
	    data_run->flags |= FS_DATA_SPARSE;
	    data_run->addr = 0;
	    if (verbose)
		tsk_fprintf(stderr, "ntfs_make_data_run: Sparse Run\n");
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
		tsk_fprintf(stderr, "ntfs_make_data_run: Sparse Run\n");
	}


	/* Advance run */
	run = (ntfs_runlist *) ((uintptr_t) run + (1 + NTFS_RUNL_LENSZ(run)
		+ NTFS_RUNL_OFFSZ(run)));
    }

    /* special case for $BADCLUST, which is a sparse file whose size is
     * the entire file system.
     *
     * If there is only one run entry and it is sparse, then there are no
     * bad blocks, so get rid of it.
     */
    if ((data_run_head != NULL)
	&& (data_run_head->next == NULL)
	&& (data_run_head->flags & FS_DATA_SPARSE)
	&& (data_run_head->len == fs->last_block + 1)) {
	free(data_run_head);
	data_run_head = NULL;
    }

    return data_run_head;
}



/*********** UNCOMPRESSION CODE *************/


/*
 * NTFS Breaks compressed data into compression units, which are
 * typically 16 clusters in size. If the data in the comp  unit
 * compresses to something smaller than 16 clusters then the
 * compresed data is stored and the rest of the compression unit
 * is filled with sparse clusters. The entire compression unit
 * can also be sparse. 
 *
 * When the data is compressed, it is broken up into 4k blocks. Each
 * of the blocks is compressed and the resulting data is stored with
 * a 2-byte header that identifies the compressed size.   The 
 * compressed data is broken into token groups (which have 8 tokens
 * in them.  Each group starts with a 1 byte header, which has 1 bit
 * for each token.  The bit identifies the type of token.  A symbol
 * type means that the data into the 1 byte token should be copied
 * directly into the uncompressed buffer. The phrase type means gives
 * the start and length of previous sequence of bytes in the same
 * uncompression unit that should be copied to this location. 
 *
 * The TSK implementation of this algorithm is kind of strange in that
 * we focus on what can be uncompressed for a given cluster.  Clusters
 * can be smaller than compression units and sub-blocks, which means that
 * we need to store state from previous clusters and we may encounter
 * situations where the 2-byte header values can cross the clusters
 */



 /* Variables used for ntfs_uncompress() method */
typedef struct {
    char *uncomp_buf;		// Buffer for uncompressed data
    unsigned int uncomp_idx;	// Index into buffer for next byte
    unsigned int uncomp_size_b;	// size of buffer in bytes (1 compression unit)

    unsigned int blk_size;	// size of the current block in comp unit
    unsigned int blk_idx;	// Location in current block (starting at 0)
    unsigned long blk_st;	// Location in uncomp_buf where block started

    uint8_t blk_iscomp;		// 0 if block is not compressed

/* The Block size value is 2 bytes and can cross a cluster boundary,
 * so we may need to store a byte from a previous cluster so that it is 
 * known for the next cluster */
    uint8_t blk_size_ispart;	// 1 if block header was split on cluster
    unsigned char blk_size_lsb;	// The LSB of the block size

/* Similarly, the phrase token header can be split since it is 2 bytes  */
    uint8_t phrase_head_ispart;	// 1 if phrase token header was split on cluster
    unsigned char phrase_head_lsb;	// The LSB of the token header

    uint8_t tag_isnext;		// 1 if next byte is tag header
    unsigned char tag;		// The header of the current tag group

    uint8_t token_idx;		// Index of current token (0 to 7)
} NTFS_COMP_INFO;


/* NTFS Compression state is good for only 1 compression unit */
static void
ntfs_uncompress_reset(NTFS_COMP_INFO * comp)
{
    memset(comp->uncomp_buf, 0, comp->uncomp_size_b);
    comp->uncomp_idx = 0;

    comp->blk_size = 0;
    comp->blk_idx = 0;
    comp->blk_st = 0;
    comp->blk_iscomp = 1;

    comp->blk_size_ispart = 0;
    comp->blk_size_lsb = 0;

    comp->phrase_head_ispart = 0;
    comp->phrase_head_lsb = 0;

    comp->tag_isnext = 0;
    comp->tag = 0;

    comp->token_idx = 0;

}

static int
ntfs_uncompress_setup(FS_INFO * fs, NTFS_COMP_INFO * comp,
    uint32_t compunit_size_c)
{
    comp->uncomp_size_b = fs->block_size * compunit_size_c;
    comp->uncomp_buf = talloc_size(fs, comp->uncomp_size_b);

    if (comp->uncomp_buf == NULL) {
	comp->uncomp_size_b = 0;
	return 1;
    }

    ntfs_uncompress_reset(comp);

    return 0;
}

static void
ntfs_uncompress_done(NTFS_COMP_INFO * comp)
{
    if (comp->uncomp_buf)
	free(comp->uncomp_buf);
    comp->uncomp_buf = NULL;
    comp->uncomp_size_b = 0;
}


 /*
  * Uncompress the data in cl_buffer, which has a size of cl_size.  The
  * result is a pointer to the uncompressed data (which is located in 
  * the NTFS_COMP_INFO structure.  The resulting data has the size of
  * uncompressed_buffer_size.  
  *
  * return 1 on error and 0 on success
  */
static int
ntfs_uncompress(NTFS_COMP_INFO * comp, char *cl_buffer,
    unsigned int cl_size, char **uncompressed_buffer,
    unsigned int *uncompressed_buffer_size)
{
    int uncomp_start_idx = comp->uncomp_idx;
    unsigned int cl_index;

    if (verbose)
	tsk_fprintf(stderr,
	    "ntfs_uncompress: comp_blk_idx: %d  comp_blk_size: %d  tag: %x\n",
	    comp->blk_idx, comp->blk_size, comp->tag);

    /* Cycle through the cluster */
    cl_index = 0;
    while (cl_index < cl_size) {

      get_block_size:

	/* The first two bytes of each block contains the size
	 * information.  Note that blocks need not be on cluster
	 * boundaries.
	 */
	if ((comp->blk_idx == 0) || (comp->blk_idx >= comp->blk_size)) {
	    comp->blk_iscomp = 1;

	    /* This is set if the first byte of the header was in the
	     * previous cluster */
	    if (comp->blk_size_ispart == 1) {
		comp->blk_size_ispart = 0;
		comp->blk_size =
		    ((((unsigned char) cl_buffer[cl_index] << 8) |
			comp->blk_size_lsb)
		    & 0x0FFF) + 3;

		/* The MSB identifies if the block is compressed */
		if ((cl_buffer[cl_index] & 0x8000) == 0)
		    comp->blk_iscomp = 0;

		cl_index++;
	    }
	    /* The full header is in this cluster */
	    else if (cl_index + 1 < cl_size) {
		comp->blk_size =
		    ((((unsigned char) cl_buffer[cl_index +
				1] << 8) | ((unsigned char)
			    cl_buffer[cl_index])) & 0x0FFF) + 3;

		/* The MSB identifies if the block is compressed */
		if ((cl_buffer[cl_index + 1] & 0x8000) == 0)
		    comp->blk_iscomp = 0;

		cl_index += 2;
	    }
	    else {
		comp->blk_size_lsb = cl_buffer[cl_index++];
		comp->blk_size_ispart = 1;
		goto return_buffer;
	    }

	    comp->blk_st = comp->uncomp_idx;
	    comp->blk_idx = 2;
	    comp->tag_isnext = 1;

	    if (verbose)
		tsk_fprintf(stderr, "ntfs_uncompress: Block size is %d\n",
		    comp->blk_size);

	    if (cl_index >= cl_size) {
		goto return_buffer;
	    }

	    // @@@ Is this an error condition -- should it goto finalize block?
	    if (comp->blk_size == 3) {
		goto return_buffer;
	    }

	    /* Some blocks are not compressed, so simply copy them */
	    if (comp->blk_iscomp == 0) {
		if (verbose)
		    tsk_fprintf(stderr,
			"ntfs_uncompress: Block is not compressed\n");
		goto finalize_block;
	    }

	    /* This case seems to occur at the same time as the previous 
	     * and seems to mean the same, so set the compressed flag.
	     */
	    if ((comp->blk_size - 2) == 4096) {
		comp->blk_iscomp = 0;
		goto finalize_block;
	    }
	}
	/* This case happens when the block being process is not compressed.
	 * this will hit for each cluster after the first */
	else if ((comp->blk_idx < comp->blk_size)
	    && (comp->blk_iscomp == 0)) {
	    if (verbose)
		tsk_fprintf(stderr,
		    "ntfs_uncompress: Block is still not compressed\n");
	    goto finalize_block;
	}
	// the else case occurs if we are in the middle of a compressed block


	/* Cycle through this sub-block 
	 * 
	 * Each loop goes into this loop, the condition was 
	 * checked in the previous if statements
	 */
	while (comp->blk_idx < comp->blk_size) {

	    /* Are we expecting the tag header? */
	    if ((comp->tag_isnext == 1) ||
		(comp->token_idx >= NTFS_TOKEN_LENGTH)) {
		comp->tag = (unsigned char) cl_buffer[cl_index];
		comp->tag_isnext = 0;
		comp->token_idx = 0;

		cl_index++;
		comp->blk_idx++;

		if (cl_index >= cl_size) {
		    goto return_buffer;
		}

		if (comp->blk_idx >= comp->blk_size) {
		    goto get_block_size;
		}

		if (verbose)
		    tsk_fprintf(stderr, "ntfs_uncompress: New Tag: %x\n",
			comp->tag);
	    }

	    while (comp->token_idx < NTFS_TOKEN_LENGTH) {

		/* Determine token type and parse appropriately. */

		/* Symbol tokens are the symbol themselves, so copy it
		 * into the umcompressed buffer 
		 */
		if ((comp->tag & NTFS_TOKEN_MASK) == NTFS_SYMBOL_TOKEN) {
		    if (verbose)
			tsk_fprintf(stderr,
			    "ntfs_uncompress: Symbol Token: %d\n",
			    comp->token_idx - 1);
		    if (comp->uncomp_idx >= comp->uncomp_size_b) {
			tsk_error_reset();
			tsk_errno = TSK_ERR_FS_FWALK;
			snprintf(tsk_errstr, TSK_ERRSTR_L,
			    "ntfs_uncompress: Trying to write past end of uncompression buffer: %d",
			    comp->uncomp_idx);
			return 1;
		    }
		    comp->uncomp_buf[comp->uncomp_idx++] =
			cl_buffer[cl_index];

		    /* Advance the tag descriptor */
		    comp->tag >>= 1;
		    if (++comp->token_idx == NTFS_TOKEN_LENGTH)
			comp->tag_isnext = 1;

		    cl_index++;
		    comp->blk_idx++;

		    if (cl_index >= cl_size) {
			goto return_buffer;
		    }
		    else if (comp->blk_idx >= comp->blk_size) {
			goto get_block_size;
		    }
		}

		/* Otherwise, it is a phrase token, which points back
		 * to a previous sequence of bytes.  This is a two byte
		 * value, which may be broken up accross sectors. 
		 */
		else {
		    int i;
		    int shift = 0;
		    unsigned long start_position_index = 0;
		    unsigned long end_position_index = 0;
		    unsigned int offset = 0;
		    unsigned int length = 0;
		    uint16_t pheader;

		    /* Check if the first byte of the header was in the
		     * previous cluster 
		     */
		    if (comp->phrase_head_ispart == 1) {
			pheader =
			    ((((cl_buffer[cl_index]) << 8) & 0xFF00) |
			    (comp->phrase_head_lsb & 0xFF));
			cl_index++;
			comp->blk_idx++;
			comp->phrase_head_ispart = 0;
		    }
		    /* Check if there is only enough room in this cluster
		     * for the first byte of the header */
		    else if (cl_index + 1 >= cl_size) {
			comp->phrase_head_lsb = cl_buffer[cl_index];
			comp->phrase_head_ispart = 1;
			cl_index++;
			comp->blk_idx++;
			goto return_buffer;
		    }
		    /* We have the full header in this cluster */
		    else {
			pheader =
			    ((((cl_buffer[cl_index +
					    1]) << 8) & 0xFF00) |
			    (cl_buffer[cl_index] & 0xFF));
			cl_index += 2;
			comp->blk_idx += 2;
		    }

		    /* Advance the tag descriptor */
		    comp->tag >>= 1;
		    if (++comp->token_idx == NTFS_TOKEN_LENGTH)
			comp->tag_isnext = 1;

		    /* The number of bits for the start and length
		     * in the 2-byte header change depending on the 
		     * location in the compression unit.  This identifies
		     * how many bits each has */
		    for (i =
			comp->uncomp_idx -
			comp->blk_st - 1; i >= 0x10; i >>= 1) {
			shift++;
		    }

//tsk_fprintf(stderr, "Start: %X  Shift: %d  UnComp_IDX %d  BlkStart: %lu  BlkIdx: %d  BlkSize: %d\n", (int)(comp->uncomp_idx - comp->blk_st - 1), shift, comp->uncomp_idx, comp->blk_st, comp->blk_idx, comp->blk_size);

		    offset = (pheader >> (12 - shift)) + 1;
		    length = (pheader & (0xFFF >> shift)) + 2;

		    start_position_index = comp->uncomp_idx - offset;
		    end_position_index = start_position_index + length;

		    if (verbose)
			tsk_fprintf(stderr,
			    "ntfs_uncompress: Phrase Token: %d\t%d\t%d\t%x\n",
			    comp->token_idx - 1, length, offset, pheader);

		    /* Sanity checks on values */
		    if (offset > comp->uncomp_idx) {
			tsk_error_reset();
			tsk_errno = TSK_ERR_FS_FWALK;
			snprintf(tsk_errstr, TSK_ERRSTR_L,
			    "ntfs_uncompress: Phrase token offset is too large:  %d (max: %d)",
			    offset, comp->uncomp_idx);
			return 1;
		    }
		    else if (length + start_position_index >
			comp->uncomp_size_b) {
			tsk_error_reset();
			tsk_errno = TSK_ERR_FS_FWALK;
			snprintf(tsk_errstr, TSK_ERRSTR_L,
			    "ntfs_uncompress: Phrase token length is too large:  %d (max: %lu)",
			    length,
			    comp->uncomp_size_b - start_position_index);
			return 1;
		    }
		    else if (end_position_index - start_position_index +
			1 > comp->uncomp_size_b - comp->uncomp_idx) {
			tsk_error_reset();
			tsk_errno = TSK_ERR_FS_FWALK;
			snprintf(tsk_errstr, TSK_ERRSTR_L,
			    "ntfs_uncompress: Phrase token length is too large for rest of uncomp buf:  %lu (max: %d)",
			    end_position_index - start_position_index + 1,
			    comp->uncomp_size_b - comp->uncomp_idx);
			return 1;
		    }

		    for (; start_position_index <= end_position_index &&
			comp->uncomp_idx < comp->uncomp_size_b;
			start_position_index++) {

			// Copy the previous data to the current position
			comp->uncomp_buf[comp->uncomp_idx++]
			    = comp->uncomp_buf[start_position_index];
		    }

		    if (cl_index >= cl_size) {
			goto return_buffer;
		    }
		    else if (comp->blk_idx >= comp->blk_size) {
			goto get_block_size;
		    }
		}
	    }
	}
    }

  finalize_block:

    /* Copy the rest of the cluster into the uncompressed buffer 
     * 
     * This is used for uncompressed blocks
     */
    for (;
	cl_index < cl_size && comp->blk_idx < comp->blk_size;
	cl_index++, comp->blk_idx++) {

	/* This seems to happen only with corrupt data -- such as
	 * when an unallocated file is being processed... */
	if (comp->uncomp_idx >= comp->uncomp_size_b) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_FWALK;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"ntfs_uncompress: Trying to write past end of uncompression buffer (1) -- corrupt data? cl_index: %du  blk_idx: %du)",
		cl_index, comp->blk_idx);
	    return 1;
	}

	// Place data in uncompression_buffer
	comp->uncomp_buf[comp->uncomp_idx++] = cl_buffer[cl_index];
    }

    if (cl_index < cl_size) {
	goto get_block_size;
    }

  return_buffer:

    *uncompressed_buffer = &(comp->uncomp_buf[uncomp_start_idx]);
    *uncompressed_buffer_size = comp->uncomp_idx - uncomp_start_idx;

    return 0;
}



/* Return 1 on error and 0 on success
 * fsize is updated to reflect the amount of the file remaining
 */
static int
ntfs_proc_compunit(NTFS_INFO * ntfs, NTFS_COMP_INFO * comp, int flags,
    FS_FILE_WALK_FN action, void *ptr, DADDR_T * comp_unit,
    uint32_t comp_unit_size, SSIZE_T * fsize, DATA_BUF * data_buf)
{
    FS_INFO *fs = (FS_INFO *) ntfs;
    unsigned int bufsize;
    int sparse = 1;
    char *buf = data_buf->data;
    int myflags, retval;
    uint64_t a;

    /* With compressed attributes, there are three scenarios.
     * 1: The compression unit is not compressed,
     * 2: The compression unit is sparse
     * 3: The compression unit is compressed
     */

    /* Check if the entire compression unit is sparse */
    for (a = 0; a < comp_unit_size && sparse == 1; a++) {
	if (comp_unit[a]) {
	    sparse = 0;
	    break;
	}
    }

    /* Entire comp unit is sparse... */
    if (sparse) {
	if (verbose)
	    tsk_fprintf(stderr,
		"ntfs_proc_compunit: Unit is fully sparse\n");

	/* If sparse clusters are not wanted, then adjust size
	 * and return */
	if (flags & FS_FLAG_FILE_NOSPARSE) {
	    *fsize -= (comp_unit_size * fs->block_size);
	    return 0;
	}

	if ((flags & FS_FLAG_FILE_AONLY) == 0)
	    memset(buf, 0, fs->block_size);

	myflags =
	    FS_FLAG_DATA_CONT | FS_FLAG_DATA_ALLOC | FS_FLAG_DATA_SPARSE |
	    FS_FLAG_DATA_COMP;

	for (a = 0; a < comp_unit_size && *fsize > 0; a++) {

	    /* Do we read a full block, or just the remainder? */
	    if ((OFF_T) fs->block_size < *fsize)
		bufsize = fs->block_size;
	    else
		bufsize = (int) *fsize;

	    retval = action(fs, 0, buf, bufsize, myflags, ptr);
	    *fsize -= bufsize;
	    if (retval == WALK_STOP) {
		return 0;
	    }
	    else if (retval == WALK_ERROR) {
		return 1;
	    }
	}
	return 0;
    }

    /* Check if the end of the unit is sparse, which means the
     * unit is compressed */
    else if (comp_unit[comp_unit_size - 1] == 0) {
	char *uncompressed_buffer = NULL;
	unsigned int uncompressed_buffer_size = 0;

	if (verbose)
	    tsk_fprintf(stderr,
		"ntfs_proc_compunit: Unit is compressed\n");

	ntfs_uncompress_reset(comp);

	for (a = 0; a < comp_unit_size && *fsize > 0; a++) {
	    SSIZE_T cnt;

	    if (comp_unit[a] == 0)
		break;

	    /* To get the uncompressed size, we must uncompress the
	     * data -- even if addresses are only needed */

	    cnt = fs_read_block
		(fs, data_buf, fs->block_size, comp_unit[a]);
	    if (cnt != fs->block_size) {
		if (cnt != 1) {
		    tsk_error_reset();
		    tsk_errno = TSK_ERR_FS_READ;
		}
		snprintf(tsk_errstr2, TSK_ERRSTR_L,
		    "ntfs_proc_compunit: Error reading block at %"
		    PRIuDADDR, comp_unit[a]);
		return 1;
	    }

	    uncompressed_buffer = NULL;
	    uncompressed_buffer_size = 0;

	    if (ntfs_uncompress(comp, buf, fs->block_size,
		    &uncompressed_buffer, &uncompressed_buffer_size)) {
		if (flags & FS_FLAG_FILE_RECOVER) {
		    // reset the flag
		    tsk_errno = TSK_ERR_FS_RECOVER;
		}
		return 1;
	    }

	    myflags = FS_FLAG_DATA_CONT | FS_FLAG_DATA_COMP;
	    retval = is_clustalloc(ntfs, comp_unit[a]);
	    if (retval == -1) {
		if (flags & FS_FLAG_FILE_RECOVER) {
		    // reset the flag
		    tsk_errno = TSK_ERR_FS_RECOVER;
		}
		return 1;
	    }
	    else if (retval == 1) {
		myflags |= FS_FLAG_DATA_ALLOC;
	    }
	    else if (retval == 0) {
		myflags |= FS_FLAG_DATA_UNALLOC;
	    }

	    retval =
		action(fs, comp_unit[a], uncompressed_buffer,
		uncompressed_buffer_size, myflags, ptr);
	    *fsize -= uncompressed_buffer_size;

	    if (retval == WALK_STOP) {
		return 0;
	    }
	    else if (retval == WALK_ERROR) {
		return 1;
	    }
	}

	/* If they want the sparse clusters, then we call the action 
	 * with no data and no size -- this helps to account for how
	 * many clusters would be needed for the file */
	if ((flags & FS_FLAG_FILE_NOSPARSE) == 0) {
	    for (; a < comp_unit_size && *fsize > 0; a++) {
		char tmp[1] = { 0 };
		myflags =
		    FS_FLAG_DATA_CONT | FS_FLAG_DATA_ALLOC |
		    FS_FLAG_DATA_SPARSE | FS_FLAG_DATA_COMP;
		retval = action(fs, 0, tmp, 0, myflags, ptr);
		if (retval == WALK_STOP) {
		    return 0;
		}
		else if (retval == WALK_ERROR) {
		    return 1;
		}
	    }
	}

	return 0;
    }

    /* Uncompressed data */
    else {

	if (verbose)
	    tsk_fprintf(stderr,
		"ntfs_proc_compunit: Unit is not compressed\n");

	for (a = 0; a < comp_unit_size && *fsize > 0; a++) {
	    if ((flags & FS_FLAG_FILE_AONLY) == 0) {
		SSIZE_T cnt;

		cnt = fs_read_block
		    (fs, data_buf, fs->block_size, comp_unit[a]);
		if (cnt != fs->block_size) {
		    if (cnt != 1) {
			tsk_error_reset();
			tsk_errno = TSK_ERR_FS_READ;
		    }
		    snprintf(tsk_errstr2, TSK_ERRSTR_L,
			"ntfs_proc_compunit: Error reading block at %"
			PRIuDADDR, comp_unit[a]);
		    return 1;
		}
	    }

	    /* Do we want to return a full block, or just the remainder? */
	    if ((OFF_T) fs->block_size < *fsize)
		bufsize = fs->block_size;
	    else
		bufsize = (int) *fsize;

	    myflags = FS_FLAG_DATA_CONT | FS_FLAG_DATA_COMP;
	    retval = is_clustalloc(ntfs, comp_unit[a]);
	    if (retval == -1) {
		if (flags & FS_FLAG_FILE_RECOVER)
		    tsk_errno = TSK_ERR_FS_RECOVER;
		return 1;
	    }
	    else if (retval == 1) {
		myflags |= FS_FLAG_DATA_ALLOC;
	    }
	    else if (retval == 0) {
		myflags |= FS_FLAG_DATA_UNALLOC;
	    }

	    retval = action(fs, comp_unit[a], buf, bufsize, myflags, ptr);
	    *fsize -= bufsize;
	    if (retval == WALK_STOP) {
		return 0;
	    }
	    else if (retval == WALK_ERROR) {
		return 1;
	    }
	}
	return 0;
    }
}


/*
 * Perform a walk on a given FS_DATA list.  The _action_ function is
 * called on each cluster of the run.  
 *
 * This gives us an interface to call an action on data and not care if
 * it is resident or not.
 *
 * used flag values: FS_FLAG_FILE_AONLY, FS_FLAG_FILE_SLACK, 
 * FS_FLAG_FILE_NOSPARSE
 *
 * If FS_FLAG_FILE_RECOVER is set, then error codes are set to _RECOVER
 * so that errors can be more easily suppressed.  No special recovery logic
 * exists in this code. 
 *
 * Action uses: FS_FLAG_DATA_CONT
 *
 * No notion of META
 *
 * returns 1 on error and 0 on success
 */
uint8_t
ntfs_data_walk(NTFS_INFO * ntfs, INUM_T inum,
    FS_DATA * fs_data, int flags, FS_FILE_WALK_FN action, void *ptr)
{
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;
    int myflags;
    int retval;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (verbose)
	tsk_fprintf(stderr,
	    "ntfs_data_walk: Processing file %" PRIuINUM "\n", inum);
    /* Process the resident buffer 
     */
    if (fs_data->flags & FS_DATA_RES) {
	char *buf = NULL;
	if ((buf = mymalloc((size_t) fs_data->size)) == NULL) {
	  return 1;
	}
	memcpy(buf, fs_data->buf, (size_t) fs_data->size);

	myflags =
	    FS_FLAG_DATA_CONT | FS_FLAG_DATA_ALLOC | FS_FLAG_DATA_RES;
	retval =
	    action(fs, ntfs->root_mft_addr, buf,
	    (unsigned int) fs_data->size, myflags, ptr);
	if (retval == WALK_STOP) {
		free(buf);
	    return 0;
	}
	else if (retval == WALK_ERROR) {
		free(buf);
	    return 1;
	}
	    free(buf);
    }
    /* Process the compressed buffer */
    else if (fs_data->flags & FS_DATA_COMP) {
	unsigned int a;
	DADDR_T addr;
	DATA_BUF *data_buf = NULL;
	SSIZE_T fsize;
	FS_DATA_RUN *fs_data_run;
	DADDR_T *comp_unit;
	uint32_t comp_unit_idx = 0;
	NTFS_COMP_INFO comp;

	if (fs_data->compsize == 0) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_ARG;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"Compression unit size is 0");
	    return 1;
	}

	if (ntfs_uncompress_setup(fs, &comp, fs_data->compsize)) {
	    return 1;
	}

	comp_unit =
	    (DADDR_T *) mymalloc(fs_data->compsize * sizeof(DADDR_T));
	if (comp_unit == NULL) {
	    ntfs_uncompress_done(&comp);
	    return 1;
	}

	fsize = (SSIZE_T) fs_data->size;

	if ((data_buf = data_buf_alloc(fs->block_size)) == NULL) {
	    ntfs_uncompress_done(&comp);
	    return 1;
	}

	/* cycle through the number of runs we have */
	fs_data_run = fs_data->run;
	while (fs_data_run) {

	    /* We may get a FILLER entry at the beginning of the run
	     * if we are processing a non-base file record because
	     * this $DATA attribute could not be the first in the bigger
	     * attribute. Therefore, do not error if it starts at 0 */
	    if (fs_data_run->flags & FS_DATA_FILLER) {
		if (fs_data_run->addr != 0) {
		    tsk_error_reset();

		    if (flags & FS_FLAG_FILE_RECOVER)
			tsk_errno = TSK_ERR_FS_RECOVER;
		    else
			tsk_errno = TSK_ERR_FS_GENFS;
		    snprintf(tsk_errstr, TSK_ERRSTR_L,
			"Filler Entry exists in fs_data_run %"
			PRIuDADDR "@%" PRIuDADDR
			" - type: %" PRIu32 "  id: %d", fs_data_run->len,
			fs_data_run->addr, fs_data->type, fs_data->id);
		    free(comp_unit);
		    ntfs_uncompress_done(&comp);
		    return 1;
		}
		else {
		    fs_data_run = fs_data_run->next;
		}
	    }

	    addr = fs_data_run->addr;

	    /* cycle through each cluster in the run */
	    for (a = 0; a < fs_data_run->len && fsize > 0; a++) {

		if (addr > fs->last_block) {
		    tsk_error_reset();

		    if (flags & FS_FLAG_FILE_RECOVER)
			tsk_errno = TSK_ERR_FS_RECOVER;
		    else
			tsk_errno = TSK_ERR_FS_BLK_NUM;
		    snprintf(tsk_errstr, TSK_ERRSTR_L,
			"Invalid address in run (too large): %"
			PRIuDADDR "", addr);

		    free(comp_unit);
		    ntfs_uncompress_done(&comp);
		    return 1;
		}

		comp_unit[comp_unit_idx++] = addr;
		if (comp_unit_idx == fs_data->compsize) {
		    if (ntfs_proc_compunit(ntfs, &comp, flags, action, ptr,
			    comp_unit, comp_unit_idx, &fsize, data_buf)) {
			free(comp_unit);
			ntfs_uncompress_done(&comp);
			return 1;
		    }
		    comp_unit_idx = 0;
		}

		/* If it is a sparse run, don't increment the addr so that
		 * it always reads 0 */
		if ((fs_data_run->flags & FS_DATA_SPARSE) == 0)
		    addr++;
	    }

	    /* advance to the next run */
	    fs_data_run = fs_data_run->next;
	}

	if (comp_unit_idx != 0) {
	    if (ntfs_proc_compunit(ntfs, &comp, flags, action, ptr,
		    comp_unit, comp_unit_idx, &fsize, data_buf)) {
		ntfs_uncompress_done(&comp);
		free(comp_unit);
		return 1;
	    }
	}

	data_buf_free(data_buf);
	ntfs_uncompress_done(&comp);
	free(comp_unit);
    }

    /* non-resident */
    else {
	unsigned int a, bufsize;
	DADDR_T addr;
	DATA_BUF *data_buf = NULL;
	char *buf = NULL;
	OFF_T fsize;
	FS_DATA_RUN *fs_data_run;

	/* if we want the slack space too, then use the runlen  */
	if (flags & FS_FLAG_FILE_SLACK)
	    fsize = fs_data->runlen;
	else
	    fsize = fs_data->size;

	if ((flags & FS_FLAG_FILE_AONLY) == 0) {
	    if ((data_buf = data_buf_alloc(fs->block_size)) == NULL) {
		return 1;
	    }
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
		if (fs_data_run->addr != 0) {
		    tsk_error_reset();
		    if (flags & FS_FLAG_FILE_RECOVER)
			tsk_errno = TSK_ERR_FS_RECOVER;
		    else
			tsk_errno = TSK_ERR_FS_GENFS;
		    snprintf(tsk_errstr, TSK_ERRSTR_L,
			"Filler Entry exists in fs_data_run %"
			PRIuDADDR "@%" PRIuDADDR
			" - type: %" PRIu32 "  id: %d", fs_data_run->len,
			fs_data_run->addr, fs_data->type, fs_data->id);
		    return 1;
		}
		else {
		    fs_data_run = fs_data_run->next;
		}
	    }

	    addr = fs_data_run->addr;
	    /* cycle through each cluster in the run */
	    for (a = 0; a < fs_data_run->len && fsize > 0; a++) {

		/* If the address is too large then give an error */
		if (addr > fs->last_block) {
		    tsk_error_reset();
		    if (flags & FS_FLAG_FILE_RECOVER)
			tsk_errno = TSK_ERR_FS_RECOVER;
		    else
			tsk_errno = TSK_ERR_FS_BLK_NUM;
		    snprintf(tsk_errstr, TSK_ERRSTR_L,
			"Invalid address in run (too large): %"
			PRIuDADDR "", addr);
		    return 1;
		}

		if ((flags & FS_FLAG_FILE_AONLY) == 0) {
		    SSIZE_T cnt;

		    /* sparse files just get 0s */
		    if (fs_data_run->flags & FS_DATA_SPARSE) {
			memset(buf, 0, fs->block_size);
		    }
		    else {
			cnt = fs_read_block
			    (fs, data_buf, fs->block_size, addr);
			if (cnt != fs->block_size) {
			    if (cnt != 1) {
				tsk_error_reset();
				tsk_errno = TSK_ERR_FS_READ;
			    }
			    snprintf(tsk_errstr2, TSK_ERRSTR_L,
				"ntfs_data_walk: Error reading block at %"
				PRIuDADDR, addr);
			    return 1;
			}
		    }
		}

		/* Do we want to return a full block, or just the remainder? */
		if ((OFF_T) fs->block_size < fsize)
		    bufsize = fs->block_size;
		else
		    bufsize = (int) fsize;

		myflags = FS_FLAG_DATA_CONT;
		retval = is_clustalloc(ntfs, addr);
		if (retval == -1) {
		    if ((flags & FS_FLAG_FILE_AONLY) == 0)
			data_buf_free(data_buf);
		    return 1;
		}
		else if (retval == 1) {
		    myflags |= FS_FLAG_DATA_ALLOC;
		}
		else if (retval == 0) {
		    myflags |= FS_FLAG_DATA_UNALLOC;
		}

		if (fs_data_run->flags & FS_DATA_SPARSE)
		    myflags |= FS_FLAG_DATA_SPARSE;

		/* Only do sparse clusters if NOSPARSE is not set */
		if (((fs_data_run->flags & FS_DATA_SPARSE) &&
			(0 == (flags & FS_FLAG_FILE_NOSPARSE))) ||
		    ((fs_data_run->flags & FS_DATA_SPARSE) == 0)) {


		    retval = action(fs, addr, buf, bufsize, myflags, ptr);
		    if (retval == WALK_STOP) {
			if ((flags & FS_FLAG_FILE_AONLY) == 0)
			    data_buf_free(data_buf);
			return 0;
		    }
		    else if (retval == WALK_ERROR) {
			if ((flags & FS_FLAG_FILE_AONLY) == 0)
			    data_buf_free(data_buf);
			return 1;
		    }
		}

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
    }

    return 0;
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
 * return 1 on eror and 0 on success
 */
static uint8_t
ntfs_proc_attrseq(NTFS_INFO * ntfs,
    FS_INODE * fs_inode, ntfs_attr * attrseq, size_t len)
{
    ntfs_attr *attr = attrseq;
    FS_DATA *fs_data_attrl = NULL, *fs_data = NULL;
    char name[NTFS_MAXNAMLEN_UTF8 + 1];
    OFF_T runlen;
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;

    if (verbose)
	tsk_fprintf(stderr,
	    "ntfs_proc_attrseq: Processing entry %"
	    PRIuINUM "\n", fs_inode->addr);

    /* Cycle through the list of attributes */
    for (; ((uintptr_t) attr >= (uintptr_t) attrseq)
	&& ((uintptr_t) attr <= ((uintptr_t) attrseq + len))
	&& (getu32(fs->endian, attr->len) > 0
	    && (getu32(fs->endian, attr->type) !=
		0xffffffff));
	attr =
	(ntfs_attr *) ((uintptr_t) attr + getu32(fs->endian, attr->len))) {

	UTF16 *name16;
	UTF8 *name8;
	int retVal;

	/* Get the type of this attribute */
	uint32_t type = getu32(fs->endian, attr->type);

	/* Copy the name and convert it to UTF8 */
	if (attr->nlen) {
	    int i;

	    name16 =
		(UTF16 *) ((uintptr_t) attr + getu16(fs->endian,
		    attr->name_off));
	    name8 = (UTF8 *) name;
	    retVal =
		tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
		(UTF16 *) ((uintptr_t) name16 +
		    attr->nlen * 2),
		&name8,
		(UTF8 *) ((uintptr_t) name8 +
		    sizeof(name)), lenientConversion);

	    if (retVal != conversionOK) {
		if (verbose)
		    tsk_fprintf(stderr,
			"ntfs_proc_attrseq: Error converting NTFS attribute name to UTF8: %d %"
			PRIuINUM, retVal, fs_inode->addr);
		*name = '\0';
	    }

	    /* Make sure it is NULL Terminated */
	    else if ((uintptr_t) name8 > (uintptr_t) name + sizeof(name))
		name[sizeof(name)] = '\0';
	    else
		*name8 = '\0';

	    /* Clean up name */
	    i = 0;
	    while (name[i] != '\0') {
		if (TSK_IS_CNTRL(name[i]))
		    name[i] = '^';
		i++;
	    }
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
		tsk_fprintf(stderr,
		    "ntfs_proc_attrseq: Resident Attribute in %"
		    PRIuINUM " Type: %" PRIu32 " Id: %"
		    PRIu16 " Name: %s\n", ntfs->mnum,
		    type, getu16(fs->endian, attr->id), name);

	    /* Add this resident stream to the fs_inode->attr list */
	    fs_inode->attr =
		fs_data_put_str(fs_inode->attr, name, type,
		getu16(fs->endian, attr->id),
		(void *) ((uintptr_t) attr +
		    getu16(fs->endian,
			attr->c.r.soff)), getu32(fs->endian,
		    attr->c.r.ssize));

	    if (fs_inode->attr == NULL) {
		strncat(tsk_errstr2, " - proc_attrseq",
		    TSK_ERRSTR_L - strlen(tsk_errstr2));
		return 1;
	    }
	}
	/* For non-resident attributes, we will copy the runlist
	 * to the generic form and then save it in the FS_INODE->attr
	 * list
	 */
	else {
	    FS_DATA_RUN *fs_data_run;
	    uint8_t data_flag = 0;
	    uint16_t id = getu16(fs->endian, attr->id);
	    uint32_t compsize = 0;

	    if (verbose)
		tsk_fprintf(stderr,
		    "ntfs_proc_attrseq: Non-Resident Attribute in %"
		    PRIuINUM " Type: %" PRIu32 " Id: %"
		    PRIu16 " Name: %s  Start VCN: %"
		    PRIu64 "\n", ntfs->mnum, type, id,
		    name, getu64(fs->endian, attr->c.nr.start_vcn));

	    /* convert the run to generic form */
	    if ((fs_data_run = ntfs_make_data_run(ntfs,
			(ntfs_runlist *) ((uintptr_t)
			    attr + getu16(fs->endian, attr->c.nr.run_off)),
			&runlen)) == NULL) {
		if (tsk_errno != 0) {
		    strncat(tsk_errstr2, " - proc_attrseq",
			TSK_ERRSTR_L - strlen(tsk_errstr2));
		    return 1;
		}
	    }

	    /* Determine the flags based on compression and stuff */
	    data_flag = 0;
	    if (getu16(fs->endian, attr->flags) & NTFS_ATTR_FLAG_COMP) {
		data_flag |= FS_DATA_COMP;
		fs_inode->flags |= FS_FLAG_META_COMP;
	    }

	    if (getu16(fs->endian, attr->flags) & NTFS_ATTR_FLAG_ENC)
		data_flag |= FS_DATA_ENC;

	    if (getu16(fs->endian, attr->flags) & NTFS_ATTR_FLAG_SPAR)
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
	     * We could also check for a start_vcn if this does
	     * not fix the problem
	     */
	    if (id == 0) {
		FS_DATA *fs_data2;

		for (fs_data2 = fs_inode->attr;
		    fs_data2 != NULL; fs_data2 = fs_data2->next) {

		    if ((fs_data2->flags & FS_DATA_INUSE) == 0)
			continue;

		    /* We found an attribute with the same name and type */
		    if ((fs_data2->type == type) &&
			(strcmp(fs_data2->name, name) == 0)) {
			id = fs_data2->id;
			if (verbose)
			    tsk_fprintf(stderr,
				"ntfs_proc_attrseq: Updating id from 0 to %"
				PRIu16 "\n", id);
			break;
		    }
		}
	    }

	    /* the compression unit size is stored in the header
	     * it is stored as the power of 2 (if it is not 0)
	     */
	    if (getu16(fs->endian, attr->c.nr.compusize) > 0) {
		compsize = 1 << (getu16(fs->endian, attr->c.nr.compusize));
	    }
	    else {
		compsize = 0;
	    }

	    /* Add the run to the list */
	    if ((fs_inode->attr =
		    fs_data_put_run(fs_inode->attr,
			getu64(fs->endian,
			    attr->c.nr.start_vcn),
			runlen, fs_data_run, name,
			type, id, getu64(fs->endian, attr->c.nr.ssize),
			data_flag, compsize)) == NULL) {

		strncat(tsk_errstr2, " - proc_attrseq: put run",
		    TSK_ERRSTR_L - strlen(tsk_errstr2));
		return 1;
	    }
	}


	/* 
	 * Special Cases, where we grab additional information
	 * regardless if they are resident or not
	 */

	/* Standard Information (is always resident) */
	if (type == NTFS_ATYPE_SI) {
	    ntfs_attr_si *si;
	    if (attr->res != NTFS_MFT_RES) {
		tsk_error_reset();
		tsk_errno = TSK_ERR_FS_INODE_INT;
		snprintf(tsk_errstr, TSK_ERRSTR_L,
		    "proc_attrseq: Standard Information Attribute is not resident!");
		return 1;
	    }
	    si = (ntfs_attr_si *) ((uintptr_t) attr +
		getu16(fs->endian, attr->c.r.soff));
	    fs_inode->mtime = nt2unixtime(getu64(fs->endian, si->mtime));
	    fs_inode->atime = nt2unixtime(getu64(fs->endian, si->atime));
	    fs_inode->ctime = nt2unixtime(getu64(fs->endian, si->ctime));
	    fs_inode->crtime = nt2unixtime(getu64(fs->endian, si->crtime));
	    fs_inode->uid = getu32(fs->endian, si->own_id);
	    fs_inode->mode |= (MODE_IXUSR | MODE_IXGRP | MODE_IXOTH);
	    if ((getu32(fs->endian, si->dos) & NTFS_SI_RO) == 0)
		fs_inode->mode |= (MODE_IRUSR | MODE_IRGRP | MODE_IROTH);
	    if ((getu32(fs->endian, si->dos) & NTFS_SI_HID) == 0)
		fs_inode->mode |= (MODE_IWUSR | MODE_IWGRP | MODE_IWOTH);
	}

	/* File Name (always resident) */
	else if (type == NTFS_ATYPE_FNAME) {
	    ntfs_attr_fname *fname;
	    FS_NAME *fs_name;
	    UTF16 *name16;
	    UTF8 *name8;
	    if (attr->res != NTFS_MFT_RES) {
		tsk_error_reset();
		tsk_errno = TSK_ERR_FS_INODE_INT;
		snprintf(tsk_errstr, TSK_ERRSTR_L,
		    "proc_attr_seq: File Name Attribute is not resident!");
		return 1;
	    }
	    fname =
		(ntfs_attr_fname *) ((uintptr_t) attr +
		getu16(fs->endian, attr->c.r.soff));
	    if (fname->nspace == NTFS_FNAME_DOS) {
		continue;
	    }

	    /* Seek to the end of the fs_name structures in FS_INODE */
	    if (fs_inode->name) {
		for (fs_name = fs_inode->name;
		    (fs_name) && (fs_name->next != NULL);
		    fs_name = fs_name->next) {
		}

		/* add to the end of the existing list */
		fs_name->next = (FS_NAME *) talloc_size(fs_name, sizeof(FS_NAME));
		if (fs_name->next == NULL) {
		    return 1;
		}
		fs_name = fs_name->next;
		fs_name->next = NULL;
	    }
	    else {
		/* First name, so we start a list */
		fs_inode->name = fs_name =
		  (FS_NAME *) talloc_size(fs_inode, sizeof(FS_NAME));
		if (fs_name == NULL) {
		    return 1;
		}
		fs_name->next = NULL;
	    }

	    name16 = (UTF16 *) & fname->name;
	    name8 = (UTF8 *) fs_name->name;
	    retVal =
		tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
		(UTF16 *) ((uintptr_t) name16 +
		    fname->nlen * 2),
		&name8,
		(UTF8 *) ((uintptr_t) name8 +
		    sizeof(fs_name->name)), lenientConversion);
	    if (retVal != conversionOK) {
		if (verbose)
		    tsk_fprintf(stderr,
			"proc_attr_seq: Error converting NTFS name in $FNAME to UTF8: %d",
			retVal);
		*name8 = '\0';
	    }
	    /* Make sure it is NULL Terminated */
	    else if ((uintptr_t) name8 >
		(uintptr_t) fs_name->name + sizeof(fs_name->name))
		fs_name->name[sizeof(fs_name->name)] = '\0';
	    else
		*name8 = '\0';

	    fs_name->par_inode = getu48(fs->endian, fname->par_ref);
	    fs_name->par_seq = getu16(fs->endian, fname->par_seq);
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
		tsk_error_reset();
		tsk_errno = TSK_ERR_FS_FUNC;
		snprintf(tsk_errstr, TSK_ERRSTR_L,
		    "Multiple instances of attribute lists in the same MFT\n"
		    "I didn't realize that could happen, contact the developers");
		return 1;
	    }
	    fs_data_attrl = fs_data_lookup(fs_inode->attr,
		NTFS_ATYPE_ATTRLIST, getu16(fs->endian, attr->id));
	    if (fs_data_attrl == NULL) {
		strncat(tsk_errstr2,
		    " - proc_attrseq: getting attribute list",
		    TSK_ERRSTR_L - strlen(tsk_errstr2));
		return 1;
	    }
	}
    }


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
		tsk_error_reset();
		tsk_errno = TSK_ERR_FS_GENFS;
		snprintf(tsk_errstr, TSK_ERRSTR_L,
		    "$Data not found while loading the MFT");
		return 1;
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
    if (fs_data_attrl) {
	if (ntfs_proc_attrlist(ntfs, fs_inode, fs_data_attrl)) {
	    return 1;
	}
    }

    return 0;
}



/********   Attribute List Action and Function ***********/


/*
 * Attribute lists are used when all of the attribute  headers can not
 * fit into one MFT entry.  This contains an entry for every attribute
 * and where they are located.  We process this to get the locations
 * and then call proc_attrseq on each of those, which adds the data
 * to the fs_inode structure.
 *
 * Return 1 on error and 0 on success
 */
static uint8_t
ntfs_proc_attrlist(NTFS_INFO * ntfs,
    FS_INODE * fs_inode, FS_DATA * fs_data_attrlist)
{
    ntfs_attrlist *list;
    char *buf;
    uintptr_t endaddr;
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;
    ntfs_mft *mft;
    FS_LOAD_FILE load_file;
    INUM_T hist[256];
    uint16_t histcnt = 0;

    if (verbose)
	tsk_fprintf(stderr,
	    "ntfs_proc_attrlist: Processing entry %"
	    PRIuINUM "\n", fs_inode->addr);

    if ((mft = (ntfs_mft *) mymalloc(ntfs->mft_rsize_b)) == NULL) {
	return 1;
    }

    /* Clear the contents of the history buffer */
    memset(hist, 0, sizeof(hist));

    /* add ourselves to the history */
    hist[histcnt++] = ntfs->mnum;

    /* Get a copy of the attribute list stream using the above action */
    load_file.left = load_file.total = (size_t) fs_data_attrlist->size;
    load_file.base = load_file.cur = buf =
	mymalloc((size_t) fs_data_attrlist->size);
    if (buf == NULL) {
	free(mft);
	return 1;
    }
    endaddr = (uintptr_t) buf + (uintptr_t) fs_data_attrlist->size;
    if (ntfs_data_walk(ntfs, ntfs->mnum,
	    fs_data_attrlist, 0, load_file_action, (void *) &load_file)) {
	strncat(tsk_errstr2, " - processing attrlist",
	    TSK_ERRSTR_L - strlen(tsk_errstr2));
	free(mft);
	return 1;
    }

    /* this value should be zero, if not then we didn't read all of the
     * buffer
     */
    if (load_file.left > 0) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_FWALK;
	snprintf(tsk_errstr2, TSK_ERRSTR_L,
	    "processing attrlist of entry %" PRIuINUM, ntfs->mnum);
	free(mft);
	free(buf);
	return 1;
    }


    /* Process the list & and call ntfs_proc_attr */
    for (list = (ntfs_attrlist *) buf;
	(list) && ((uintptr_t) list < endaddr)
	&& (getu16(fs->endian, list->len) > 0);
	list =
	(ntfs_attrlist *) ((uintptr_t) list + getu16(fs->endian,
		list->len))) {
	INUM_T mftnum;
	uint32_t type;
	uint16_t id, i;
	/* Which MFT is this attribute in? */
	mftnum = getu48(fs->endian, list->file_ref);
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
	type = getu32(fs->endian, list->type);
	id = getu16(fs->endian, list->id);
	if (verbose)
	    tsk_fprintf(stderr,
		"ntfs_proc_attrlist: mft: %" PRIuINUM
		" type %" PRIu32 " id %" PRIu16
		"  VCN: %" PRIu64 "\n", mftnum, type,
		id, getu64(fs->endian, list->start_vcn));
	/* 
	 * Read the MFT entry 
	 */
	/* Sanity check. */
	if (mftnum < ntfs->fs_info.first_inum ||
	    mftnum > ntfs->fs_info.last_inum) {

	    if (verbose) {
		/* this case can easily occur if the attribute list was non-resident and the cluster has been reallocated */

		tsk_fprintf(stderr,
		    "Invalid MFT file reference (%"
		    PRIuINUM
		    ") in the unallocated attribute list of MFT %"
		    PRIuINUM "", mftnum, ntfs->mnum);
	    }

	    continue;
	}

	if (ntfs_dinode_lookup(ntfs, mft, mftnum)) {
	    free(mft);
	    free(buf);
	    strncat(tsk_errstr2, " - proc_attrlist",
		TSK_ERRSTR_L - strlen(tsk_errstr2));
	    return 1;
	}

	/* verify that this entry refers to the original one */
	if (getu48(fs->endian, mft->base_ref) != ntfs->mnum) {

	    /* Before we raise alarms, check if the original was
	     * unallocated.  If so, then the list entry could 
	     * have been reallocated, so we will just ignore it
	     */
	    if ((getu16(fs->endian,
			ntfs->mft->flags) & NTFS_MFT_INUSE) == 0) {
		continue;
	    }
	    else {
		tsk_error_reset();
		tsk_errno = TSK_ERR_FS_INODE_INT;
		snprintf(tsk_errstr, TSK_ERRSTR_L,
		    "Extension record %" PRIuINUM
		    " (file ref = %" PRIuINUM
		    ") is not for attribute list of %"
		    PRIuINUM "", mftnum, getu48(fs->endian,
			mft->base_ref), ntfs->mnum);
		free(mft);
		free(buf);
		return 1;
	    }
	}
	/* 
	 * Process the attribute seq for this MFT entry and add them
	 * to the FS_INODE structure
	 */

	if (ntfs_proc_attrseq(ntfs, fs_inode, (ntfs_attr *) ((uintptr_t)
		    mft +
		    getu16(fs->endian,
			mft->
			attr_off)),
		ntfs->mft_rsize_b - getu16(fs->endian, mft->attr_off))) {
	    strncat(tsk_errstr2, "- proc_attrlist",
		TSK_ERRSTR_L - strlen(tsk_errstr2));
	    free(mft);
	    free(buf);
	    return 1;
	}
    }

    free(mft);
    free(buf);
    return 0;
}



/*
 * Copy the MFT entry saved in ntfs->mft into the generic structure 
 */
static uint8_t
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
    fs_inode->nlink = getu16(fs->endian, mft->link);
    fs_inode->seq = getu16(fs->endian, mft->seq);
    fs_inode->addr = ntfs->mnum;

    /* Set the mode for file or directory */
    if (getu16(fs->endian, ntfs->mft->flags) & NTFS_MFT_DIR)
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
    fs_inode->flags =
	((getu16(fs->endian, ntfs->mft->flags) &
	    NTFS_MFT_INUSE) ? FS_FLAG_META_ALLOC : FS_FLAG_META_UNALLOC);

    /* MFT entries are only allocated when needed, so it has been used */
    fs_inode->flags |= FS_FLAG_META_USED;

    /* Process the attribute sequence to fill in the fs_inode->attr
     * list and the other info such as size and times
     */
    attr =
	(ntfs_attr *) ((uintptr_t) mft + getu16(fs->endian,
	    mft->attr_off));
    if (ntfs_proc_attrseq(ntfs, fs_inode, attr,
	    ntfs->mft_rsize_b - getu16(fs->endian, mft->attr_off))) {
	return 1;
    }
    return 0;
}


/*
 * Read the mft entry and put it into the ntfs->mft structure
 * Also sets the ntfs->mnum value
 *
 * Return 1 on error and 0 on success
 */
uint8_t
ntfs_dinode_load(NTFS_INFO * ntfs, INUM_T mftnum)
{
    /* mft_lookup does a sanity check, so we can skip it here */
    if (ntfs_dinode_lookup(ntfs, ntfs->mft, mftnum))
	return 1;
    ntfs->mnum = mftnum;
    return 0;
}


/*
 * return the MFT entry in the generic FS_INODE format
 *
 * Return NULL on error 
 */
static FS_INODE *
ntfs_inode_lookup(FS_INFO * fs, INUM_T mftnum)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    FS_INODE *fs_inode;

    // clean up any error messages that are lying around
    tsk_error_reset();

    fs_inode = fs_inode_alloc(NTFS_NDADDR, NTFS_NIADDR);
    if (fs_inode == NULL)
	return NULL;

    /* Lookup inode and store it in the ntfs structure */
    if (ntfs_dinode_load(ntfs, mftnum)) {
	fs_inode_free(fs_inode);
	return NULL;
    }

    /* Copy the structure in ntfs to generic fs_inode */
    if (ntfs_dinode_copy(ntfs, fs_inode)) {
	fs_inode_free(fs_inode);
	return NULL;
    }

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
 *
 * Return 1 on error and 0 on success
 */
static uint8_t
ntfs_load_attrdef(NTFS_INFO * ntfs)
{
    FS_INODE *fs_inode;
    FS_DATA *fs_data;
    FS_INFO *fs = &ntfs->fs_info;
    FS_LOAD_FILE load_file;

    /* if already loaded, return now */
    if (ntfs->attrdef)
	return 1;

    if ((fs_inode = ntfs_inode_lookup(fs, NTFS_MFT_ATTR)) == NULL)
	return 1;

    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_DATA);
    if (!fs_data) {
	//("Data attribute not found in $Attr");
	fs_inode_free(fs_inode);
	return 1;
    }


    /* Get a copy of the attribute list stream using the above action */
    load_file.left = load_file.total = (size_t) fs_data->size;
    load_file.base = load_file.cur = mymalloc((size_t) fs_data->size);
    if (load_file.cur == NULL) {
	fs_inode_free(fs_inode);
	return 1;
    }
    ntfs->attrdef = (ntfs_attrdef *) load_file.base;

    if (ntfs_data_walk(ntfs, fs_inode->addr, fs_data,
	    0, load_file_action, (void *) &load_file)) {
	strncat(tsk_errstr2, " - load_attrdef",
	    TSK_ERRSTR_L - strlen(tsk_errstr2));
	fs_inode_free(fs_inode);
	free(ntfs->attrdef);
	ntfs->attrdef = NULL;
	return 1;
    }
    else if (load_file.left > 0) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_FWALK;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "load_attrdef: space still left after walking $Attr data");
	fs_inode_free(fs_inode);
	free(ntfs->attrdef);
	ntfs->attrdef = NULL;
	return 1;
    }

    ntfs->attrdef_len = (SSIZE_T) fs_data->size;
    fs_inode_free(fs_inode);
    return 0;
}


/* 
 * return the name of the attribute type.  If the attribute has not
 * been loaded yet, it will be.
 *
 * Return 1 on error and 0 on success
 */
uint8_t
ntfs_attrname_lookup(FS_INFO * fs, uint16_t type, char *name, int len)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    ntfs_attrdef *attrdef;
    if (!ntfs->attrdef) {
	if (ntfs_load_attrdef(ntfs))
	    return 1;
    }

    attrdef = ntfs->attrdef;
    while (
	((SSIZE_T) ((uintptr_t) attrdef - (uintptr_t) ntfs->attrdef +
		sizeof(ntfs_attrdef)) < ntfs->attrdef_len) &&
	(getu32(fs->endian, attrdef->type))) {
	if (getu32(fs->endian, attrdef->type) == type) {

	    UTF16 *name16 = (UTF16 *) attrdef->label;
	    UTF8 *name8 = (UTF8 *) name;
	    int retVal;
	    retVal =
		tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
		(UTF16 *) ((uintptr_t) name16 +
		    sizeof(attrdef->
			label)),
		&name8,
		(UTF8 *) ((uintptr_t) name8 + len), lenientConversion);
	    if (retVal != conversionOK) {
		if (verbose)
		    tsk_fprintf(stderr,
			"attrname_lookup: Error converting NTFS attribute def label to UTF8: %d",
			retVal);
		break;
	    }

	    /* Make sure it is NULL Terminated */
	    else if ((uintptr_t) name8 > (uintptr_t) name + len)
		name[len] = '\0';
	    else
		*name8 = '\0';
	    return 0;
	}
	attrdef++;
    }
    /* If we didn't find it, then call it '?' */
    snprintf(name, len, "?");
    return 0;
}


/* Load the block bitmap $Data run  and allocate a buffer for a cache 
 *
 * return 1 on error and 0 on success
 * */
static uint8_t
ntfs_load_bmap(NTFS_INFO * ntfs)
{
    SSIZE_T cnt;
    ntfs_attr *attr;
    FS_INFO *fs = &ntfs->fs_info;

    /* Get data on the bitmap */
    if (ntfs_dinode_load(ntfs, NTFS_MFT_BMAP)) {
	return 1;
    }

    attr = (ntfs_attr *) ((uintptr_t) ntfs->mft +
	getu16(fs->endian, ntfs->mft->attr_off));

    /* cycle through them */
    while (((uintptr_t) attr >= (uintptr_t) ntfs->mft)
	&& ((uintptr_t) attr <=
	    ((uintptr_t) ntfs->mft + (uintptr_t) ntfs->mft_rsize_b))
	&& (getu32(fs->endian, attr->len) > 0
	    && (getu32(fs->endian, attr->type) != 0xffffffff)
	    && (getu32(fs->endian, attr->type) != NTFS_ATYPE_DATA))) {
	attr =
	    (ntfs_attr *) ((uintptr_t) attr + getu32(fs->endian,
		attr->len));
    }

    /* did we get it? */
    if (getu32(fs->endian, attr->type) != NTFS_ATYPE_DATA) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_INODE_INT;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "Error Finding Bitmap Data Attribute");
	return 1;
    }

    /* convert to generic form */
    ntfs->bmap = ntfs_make_data_run(ntfs,
	(ntfs_runlist
	    *) ((uintptr_t) attr + getu16(fs->endian, attr->c.nr.run_off)),
	NULL);

    if (ntfs->bmap == NULL) {
	return 1;
    }

    ntfs->bmap_buf = data_buf_alloc(fs->block_size);
    if (ntfs->bmap_buf == NULL) {
	return 1;
    }

    /* Load the first cluster so that we have something there */
    ntfs->bmap_buf_off = 0;
    if (ntfs->bmap->addr > fs->last_block) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_GENFS;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "ntfs_load_bmap: Bitmap too large for image size: %"
	    PRIuDADDR "", ntfs->bmap->addr);
	return 1;
    }
    cnt =
	fs_read_block(fs, ntfs->bmap_buf, fs->block_size,
	ntfs->bmap->addr);
    if (cnt != fs->block_size) {
	if (cnt != 1) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_READ;
	}
	snprintf(tsk_errstr2, TSK_ERRSTR_L,
	    "ntfs_load_bmap: Error reading block at %"
	    PRIuDADDR, ntfs->bmap->addr);
	return 1;
    }
    return 0;
}


/*
 * Load the VOLUME MFT entry and the VINFO attribute so that we
 * can identify the volume version of this.  
 *
 * Return 1 on error and 0 on success
 */
static uint8_t
ntfs_load_ver(NTFS_INFO * ntfs)
{
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;
    FS_INODE *fs_inode;
    FS_DATA *fs_data;
    if ((fs_inode = ntfs_inode_lookup(fs, NTFS_MFT_VOL)) == NULL) {
	return 1;
    }

    /* cache the data attribute */
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_VINFO);
    if (!fs_data) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_INODE_INT;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "Volume Info attribute not found in $Volume");
	fs_inode_free(fs_inode);
	return 1;
    }

    if ((fs_data->flags & FS_DATA_RES)
	&& (fs_data->size)) {
	ntfs_attr_vinfo *vinfo = (ntfs_attr_vinfo *) fs_data->buf;

	if ((vinfo->maj_ver == 1)
	    && (vinfo->min_ver == 2)) {
	    ntfs->ver = NTFS_VINFO_NT;
	}
	else if ((vinfo->maj_ver == 3)
	    && (vinfo->min_ver == 0)) {
	    ntfs->ver = NTFS_VINFO_2K;
	}
	else if ((vinfo->maj_ver == 3)
	    && (vinfo->min_ver == 1)) {
	    ntfs->ver = NTFS_VINFO_XP;
	}
	else {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_GENFS;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"unknown version: %d.%d\n",
		vinfo->maj_ver, vinfo->min_ver);
	    fs_inode_free(fs_inode);
	    return 1;
	}
    }
    else {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_GENFS;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "load_version: VINFO is a non-resident attribute");
	return 1;
    }

    fs_inode_free(fs_inode);
    return 0;
}




/* 
 * Process the SDS entry from the $Secure File and save to
 * the sid structure in NTFS_INFO
 *
 * Return 1 on error and 0 on success 
 */
static int
ntfs_load_sid(FS_INFO * fs, ntfs_attr_sds * sds)
{
    char *sid_str = NULL;
    // "S-"
    unsigned int sid_str_len = 2;

    NTFS_INFO *ntfs = (NTFS_INFO *) fs;

    unsigned int owner_offset =
	getu32(fs->endian, sds->self_rel_sec_desc.owner);
    ntfs_sid *sid =
	(ntfs_sid *) ((uint8_t *) & sds->self_rel_sec_desc + owner_offset);

    // "1-"
    sid_str_len += 2;
    //tsk_fprintf(stderr, "Revision: %i\n", sid->revision);

    // This check helps not process invalid data, which was noticed while testing
    // a failing harddrive
    if (sid->revision == 1) {
	NTFS_SID_ENTRY *sid_entry;
	int index;
	int len;
	uint64_t authority;
	int i, j;
	char *sid_str_offset;

	//tsk_fprintf(stderr, "Sub-Authority Count: %i\n", sid->sub_auth_count);

	for (authority = i = 0, j = 40; i < 6; i++, j -= 8)
	    authority += (uint64_t) sid->ident_auth[i] << j;

	//tsk_fprintf(stderr, "NT Authority: %" PRIu64 "\n", authority);

	// "-XXXXXXXXXX"
	sid_str_len += (1 + 10) * sid->sub_auth_count;

	if ((sid_str = (char *) mymalloc(sid_str_len)) == NULL) {
	    return 1;
	}

	len = sprintf(sid_str, "S-1-%" PRIu64, authority);
	sid_str_offset = sid_str + len;

	for (index = 0; index < sid->sub_auth_count; index++) {
	    len =
		sprintf(sid_str_offset, "-%" PRIu32, sid->sub_auth[index]);
	    sid_str_offset += len;
	}
	//tsk_fprintf(stderr, "SID: %s\n\n", sid_str);

	if ((sid_entry =
		(NTFS_SID_ENTRY *) mymalloc(sizeof(NTFS_SID_ENTRY))) ==
	    NULL) {
	    free(sid_str);
	    return 1;
	}

	// malloc size of ntfs_sid plus extra for each sub_auth_count above 1 because
	// 1 is already expected as a minimum in the ntfs_sid struct.
	if ((sid_entry->data =
	     (ntfs_sid *) talloc_size(sid_entry, sizeof(ntfs_sid) +
		    ((int) sid->sub_auth_count -
			1) * (sizeof(uint32_t) * 10))) == NULL) {
	    free(sid_str);
	    free(sid_entry);
	    return 1;
	}

	memcpy(sid_entry->data, sid,
	    sizeof(ntfs_sid) + ((int) sid->sub_auth_count -
		1) * sizeof(uint32_t));
	sid_entry->sid_str = sid_str;
	sid_entry->sec_id = getu32(fs->endian, sds->sec_id);
	sid_entry->next = NULL;

	if (ntfs->sid == NULL) {
	    ntfs->sid = sid_entry;
	}
	else {
	    NTFS_SID_ENTRY *sid_tmp;
	    sid_tmp = ntfs->sid;
	    while (sid_tmp) {
		if (sid_tmp->next == NULL) {
		    sid_tmp->next = sid_entry;
		    break;
		}
		sid_tmp = sid_tmp->next;
	    }
	}
    }
    return 0;
}


/* Process the $SDS attribute in the $Secure file and load results
 * into sds structure in NTFS_INFO
 *
 * return 1 on error and 0 on success
 * */
static int
ntfs_proc_sds(FS_INFO * fs, NTFS_SXX_BUFFER * sds_buffer)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;

    unsigned int offset = 0;
    unsigned int total_bytes_processed = 0;
    uint64_t current_offset = 0;

    NTFS_SDS_ENTRY *previous_sds_entry = NULL;
    ntfs_attr_sds *sds = (ntfs_attr_sds *) sds_buffer->buffer;


    while (total_bytes_processed < sds_buffer->size) {
	current_offset =
	    (uintptr_t *) sds - (uintptr_t *) sds_buffer->buffer;

	offset = getu32(fs->endian, sds->ent_size);
	if (offset % 16) {
	    offset = ((offset / 16) + 1) * 16;
	}

	if ((offset != 0) && (offset < (sds_buffer->size - current_offset))
	    && (getu64(fs->endian, sds->file_off) < sds_buffer->size)) {

	    NTFS_SDS_ENTRY *sds_entry;

	    if ((sds_entry =
		    (NTFS_SDS_ENTRY *) mymalloc(sizeof(NTFS_SDS_ENTRY))) ==
		NULL) {
		return 1;
	    }
	    if ((sds_entry->data = (uint8_t *) talloc_size(sds_entry, offset)) == NULL) {
		free(sds_entry);
		return 1;
	    }
	    memcpy(sds_entry->data, sds, offset);
	    sds_entry->len = offset;
	    sds_entry->next = NULL;

	    if (previous_sds_entry == NULL) {
		ntfs->sds = sds_entry;
	    }
	    else {
		previous_sds_entry->next = sds_entry;
	    }
	    previous_sds_entry = sds_entry;

	    if (ntfs_load_sid(fs, sds)) {
		return 1;
	    }

	    sds = (ntfs_attr_sds *) ((uint8_t *) sds + offset);
	    total_bytes_processed += offset;
	}
	else {
	    total_bytes_processed =
		((total_bytes_processed / NTFS_SDS_BLOCK_OFFSET) +
		1) * NTFS_SDS_BLOCK_OFFSET;
	    sds =
		(ntfs_attr_sds *) ((uint8_t *) sds_buffer->buffer +
		total_bytes_processed);
	}
    }

    return 0;
}


#if 0
void
ntfs_load_sii(FS_INFO * fs, NTFS_SXX_BUFFER * sii_buffer)
{
    unsigned int total_bytes_processed = 0;
    unsigned int idx_buffer_length = 0;
    unsigned int sii_buffer_offset = 0;

    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    NTFS_SII_ENTRY *previous_sii_entry = NULL;

    /* Loop by cluster size */
    for (sii_buffer_offset = 0; sii_buffer_offset < sii_buffer->size;
	sii_buffer_offset += ntfs->csize_b) {
	ntfs_idxrec *idxrec =
	    (ntfs_idxrec *) & sii_buffer->buffer[sii_buffer_offset];

	idx_buffer_length = getu32(fs->endian, idxrec->list.buf_off);

	ntfs_attr_sii *sii =
	    (ntfs_attr_sii *) ((uintptr_t) & idxrec->list +
	    getu32(fs->endian,
		idxrec->list.begin_off));

	total_bytes_processed =
	    (uint8_t) ((uintptr_t) sii - (uintptr_t) idxrec);

	do {
	    NTFS_SII_ENTRY *sii_entry;

	    if ((sii_entry =
		    (NTFS_SII_ENTRY *) mymalloc(sizeof(NTFS_SII_ENTRY))) ==
		NULL) {
		return 1;
	    }

	    if ((sii_entry->data =
		 (ntfs_attr_sii *) talloc_size(sii_entry, sizeof(ntfs_attr_sii))) ==
		NULL) {
		free(sii_entry);
		return 1;
	    }
	    memcpy(sii_entry->data, sii, sizeof(ntfs_attr_sii));

	    if (previous_sii_entry == NULL) {
		previous_sii_entry = sii_entry;
		previous_sii_entry->next = NULL;
		ntfs->sii = previous_sii_entry;
	    }
	    else {
		previous_sii_entry->next = sii_entry;
		previous_sii_entry = previous_sii_entry->next;
		previous_sii_entry->next = NULL;
	    }

	    sii++;
	    total_bytes_processed += sizeof(ntfs_attr_sii);
	} while (total_bytes_processed + sizeof(ntfs_attr_sii) <=
	    idx_buffer_length);
    }
}



void
ntfs_load_sdh(FS_INFO * fs, NTFS_SXX_BUFFER * sdh_buffer)
{
    unsigned int total_bytes_processed = 0;
    unsigned int idx_buffer_length = 0;
    unsigned int sdh_buffer_offset = 0;

    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    NTFS_SDH_ENTRY *previous_sdh_entry = NULL;

    /* Loop by cluster size */
    for (sdh_buffer_offset = 0; sdh_buffer_offset < sdh_buffer->size;
	sdh_buffer_offset += ntfs->csize_b) {
	ntfs_idxrec *idxrec =
	    (ntfs_idxrec *) & sdh_buffer->buffer[sdh_buffer_offset];

	idx_buffer_length = getu32(fs->endian, idxrec->list.buf_off);

	ntfs_attr_sdh *sdh =
	    (ntfs_attr_sdh *) ((uintptr_t) & idxrec->list +
	    getu32(fs->endian,
		idxrec->list.begin_off));

	total_bytes_processed =
	    (uint8_t) ((uintptr_t) sdh - (uintptr_t) idxrec);

	do {
	    NTFS_SDH_ENTRY *sdh_entry =
		(NTFS_SDH_ENTRY *) malloc(sizeof(NTFS_SDH_ENTRY));
	    sdh_entry->data =
		(ntfs_attr_sdh *) malloc(sizeof(ntfs_attr_sdh));
	    memcpy(sdh_entry->data, sdh, sizeof(ntfs_attr_sdh));

	    if (previous_sdh_entry == NULL) {
		previous_sdh_entry = sdh_entry;
		previous_sdh_entry->next = NULL;
		ntfs->sdh = previous_sdh_entry;
	    }
	    else {
		previous_sdh_entry->next = sdh_entry;
		previous_sdh_entry = previous_sdh_entry->next;
		previous_sdh_entry->next = NULL;
	    }

	    sdh++;
	    total_bytes_processed += sizeof(ntfs_attr_sdh);
	    //tsk_fprintf(stderr, "total_bytes_processed: %u\tidx_buffer_length: %u\n", total_bytes_processed, idx_buffer_length);
	} while (total_bytes_processed + sizeof(ntfs_attr_sdh) <=
	    idx_buffer_length);
    }
}
#endif

uint8_t
ntfs_load_sxx_buffer(FS_INFO * fs, DADDR_T addr, char *buf,
    size_t size, int flags, void *ptr)
{
    NTFS_SXX_BUFFER *sxx_buffer = (NTFS_SXX_BUFFER *) ptr;

    if ((sxx_buffer->buffer =
	    (char *) myrealloc(sxx_buffer->buffer,
		sxx_buffer->size + size)) == NULL) {
	return WALK_ERROR;
    }

    memcpy(&(sxx_buffer->buffer[sxx_buffer->size]), buf, size);
    sxx_buffer->size += size;
    return WALK_CONT;
}


/*
 * Load the $Secure attributes so that we can identify the user.
 */
static int
ntfs_load_secure(NTFS_INFO * ntfs)
{
    FS_INFO *fs = (FS_INFO *) & ntfs->fs_info;
    FS_INODE *fs_inode;
    FS_DATA *fs_data;
    NTFS_SXX_BUFFER sds_buffer;

    ntfs->sds = NULL;
    ntfs->sid = NULL;
    //ntfs->sdh = NULL;
    //ntfs->sii = NULL;

    fs_inode = ntfs_inode_lookup(fs, NTFS_MFT_SECURE);
    if (!fs_inode) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_INODE_NUM;
	strncat(tsk_errstr2,
	    " - load_secure: Error finding $Secure MFT Entry",
	    TSK_ERRSTR_L - strlen(tsk_errstr2));
	return 1;
    }

    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_DATA);
    if (!fs_data) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "ntfs_load_secure: Error finding $Data attribute");
	return 1;
    }

    sds_buffer.size = 0;
    sds_buffer.buffer = NULL;

    if (ntfs_data_walk(ntfs, fs_inode->addr, fs_data, 0,
	    ntfs_load_sxx_buffer, (void *) &sds_buffer)) {
	fs_inode_free(fs_inode);
	return 1;
    }

    if (ntfs_proc_sds(fs, &sds_buffer)) {
	free(sds_buffer.buffer);
	fs_inode_free(fs_inode);
	return 1;
    }

    free(sds_buffer.buffer);
    fs_inode_free(fs_inode);
    return 0;
}



/**********************************************************************
 *
 *  Exported Walk Functions
 *
 **********************************************************************/

/*
 *
 * flag values: FS_FLAG_FILE_AONLY, FS_FLAG_FILE_SLACK, FS_FLAG_FILE_NOSPARSE
 * FS_FLAG_FILE_NOID
 * 
 * If FS_FLAG_FILE_RECOVER is set, then error codes are set to _RECOVER
 * so that errors can be more easily suppressed.  No special recovery logic
 * exists in this code. 
 *
 * action uses: FS_FLAG_DATA_CONT
 *
 * No notion of meta with NTFS
 *
 * a type of 0 will use $Data for files and IDXROOT for directories
 * an id of 0 will ignore the id and just find the first entry with the type
 *
 * Return 0 on success and 1 on error
 */
uint8_t
ntfs_file_walk(FS_INFO * fs,
    FS_INODE * fs_inode,
    uint32_t type, uint16_t id,
    int flags, FS_FILE_WALK_FN action, void *ptr)
{
    FS_DATA *fs_data;
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /* no data */
    if (fs_inode->attr == NULL) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "file_walk: attributes are NULL");
	return 1;
    }

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
	if (!fs_data) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_ARG;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"ntfs_file_walk: type %" PRIu32 " not found in file",
		type);
	    return 1;
	}
    }
    else {
	fs_data = fs_data_lookup(fs_inode->attr, type, id);
	if (!fs_data) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_ARG;
	    snprintf(tsk_errstr, TSK_ERRSTR_L,
		"ntfs_file_walk: type %" PRIu32 "-%" PRIu16
		" not found in file", type, id);
	    return 1;
	}
    }


    /* process the content */
    return ntfs_data_walk(ntfs, fs_inode->addr, fs_data, flags, action,
	ptr);
}





/*
 * flags: FS_FLAG_DATA_ALLOC and FS_FLAG_UNALLOC
 *
 * @@@ We should probably consider some data META, but it is tough with
 * the NTFS design ...
 */
uint8_t
ntfs_block_walk(FS_INFO * fs,
    DADDR_T start_blk,
    DADDR_T end_blk, int flags, FS_BLOCK_WALK_FN action, void *ptr)
{
    char *myname = "ntfs_block_walk";
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    DADDR_T addr;
    DATA_BUF *data_buf;
    int myflags;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (start_blk < fs->first_block || start_blk > fs->last_block) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_WALK_RNG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "%s: start block: %" PRIuDADDR "", myname, start_blk);
	return 1;
    }
    else if (end_blk < fs->first_block || end_blk > fs->last_block) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_FUNC;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "%s: last block: %" PRIuDADDR "", myname, end_blk);
	return 1;
    }

    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((flags & FS_FLAG_DATA_ALLOC) == 0) &&
	((flags & FS_FLAG_DATA_UNALLOC) == 0)) {
	flags |= (FS_FLAG_DATA_ALLOC | FS_FLAG_DATA_UNALLOC);
    }


    if ((data_buf = data_buf_alloc(fs->block_size)) == NULL) {
	return 1;
    }

    /* Cycle through the blocks */
    for (addr = start_blk; addr <= end_blk; addr++) {
	int retval;

	/* identify if the cluster is allocated or not */
	retval = is_clustalloc(ntfs, addr);
	if (retval == -1) {
	    data_buf_free(data_buf);
	    return 1;
	}
	else if (retval == 1) {
	    myflags = FS_FLAG_DATA_ALLOC;
	}
	else {
	    myflags = FS_FLAG_DATA_UNALLOC;
	}

	if ((flags & myflags) == myflags) {
	    SSIZE_T cnt;

	    cnt = fs_read_block(fs, data_buf, fs->block_size, addr);
	    if (cnt != fs->block_size) {
		if (cnt != 1) {
		    tsk_error_reset();
		    tsk_errno = TSK_ERR_FS_READ;
		}
		snprintf(tsk_errstr2, TSK_ERRSTR_L,
		    "ntfs_block_walk: Error reading block at %"
		    PRIuDADDR, addr);
		data_buf_free(data_buf);
		return 1;
	    }

	    retval = action(fs, addr, data_buf->data, myflags, ptr);
	    if (retval == WALK_STOP) {
		data_buf_free(data_buf);
		return 0;
	    }
	    else if (retval == WALK_ERROR) {
		data_buf_free(data_buf);
		return 1;
	    }
	}
    }

    data_buf_free(data_buf);
    return 0;
}


static uint8_t
inode_walk_dent_orphan_act(FS_INFO * fs, FS_DENT * fs_dent, int flags,
    void *ptr)
{
    if ((fs_dent->fsi) && (fs_dent->fsi->flags & FS_FLAG_META_UNALLOC)) {
	if (tsk_list_add(&fs->list_inum_named, fs_dent->fsi->addr))
	    return WALK_STOP;
    }
    return WALK_CONT;
}



/*
 * inode_walk
 *
 * Flags: FS_FLAG_META_ALLOC, FS_FLAG_META_UNALLOC, 
 * FS_FLAG_META_USED, FS_FLAG_META_ORPHAN
 *
 * Not used: FS_FLAG_META_UNUSED (Only allocated when needed)
 *
 * Note that with ORPHAN, entries will be found that can also be
 * found by searching based on parent directories (if parent directory is
 * known)
 */
uint8_t
ntfs_inode_walk(FS_INFO * fs,
    INUM_T start_inum,
    INUM_T end_inum, int flags, FS_INODE_WALK_FN action, void *ptr)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    int myflags;
    INUM_T mftnum;
    FS_INODE *fs_inode;

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_WALK_RNG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "inode_walk: Starting inode number is too small (%"
	    PRIuINUM ")", start_inum);
	return 1;
    }
    if (start_inum > fs->last_inum) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_WALK_RNG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "inode_walk: Starting inode number is too large (%"
	    PRIuINUM ")", start_inum);
	return 1;
    }
    if (end_inum < fs->first_inum) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_FUNC;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "inode_walk: Ending inode number is too small (%"
	    PRIuINUM ")", end_inum);
	return 1;
    }
    if (end_inum > fs->last_inum) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_FUNC;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "Ending inode number is too large (%" PRIuINUM ")", end_inum);
	return 1;
    }


    /* If ORPHAN is wanted, then make sure that the flags are correct */
    if (flags & FS_FLAG_META_ORPHAN) {
	flags |= FS_FLAG_META_UNALLOC;
	flags &= ~FS_FLAG_META_ALLOC;
    }

    else if (((flags & FS_FLAG_META_ALLOC) == 0) &&
	((flags & FS_FLAG_META_UNALLOC) == 0)) {
	flags |= (FS_FLAG_META_ALLOC | FS_FLAG_META_UNALLOC);
    }

    /* If neither of the USED or UNUSED flags are set, then set them
     * both
     */
    if (((flags & FS_FLAG_META_USED) == 0) &&
	((flags & FS_FLAG_META_UNUSED) == 0)) {
	flags |= (FS_FLAG_META_USED | FS_FLAG_META_UNUSED);
    }


    /* If we are looking for orphan files and have not yet filled
     * in the list of unalloc inodes that are pointed to, then fill
     * in the list
     * */
    if ((flags & FS_FLAG_META_ORPHAN) && (fs->list_inum_named == NULL)) {

	if (ntfs_dent_walk(fs, fs->root_inum,
		FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC |
		FS_FLAG_NAME_RECURSE, inode_walk_dent_orphan_act, NULL)) {
	    strncat(tsk_errstr2,
		" - ntfs_inode_walk: identifying inodes allocated by file names",
		TSK_ERRSTR_L);
	    return 1;
	}
    }


    if ((fs_inode = fs_inode_alloc(NTFS_NDADDR, NTFS_NIADDR)) == NULL) {
	return 1;
    }

    for (mftnum = start_inum; mftnum <= end_inum; mftnum++) {
	int retval;

	/* read MFT entry in to NTFS_INFO */
	if (ntfs_dinode_load(ntfs, mftnum)) {
	    fs_inode_free(fs_inode);
	    return 1;
	}

	/* we only want to look at base file records 
	 * (extended are because the base could not fit into one)
	 */
	if (getu48(fs->endian, ntfs->mft->base_ref) != NTFS_MFT_BASE)
	    continue;

	/* NOTE: We could add a sanity check here with the MFT bitmap
	 * to validate of the INUSE flag and bitmap are in agreement
	 */
	/* check flags */
	myflags =
	    ((getu16(fs->endian, ntfs->mft->flags) &
		NTFS_MFT_INUSE) ? FS_FLAG_META_ALLOC :
	    FS_FLAG_META_UNALLOC);

	/* MFT entries are only allocated when needed, so it must have 
	 * been used
	 */
	myflags |= FS_FLAG_META_USED;
	if ((flags & myflags) != myflags)
	    continue;


	/* If we want only orphans, then check if this
	 * inode is in the seen list
	 * */
	if ((myflags & FS_FLAG_META_UNALLOC) &&
	    (flags & FS_FLAG_META_ORPHAN) &&
	    (tsk_list_find(fs->list_inum_named, mftnum))) {
	    continue;
	}


	/* copy into generic format */
	if (ntfs_dinode_copy(ntfs, fs_inode)) {
	    fs_inode_free(fs_inode);
	    return 1;
	}

	/* call action */
	retval = action(fs, fs_inode, myflags, ptr);

	if (retval == WALK_STOP) {
	    fs_inode_free(fs_inode);
	    return 0;
	}
	else if (retval == WALK_ERROR) {
	    fs_inode_free(fs_inode);
	    return 1;
	}
    }

    fs_inode_free(fs_inode);
    return 0;
}


char *
ntfs_get_sid_as_string(FS_INFO * fs, uint32_t security_id)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    NTFS_SID_ENTRY *sid_entry = ntfs->sid;

    while ((sid_entry) && sid_entry->sec_id != security_id) {
	sid_entry = sid_entry->next;
    }

    if (sid_entry) {
	return sid_entry->sid_str;
    }

    return "";
}














static uint8_t
ntfs_fscheck(FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
	"fscheck not implemented for NTFS yet");
    return 1;
}


static uint8_t
ntfs_fsstat(FS_INFO * fs, FILE * hFile)
{
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;
    FS_INODE *fs_inode;
    FS_DATA *fs_data;
    char asc[512];
    ntfs_attrdef *attrdeftmp;
    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "File System Type: NTFS\n");
    tsk_fprintf(hFile,
	"Volume Serial Number: %.16" PRIX64
	"\n", getu64(fs->endian, ntfs->fs->serial));
    tsk_fprintf(hFile, "OEM Name: %c%c%c%c%c%c%c%c\n",
	ntfs->fs->oemname[0],
	ntfs->fs->oemname[1],
	ntfs->fs->oemname[2],
	ntfs->fs->oemname[3],
	ntfs->fs->oemname[4],
	ntfs->fs->oemname[5], ntfs->fs->oemname[6], ntfs->fs->oemname[7]);
    /*
     * Volume 
     */
    fs_inode = ntfs_inode_lookup(fs, NTFS_MFT_VOL);
    if (!fs_inode) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_INODE_NUM;
	strncat(tsk_errstr2, " - fsstat: Error finding Volume MFT Entry",
	    TSK_ERRSTR_L - strlen(tsk_errstr2));
	return 1;
    }

    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_VNAME);
    if (!fs_data) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_INODE_INT;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "Volume Name attribute not found in $Volume");
	return 1;
    }

    if ((fs_data->flags & FS_DATA_RES)
	&& (fs_data->size)) {

	UTF16 *name16 = (UTF16 *) fs_data->buf;
	UTF8 *name8 = (UTF8 *) asc;
	int retVal;
	retVal =
	    tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
	    (UTF16 *) ((uintptr_t) name16 +
		(int) fs_data->
		size), &name8,
	    (UTF8 *) ((uintptr_t) name8 + sizeof(asc)), lenientConversion);
	if (retVal != conversionOK) {
	    if (verbose)
		tsk_fprintf(stderr,
		    "fsstat: Error converting NTFS Volume label to UTF8: %d",
		    retVal);
	    *name8 = '\0';
	}

	/* Make sure it is NULL Terminated */
	else if ((uintptr_t) name8 > (uintptr_t) asc + sizeof(asc))
	    asc[sizeof(asc)] = '\0';
	else
	    *name8 = '\0';
	tsk_fprintf(hFile, "Volume Name: %s\n", asc);
    }

    fs_inode_free(fs_inode);
    fs_inode = NULL;
    fs_data = NULL;
    if (ntfs->ver == NTFS_VINFO_NT)
	tsk_fprintf(hFile, "Version: Windows NT\n");
    else if (ntfs->ver == NTFS_VINFO_2K)
	tsk_fprintf(hFile, "Version: Windows 2000\n");
    else if (ntfs->ver == NTFS_VINFO_XP)
	tsk_fprintf(hFile, "Version: Windows XP\n");
    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile,
	"First Cluster of MFT: %" PRIu64 "\n",
	getu64(fs->endian, ntfs->fs->mft_clust));
    tsk_fprintf(hFile,
	"First Cluster of MFT Mirror: %"
	PRIu64 "\n", getu64(fs->endian, ntfs->fs->mftm_clust));
    tsk_fprintf(hFile,
	"Size of MFT Entries: %" PRIu16 " bytes\n", ntfs->mft_rsize_b);
    tsk_fprintf(hFile,
	"Size of Index Records: %" PRIu16 " bytes\n", ntfs->idx_rsize_b);
    tsk_fprintf(hFile,
	"Range: %" PRIuINUM " - %" PRIuINUM
	"\n", fs->first_inum, fs->last_inum);
    tsk_fprintf(hFile, "Root Directory: %" PRIuINUM "\n", fs->root_inum);
    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Sector Size: %" PRIu16 "\n", ntfs->ssize_b);
    tsk_fprintf(hFile, "Cluster Size: %" PRIu16 "\n", ntfs->csize_b);
    tsk_fprintf(hFile,
	"Total Cluster Range: %" PRIuDADDR
	" - %" PRIuDADDR "\n", fs->first_block, fs->last_block);
    tsk_fprintf(hFile,
	"Total Sector Range: 0 - %" PRIu64
	"\n", getu64(fs->endian, ntfs->fs->vol_size_s) - 1);
    /* 
     * Attrdef Info 
     */
    tsk_fprintf(hFile, "\n$AttrDef Attribute Values:\n");
    if (!ntfs->attrdef) {
	if (ntfs_load_attrdef(ntfs)) {
	    tsk_fprintf(hFile, "Error loading attribute definitions\n");
	    goto attrdef_egress;
	}
    }

    attrdeftmp = ntfs->attrdef;
    while (((SSIZE_T) ((uintptr_t) attrdeftmp - (uintptr_t) ntfs->attrdef +
		sizeof(ntfs_attrdef)) < ntfs->attrdef_len) &&
	(getu32(fs->endian, attrdeftmp->type))) {
	UTF16 *name16 = (UTF16 *) attrdeftmp->label;
	UTF8 *name8 = (UTF8 *) asc;
	int retVal;
	retVal =
	    tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
	    (UTF16 *) ((uintptr_t) name16 +
		sizeof(attrdeftmp->
		    label)),
	    &name8,
	    (UTF8 *) ((uintptr_t) name8 + sizeof(asc)), lenientConversion);
	if (retVal != conversionOK) {
	    if (verbose)
		tsk_fprintf(stderr,
		    "fsstat: Error converting NTFS attribute def label to UTF8: %d",
		    retVal);
	    *name8 = '\0';
	}

	/* Make sure it is NULL Terminated */
	else if ((uintptr_t) name8 > (uintptr_t) asc + sizeof(asc))
	    asc[sizeof(asc)] = '\0';
	else
	    *name8 = '\0';
	tsk_fprintf(hFile, "%s (%" PRIu32 ")   ",
	    asc, getu32(fs->endian, attrdeftmp->type));
	if ((getu64(fs->endian, attrdeftmp->minsize) == 0) &&
	    (getu64(fs->endian,
		    attrdeftmp->maxsize) == 0xffffffffffffffffULL)) {

	    tsk_fprintf(hFile, "Size: No Limit");
	}
	else {
	    tsk_fprintf(hFile, "Size: %" PRIu64 "-%" PRIu64,
		getu64(fs->endian, attrdeftmp->minsize),
		getu64(fs->endian, attrdeftmp->maxsize));
	}

	tsk_fprintf(hFile, "   Flags: %s%s%s\n",
	    (getu32(fs->endian, attrdeftmp->flags) &
		NTFS_ATTRDEF_FLAGS_RES ? "Resident" :
		""), (getu32(fs->endian,
		    attrdeftmp->
		    flags) &
		NTFS_ATTRDEF_FLAGS_NONRES ?
		"Non-resident" : ""),
	    (getu32(fs->endian, attrdeftmp->flags) &
		NTFS_ATTRDEF_FLAGS_IDX ? ",Index" : ""));
	attrdeftmp++;
    }

  attrdef_egress:

    return 0;
}


/************************* istat *******************************/

#define NTFS_PRINT_WIDTH   8
typedef struct {
    FILE *hFile;
    int idx;
} NTFS_PRINT_ADDR;
static uint8_t
print_addr_act(FS_INFO * fs, DADDR_T addr,
    char *buf, size_t size, int flags, void *ptr)
{
    NTFS_PRINT_ADDR *print = (NTFS_PRINT_ADDR *) ptr;
    tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr);
    if (++(print->idx) == NTFS_PRINT_WIDTH) {
	tsk_fprintf(print->hFile, "\n");
	print->idx = 0;
    }

    return WALK_CONT;
}


static uint8_t
ntfs_istat(FS_INFO * fs, FILE * hFile,
    INUM_T inum, DADDR_T numblock, int32_t sec_skew)
{
    FS_INODE *fs_inode;
    FS_DATA *fs_data;
    NTFS_INFO *ntfs = (NTFS_INFO *) fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    fs_inode = ntfs_inode_lookup(fs, inum);
    if (fs_inode == NULL) {
	strncat(tsk_errstr2, " - istat",
	    TSK_ERRSTR_L - strlen(tsk_errstr2));
	return 1;
    }

    tsk_fprintf(hFile, "MFT Entry Header Values:\n");
    tsk_fprintf(hFile,
	"Entry: %" PRIuINUM
	"        Sequence: %" PRIu32 "\n", inum, fs_inode->seq);
    if (getu48(fs->endian, ntfs->mft->base_ref) != 0) {
	tsk_fprintf(hFile,
	    "Base File Record: %" PRIu64 "\n",
	    (uint64_t) getu48(fs->endian, ntfs->mft->base_ref));
    }

    tsk_fprintf(hFile,
	"$LogFile Sequence Number: %" PRIu64
	"\n", getu64(fs->endian, ntfs->mft->lsn));
    tsk_fprintf(hFile, "%sAllocated %s\n",
	(fs_inode->
	    flags & FS_FLAG_META_ALLOC) ? "" :
	"Not ", (fs_inode->mode & FS_INODE_DIR) ? "Directory" : "File");
    tsk_fprintf(hFile, "Links: %u\n", fs_inode->nlink);

    /* STANDARD_INFORMATION info */
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_SI);
    if (fs_data) {
	ntfs_attr_si *si = (ntfs_attr_si *) fs_data->buf;
	int a = 0;
	tsk_fprintf(hFile, "\n$STANDARD_INFORMATION Attribute Values:\n");
	tsk_fprintf(hFile, "Flags: ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_RO)
	    tsk_fprintf(hFile, "%sRead Only", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_HID)
	    tsk_fprintf(hFile, "%sHidden", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_SYS)
	    tsk_fprintf(hFile, "%sSystem", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_ARCH)
	    tsk_fprintf(hFile, "%sArchive", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_DEV)
	    tsk_fprintf(hFile, "%sDevice", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_NORM)
	    tsk_fprintf(hFile, "%sNormal", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_TEMP)
	    tsk_fprintf(hFile, "%sTemporary", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_SPAR)
	    tsk_fprintf(hFile, "%sSparse", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_REP)
	    tsk_fprintf(hFile, "%sReparse Point", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_COMP)
	    tsk_fprintf(hFile, "%sCompressed", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_OFF)
	    tsk_fprintf(hFile, "%sOffline", a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_NOIDX)
	    tsk_fprintf(hFile, "%sNot Content Indexed",
		a++ == 0 ? "" : ", ");
	if (getu32(fs->endian, si->dos) & NTFS_SI_ENC)
	    tsk_fprintf(hFile, "%sEncrypted", a++ == 0 ? "" : ", ");
	tsk_fprintf(hFile, "\n");
	tsk_fprintf(hFile, "Owner ID: %" PRIu32 "\n", getu32(fs->endian,
		si->own_id));

	tsk_fprintf(hFile, "Security ID: %" PRIu32 "  (%s)\n",
	    getu32(fs->endian, si->sec_id), ntfs_get_sid_as_string(fs,
		getu32(fs->endian, si->sec_id)));


	if (getu32(fs->endian, si->maxver) != 0) {
	    tsk_fprintf(hFile,
		"Version %" PRIu32 " of %" PRIu32
		"\n", getu32(fs->endian, si->ver), getu32(fs->endian,
		    si->maxver));
	}

	if (getu64(fs->endian, si->quota) != 0) {
	    tsk_fprintf(hFile, "Quota Charged: %" PRIu64 "\n",
		getu64(fs->endian, si->quota));
	}

	if (getu64(fs->endian, si->usn) != 0) {
	    tsk_fprintf(hFile,
		"Last User Journal Update Sequence Number: %"
		PRIu64 "\n", getu64(fs->endian, si->usn));
	}


	/* Times - take it from fs_inode instead of redoing the work */

	if (sec_skew != 0) {
	    tsk_fprintf(hFile, "\nAdjusted times:\n");
	    fs_inode->mtime -= sec_skew;
	    fs_inode->atime -= sec_skew;
	    fs_inode->ctime -= sec_skew;
	    fs_inode->crtime -= sec_skew;
	    tsk_fprintf(hFile, "Created:\t%s", ctime(&fs_inode->crtime));
	    tsk_fprintf(hFile, "File Modified:\t%s",
		ctime(&fs_inode->mtime));
	    tsk_fprintf(hFile, "MFT Modified:\t%s",
		ctime(&fs_inode->ctime));
	    tsk_fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
	    fs_inode->mtime += sec_skew;
	    fs_inode->atime += sec_skew;
	    fs_inode->ctime += sec_skew;
	    fs_inode->crtime += sec_skew;
	    tsk_fprintf(hFile, "\nOriginal times:\n");
	}

	tsk_fprintf(hFile, "Created:\t%s", ctime(&fs_inode->crtime));
	tsk_fprintf(hFile, "File Modified:\t%s", ctime(&fs_inode->mtime));
	tsk_fprintf(hFile, "MFT Modified:\t%s", ctime(&fs_inode->ctime));
	tsk_fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
    }

    /* $FILE_NAME Information */
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_FNAME);
    if (fs_data) {

	ntfs_attr_fname *fname = (ntfs_attr_fname *) fs_data->buf;
	time_t cr_time, m_time, c_time, a_time;
	uint64_t flags;
	int a = 0;
	tsk_fprintf(hFile, "\n$FILE_NAME Attribute Values:\n");
	flags = getu64(fs->endian, fname->flags);
	tsk_fprintf(hFile, "Flags: ");
	if (flags & NTFS_FNAME_FLAGS_DIR)
	    tsk_fprintf(hFile, "%sDirectory", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_DEV)
	    tsk_fprintf(hFile, "%sDevice", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_NORM)
	    tsk_fprintf(hFile, "%sNormal", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_RO)
	    tsk_fprintf(hFile, "%sRead Only", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_HID)
	    tsk_fprintf(hFile, "%sHidden", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_SYS)
	    tsk_fprintf(hFile, "%sSystem", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_ARCH)
	    tsk_fprintf(hFile, "%sArchive", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_TEMP)
	    tsk_fprintf(hFile, "%sTemp", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_SPAR)
	    tsk_fprintf(hFile, "%sSparse", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_REP)
	    tsk_fprintf(hFile, "%sReparse Point", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_COMP)
	    tsk_fprintf(hFile, "%sCompressed", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_ENC)
	    tsk_fprintf(hFile, "%sEncrypted", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_OFF)
	    tsk_fprintf(hFile, "%sOffline", a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_NOIDX)
	    tsk_fprintf(hFile, "%sNot Content Indexed",
		a++ == 0 ? "" : ", ");
	if (flags & NTFS_FNAME_FLAGS_IDXVIEW)
	    tsk_fprintf(hFile, "%sIndex View", a++ == 0 ? "" : ", ");
	tsk_fprintf(hFile, "\n");
	/* We could look this up in the attribute, but we already did
	 * the work */
	if (fs_inode->name) {
	    FS_NAME *fs_name = fs_inode->name;
	    tsk_fprintf(hFile, "Name: ");
	    while (fs_name) {
		tsk_fprintf(hFile, "%s", fs_name->name);
		fs_name = fs_name->next;
		if (fs_name)
		    tsk_fprintf(hFile, ", ");
		else
		    tsk_fprintf(hFile, "\n");
	    }
	}

	tsk_fprintf(hFile,
	    "Parent MFT Entry: %" PRIu64
	    " \tSequence: %" PRIu16 "\n",
	    (uint64_t) getu48(fs->endian, fname->par_ref),
	    getu16(fs->endian, fname->par_seq));
	tsk_fprintf(hFile,
	    "Allocated Size: %" PRIu64
	    "   \tActual Size: %" PRIu64 "\n",
	    getu64(fs->endian, fname->alloc_fsize), getu64(fs->endian,
		fname->real_fsize));
	/* 
	 * Times 
	 */
	cr_time = nt2unixtime(getu64(fs->endian, fname->crtime));
	/* altered - modified */
	m_time = nt2unixtime(getu64(fs->endian, fname->mtime));
	/* MFT modified */
	c_time = nt2unixtime(getu64(fs->endian, fname->ctime));
	/* Access */
	a_time = nt2unixtime(getu64(fs->endian, fname->atime));
	if (sec_skew != 0) {
	    tsk_fprintf(hFile, "\nAdjusted times:\n");
	    cr_time -= sec_skew;
	    m_time -= sec_skew;
	    a_time -= sec_skew;
	    c_time -= sec_skew;
	    tsk_fprintf(hFile, "Created:\t%s", ctime(&cr_time));
	    tsk_fprintf(hFile, "File Modified:\t%s", ctime(&m_time));
	    tsk_fprintf(hFile, "MFT Modified:\t%s", ctime(&c_time));
	    tsk_fprintf(hFile, "Accessed:\t%s", ctime(&a_time));
	    cr_time += sec_skew;
	    m_time += sec_skew;
	    a_time += sec_skew;
	    c_time += sec_skew;
	    tsk_fprintf(hFile, "\nOriginal times:\n");
	}

	tsk_fprintf(hFile, "Created:\t%s", ctime(&cr_time));
	tsk_fprintf(hFile, "File Modified:\t%s", ctime(&m_time));
	tsk_fprintf(hFile, "MFT Modified:\t%s", ctime(&c_time));
	tsk_fprintf(hFile, "Accessed:\t%s", ctime(&a_time));
    }


    /* $OBJECT_ID Information */
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_OBJID);
    if (fs_data) {
	ntfs_attr_objid *objid = (ntfs_attr_objid *) fs_data->buf;
	uint64_t id1, id2;
	tsk_fprintf(hFile, "\n$OBJECT_ID Attribute Values:\n");
	id1 = getu64(fs->endian, objid->objid1);
	id2 = getu64(fs->endian, objid->objid2);
	tsk_fprintf(hFile,
	    "Object Id: %.8" PRIx32 "-%.4" PRIx16
	    "-%.4" PRIx16 "-%.4" PRIx16 "-%.12"
	    PRIx64 "\n",
	    (uint32_t) (id2 >> 32) & 0xffffffff,
	    (uint16_t) (id2 >> 16) & 0xffff,
	    (uint16_t) (id2 & 0xffff),
	    (uint16_t) (id1 >> 48) & 0xffff, (uint64_t) (id1 & (uint64_t)
		0x0000ffffffffffffULL));
	/* The rest of the  fields do not always exist.  Check the attr size */
	if (fs_data->size > 16) {
	    id1 = getu64(fs->endian, objid->orig_volid1);
	    id2 = getu64(fs->endian, objid->orig_volid2);
	    tsk_fprintf(hFile,
		"Birth Volume Id: %.8" PRIx32 "-%.4"
		PRIx16 "-%.4" PRIx16 "-%.4" PRIx16
		"-%.12" PRIx64 "\n",
		(uint32_t) (id2 >> 32) & 0xffffffff,
		(uint16_t) (id2 >> 16) & 0xffff,
		(uint16_t) (id2 & 0xffff),
		(uint16_t) (id1 >> 48) & 0xffff,
		(uint64_t) (id1 & (uint64_t)
		    0x0000ffffffffffffULL));
	}

	if (fs_data->size > 32) {
	    id1 = getu64(fs->endian, objid->orig_objid1);
	    id2 = getu64(fs->endian, objid->orig_objid2);
	    tsk_fprintf(hFile,
		"Birth Object Id: %.8" PRIx32 "-%.4"
		PRIx16 "-%.4" PRIx16 "-%.4" PRIx16
		"-%.12" PRIx64 "\n",
		(uint32_t) (id2 >> 32) & 0xffffffff,
		(uint16_t) (id2 >> 16) & 0xffff,
		(uint16_t) (id2 & 0xffff),
		(uint16_t) (id1 >> 48) & 0xffff,
		(uint64_t) (id1 & (uint64_t)
		    0x0000ffffffffffffULL));
	}

	if (fs_data->size > 48) {
	    id1 = getu64(fs->endian, objid->orig_domid1);
	    id2 = getu64(fs->endian, objid->orig_domid2);
	    tsk_fprintf(hFile,
		"Birth Domain Id: %.8" PRIx32 "-%.4"
		PRIx16 "-%.4" PRIx16 "-%.4" PRIx16
		"-%.12" PRIx64 "\n",
		(uint32_t) (id2 >> 32) & 0xffffffff,
		(uint16_t) (id2 >> 16) & 0xffff,
		(uint16_t) (id2 & 0xffff),
		(uint16_t) (id1 >> 48) & 0xffff,
		(uint64_t) (id1 & (uint64_t)
		    0x0000ffffffffffffULL));
	}
    }

    /* Attribute List Information */
    fs_data = fs_data_lookup_noid(fs_inode->attr, NTFS_ATYPE_ATTRLIST);
    if (fs_data) {
	char *buf;
	ntfs_attrlist *list;
	uintptr_t endaddr;
	FS_LOAD_FILE load_file;

	tsk_fprintf(hFile, "\n$ATTRIBUTE_LIST Attribute Values:\n");

	/* Get a copy of the attribute list stream  */
	load_file.total = load_file.left = (size_t) fs_data->size;
	load_file.cur = load_file.base = buf =
	    mymalloc((size_t) fs_data->size);
	if (buf == NULL) {
	    return 1;
	}

	endaddr = (uintptr_t) buf + (uintptr_t) fs_data->size;
	if (ntfs_data_walk(ntfs, fs_inode->addr, fs_data,
		0, load_file_action, (void *) &load_file)) {
	    tsk_fprintf(hFile, "error reading attribute list buffer\n");
	    tsk_error_reset();
	    goto egress;
	}

	/* this value should be zero, if not then we didn't read all of the
	 * buffer
	 */
	if (load_file.left > 0) {
	    tsk_fprintf(hFile, "error reading attribute list buffer\n");
	    goto egress;
	}

	/* Process the list & print the details */
	for (list = (ntfs_attrlist *) buf;
	    (list) && ((uintptr_t) list < endaddr)
	    && (getu16(fs->endian, list->len) > 0);
	    list =
	    (ntfs_attrlist *) ((uintptr_t) list + getu16(fs->endian,
		    list->len))) {
	    tsk_fprintf(hFile,
		"Type: %" PRIu32 "-%" PRIu16 " \tMFT Entry: %" PRIu64
		" \tVCN: %" PRIu64 "\n", getu32(fs->endian, list->type),
		getu16(fs->endian, list->id), (uint64_t) getu48(fs->endian,
		    list->file_ref), getu64(fs->endian, list->start_vcn));
	}
      egress:
	free(buf);
    }

    /* Print all of the attributes */
    tsk_fprintf(hFile, "\nAttributes: \n");
    for (fs_data = fs_inode->attr;
	fs_data != NULL; fs_data = fs_data->next) {
	char type[512];

	if ((fs_data->flags & FS_DATA_INUSE) == 0)
	    continue;

	if (ntfs_attrname_lookup(fs, fs_data->type, type, 512)) {
	    tsk_fprintf(hFile, "error looking attribute name\n");
	    break;
	}
	tsk_fprintf(hFile,
	    "Type: %s (%" PRIu32 "-%" PRIu16
	    ")   Name: %s   %sResident%s%s%s   size: %"
	    PRIuOFF "\n", type, fs_data->type,
	    fs_data->id, fs_data->name,
	    (fs_data->
		flags & FS_DATA_NONRES) ? "Non-" :
	    "",
	    (fs_data->
		flags & FS_DATA_ENC) ? ", Encrypted"
	    : "",
	    (fs_data->
		flags & FS_DATA_COMP) ?
	    ", Compressed" : "",
	    (fs_data->
		flags & FS_DATA_SPAR) ? ", Sparse" : "", fs_data->size);

	/* print the layout if it is non-resident and not "special" */
	if (fs_data->flags & FS_DATA_NONRES) {
	    NTFS_PRINT_ADDR print_addr;
	    print_addr.idx = 0;
	    print_addr.hFile = hFile;
	    if (fs->file_walk(fs, fs_inode, fs_data->type,
		    fs_data->id,
		    (FS_FLAG_FILE_AONLY |
			FS_FLAG_FILE_SLACK),
		    print_addr_act, (void *) &print_addr)) {
		tsk_fprintf(hFile, "\nError walking file\n");
		tsk_error_reset();
	    }
	    if (print_addr.idx != 0)
		tsk_fprintf(hFile, "\n");
	}
    }

    fs_inode_free(fs_inode);
    return 0;
}



/* JOURNAL CODE - MOVE TO NEW FILE AT SOME POINT */

uint8_t
ntfs_jopen(FS_INFO * fs, INUM_T inum)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
	"NTFS Journal is not yet supported\n");
    return 1;
}

uint8_t
ntfs_jentry_walk(FS_INFO * fs, int flags,
    FS_JENTRY_WALK_FN action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
	"NTFS Journal is not yet supported\n");
    return 1;
}


uint8_t
ntfs_jblk_walk(FS_INFO * fs, DADDR_T start,
    DADDR_T end, int flags, FS_JBLK_WALK_FN action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
	"NTFS Journal is not yet supported\n");
    return 1;
}



static void
ntfs_secure_data_free(NTFS_INFO * ntfs)
{
    NTFS_SDS_ENTRY *nsds;
    NTFS_SID_ENTRY *nsid;

    // Iterate of sds entries and free them
    while (ntfs->sds) {
	nsds = ntfs->sds->next;
	free(ntfs->sds->data);
	free(ntfs->sds);
	ntfs->sds = nsds;
    }

    // Iterate of sid entries and free them
    while (ntfs->sid) {
	nsid = ntfs->sid->next;
	free(ntfs->sid->data);
	free(ntfs->sid->sid_str);
	free(ntfs->sid);
	ntfs->sid = nsid;
    }
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
    ntfs_secure_data_free(ntfs);

    if (fs->list_inum_named) {
	tsk_list_free(fs->list_inum_named);
	fs->list_inum_named = NULL;
    }

    free(fs);
}


/* Return NULL on error */
FS_INFO *
ntfs_open(IMG_INFO * img_info, SSIZE_T offset, uint8_t ftype, uint8_t test)
{
    char *myname = "ntfs_open";
    NTFS_INFO *ntfs;
    FS_INFO *fs;
    unsigned int len;
    SSIZE_T cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((ftype & FSMASK) != NTFS_TYPE) {
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L, "Invalid FS type in ntfs_open");
	return NULL;
    }

    if ((ntfs = (NTFS_INFO *) mymalloc(sizeof(*ntfs))) == NULL) {
	return NULL;
    }
    fs = &(ntfs->fs_info);

    fs->ftype = ftype;
    fs->flags = FS_HAVE_SEQ;
    fs->img_info = img_info;
    fs->offset = offset;

    ntfs->loading_the_MFT = 0;
    ntfs->bmap = NULL;
    ntfs->bmap_buf = NULL;

    /* Read the boot sector */
    len = roundup(sizeof(ntfs_sb), NTFS_DEV_BSIZE);
    ntfs->fs = (ntfs_sb *) mymalloc(len);
    if (ntfs->fs == NULL) {
	free(ntfs);
	return NULL;
    }

    cnt = fs_read_random(fs, (char *) ntfs->fs, len, (OFF_T) 0);
    if (cnt != len) {
	if (cnt != -1) {
	    tsk_error_reset();
	    tsk_errno = TSK_ERR_FS_READ;
	}
	snprintf(tsk_errstr2, TSK_ERRSTR_L,
	    "%s: Error reading boot sector.", myname);
	free(ntfs->fs);
	free(ntfs);
	return NULL;
    }

    /* Check the magic value */
    if (fs_guessu16(fs, ntfs->fs->magic, NTFS_FS_MAGIC)) {
	free(ntfs->fs);
	free(ntfs);
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_MAGIC;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "Not a NTFS file system (magic)");
	return NULL;
    }


    /*
     * block calculations : although there are no blocks in ntfs,
     * we are using a cluster as a "block"
     */

    ntfs->ssize_b = getu16(fs->endian, ntfs->fs->ssize);
    if (ntfs->ssize_b % 512) {
	free(ntfs->fs);
	free(ntfs);
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_MAGIC;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "Not a NTFS file system (invalid sector size)");
	return NULL;
    }

    if ((ntfs->fs->csize != 0x01) &&
	(ntfs->fs->csize != 0x02) &&
	(ntfs->fs->csize != 0x04) &&
	(ntfs->fs->csize != 0x08) &&
	(ntfs->fs->csize != 0x10) &&
	(ntfs->fs->csize != 0x20) && (ntfs->fs->csize != 0x40)
	&& (ntfs->fs->csize != 0x80)) {

	free(ntfs->fs);
	free(ntfs);
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_MAGIC;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "Not a NTFS file system (invalid cluster size)");
	return NULL;
    }

    ntfs->csize_b = ntfs->fs->csize * ntfs->ssize_b;
    fs->first_block = 0;
    /* This field is defined as 64-bits but according to the
     * NTFS drivers in Linux, windows only uses 32-bits
     */
    fs->block_count =
	(DADDR_T) getu32(fs->endian,
	ntfs->fs->vol_size_s) / ntfs->fs->csize;
    fs->last_block = fs->block_count - 1;
    fs->block_size = ntfs->csize_b;
    fs->dev_bsize = NTFS_DEV_BSIZE;
    if (ntfs->fs->mft_rsize_c > 0)
	ntfs->mft_rsize_b = ntfs->fs->mft_rsize_c * ntfs->csize_b;
    else
	/* if the mft_rsize_c is not > 0, then it is -log2(rsize_b) */
	ntfs->mft_rsize_b = 1 << -ntfs->fs->mft_rsize_c;
    if (ntfs->mft_rsize_b % 512) {
	free(ntfs->fs);
	free(ntfs);
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_MAGIC;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "Not a NTFS file system (invalid MFT entry size)");
	return NULL;
    }

    if (ntfs->fs->idx_rsize_c > 0)
	ntfs->idx_rsize_b = ntfs->fs->idx_rsize_c * ntfs->csize_b;
    else
	/* if the idx_rsize_c is not > 0, then it is -log2(rsize_b) */
	ntfs->idx_rsize_b = 1 << -ntfs->fs->idx_rsize_c;
    if (ntfs->idx_rsize_b % 512) {
	free(ntfs->fs);
	free(ntfs);
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_MAGIC;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "Not a NTFS file system (invalid idx record size)");
	return NULL;
    }

    ntfs->root_mft_addr =
	getu64(fs->endian, ntfs->fs->mft_clust) * ntfs->csize_b;
    if (getu64(fs->endian, ntfs->fs->mft_clust) > fs->last_block) {
	free(ntfs->fs);
	free(ntfs);
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_MAGIC;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "Not a NTFS file system (invalid starting MFT clust)");
	return NULL;
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
    if (ntfs->mft == NULL) {
	free(ntfs->fs);
	free(ntfs);
	return NULL;
    }

    ntfs->mnum = 0;
    fs->root_inum = NTFS_ROOTINO;
    fs->first_inum = NTFS_FIRSTINO;
    fs->last_inum = NTFS_LAST_DEFAULT_INO;
    ntfs->mft_data = NULL;

    /* load the data run for the MFT table into ntfs->mft */
    ntfs->loading_the_MFT = 1;
    if (ntfs_dinode_lookup(ntfs, ntfs->mft, NTFS_MFT_MFT)) {
	free(ntfs->mft);
	free(ntfs->fs);
	free(ntfs);
	return NULL;
    }

    ntfs->mft_inode = fs_inode_alloc(NTFS_NDADDR, NTFS_NIADDR);
    if (ntfs->mft_inode == NULL) {
	free(ntfs->mft);
	free(ntfs->fs);
	free(ntfs);
	return NULL;
    }
    if (ntfs_dinode_copy(ntfs, ntfs->mft_inode)) {
	fs_inode_free(ntfs->mft_inode);
	free(ntfs->mft);
	free(ntfs->fs);
	free(ntfs);
	return NULL;
    }

    /* cache the data attribute 
     *
     * This will likely be done already by proc_attrseq, but this
     * should be quick
     */
    ntfs->mft_data =
	fs_data_lookup_noid(ntfs->mft_inode->attr, NTFS_ATYPE_DATA);
    if (!ntfs->mft_data) {
	fs_inode_free(ntfs->mft_inode);
	free(ntfs->mft);
	free(ntfs->fs);
	free(ntfs);
	strncat(tsk_errstr2, " - Data Attribute not found in $MFT",
	    TSK_ERRSTR_L - strlen(tsk_errstr2));
	return NULL;
    }

    /* Get the inode count based on the table size */
    fs->inum_count = ntfs->mft_data->size / ntfs->mft_rsize_b;
    fs->last_inum = fs->inum_count - 1;

    /* reset the flag that we are no longer loading $MFT */
    ntfs->loading_the_MFT = 0;

    /* load the version of the file system */
    if (ntfs_load_ver(ntfs)) {
	fs_inode_free(ntfs->mft_inode);
	free(ntfs->mft);
	free(ntfs->fs);
	free(ntfs);
	return NULL;
    }

    /* load the data block bitmap data run into ntfs_info */
    if (ntfs_load_bmap(ntfs)) {
	fs_inode_free(ntfs->mft_inode);
	free(ntfs->mft);
	free(ntfs->fs);
	free(ntfs);
	return NULL;
    }

    /* load the SID data into ntfs_info ($Secure - $SDS, $SDH, $SII */
    if (ntfs_load_secure(ntfs)) {
	fs_inode_free(ntfs->mft_inode);
	free(ntfs->mft);
	free(ntfs->fs);
	free(ntfs);
	return NULL;
    }


    /* set this to NULL and it will be loaded if needed */
    ntfs->attrdef = NULL;
    fs->jblk_walk = ntfs_jblk_walk;
    fs->jentry_walk = ntfs_jentry_walk;
    fs->jopen = ntfs_jopen;
    fs->journ_inum = 0;

    fs->list_inum_named = NULL;

    if (verbose) {
	tsk_fprintf(stderr,
	    "ssize: %" PRIu16
	    " csize: %d serial: %" PRIx64 "\n",
	    getu16(fs->endian, ntfs->fs->ssize),
	    ntfs->fs->csize, getu64(fs->endian, ntfs->fs->serial));
	tsk_fprintf(stderr,
	    "mft_rsize: %d idx_rsize: %d vol: %d mft: %"
	    PRIu64 " mft_mir: %" PRIu64 "\n",
	    ntfs->mft_rsize_b, ntfs->idx_rsize_b,
	    (int) fs->block_count, getu64(fs->endian,
		ntfs->fs->mft_clust), getu64(fs->endian,
		ntfs->fs->mftm_clust));
    }

    return fs;
}
