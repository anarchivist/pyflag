/*
** fatfs
** The Sleuth Kit 
**
** Content and meta data layer support for the FAT file system 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
*/

#include "fs_tools.h"
#include "fs_types.h"
#include "fatfs.h"
#include "fs_io.h"
#include "mymalloc.h"
#include "error.h"


/*
 * Implementation NOTES 
 *
 * FS_INODE contains the first cluster.  file_walk will return sector
 * values though because the cluster numbers do not start until after
 * the FAT.  That makes it very hard to address the first few blocks!
 *
 * Inodes numbers do not exist in FAT.  To make up for this we will count
 * directory entries as the inodes.   As the root directory does not have
 * any records in FAT, we will give it times of 0 and call it inode 2 to
 * keep consistent with UNIX.  After that, each 32-byte slot is numbered
 * as though it were a directory entry (even if it is not).  Therefore,
 * when an inode walk is performed, not all inode values will be displayed
 * even when '-e' is given for ils. 
 *
 * Progs like 'ils -e' are very slow because we have to look at each
 * block to see if it is a file system structure.
 */


/*
 * Return the entry in the File Allocation Table (FAT) for the given 
 * cluster
 *
 * The return value is in clusters and may need to be coverted to
 * sectors by the calling function
 */
static u_int32_t 
getFAT(FATFS_INFO *fatfs, u_int32_t clust)
{
	u_int8_t *ptr;
	u_int16_t tmp16;
	u_int32_t retval = 0;
	FS_INFO *fs = (FS_INFO *) & fatfs->fs_info;
	DADDR_T	sect, offs;

	/* Sanity Check */
	if (clust > fatfs->lastclust)
		return 0;

	switch (fatfs->fs_info.ftype) {
	  case MS12_FAT:
		if (clust & 0xf000)
			error("getFAT: FAT12 Cluster %d too large", clust);

		/* id the sector in the FAT */
		sect = fatfs->firstfatsect + (clust + clust / 2) / fatfs->ssize;

		/* Load the FAT if we don't have it */
		if ((sect < fatfs->table->addr) || 
		  (sect >= (fatfs->table->addr + FAT_CACHE_S)) ||
		  (-1 == fatfs->table->addr) ) {
			fs->read_block (fs, fatfs->table, FAT_CACHE_B, sect, "getFAT FAT12");
		}

		/* get the offset into the cache */
		offs = (sect - fatfs->table->addr)*fatfs->ssize + 
		  (clust + clust / 2) % fatfs->ssize; 

		/* special case when the 12-bit value goes across the cache
		 * we load the cache to start at this sect.  The cache
		 * size must therefore be at least 2 sectors large 
		 */
		if (offs == (FAT_CACHE_B - 1) )  {
			fs->read_block (fs, fatfs->table, FAT_CACHE_B, sect, "getFAT FAT12 - overlap");

			offs = (sect - fatfs->table->addr)*fatfs->ssize + 
			  (clust + clust / 2) % fatfs->ssize; 
		}

		/* get pointer to entry in current buffer */
		ptr = fatfs->table->data + offs;

		tmp16 = getu16(fs, ptr);

		/* slide it over if it is one of the odd clusters */
		if (clust & 1)
			tmp16 >>= 4;

		retval = tmp16 & FATFS_12_MASK;

		/* sanity check */
		if ((retval > (fatfs->lastclust)) &&
		  (retval < (0x0ffffff7 & FATFS_12_MASK)))
			error ("getFAT: return FAT12 cluster (%d) too large (%d)", 
			  clust, retval);

		break;

	  case MS16_FAT:
		/* Get sector in FAT for cluster and load it if needed */
		sect = fatfs->firstfatsect + (clust * 2) / fatfs->ssize;
		if ((sect < fatfs->table->addr) || 
		  (sect >= (fatfs->table->addr + FAT_CACHE_S)) ||
		  (-1 == fatfs->table->addr) ) 
			fs->read_block (fs, fatfs->table, FAT_CACHE_B, sect, "getFAT FAT16");

		/* get pointer to entry in current buffer */
		ptr = fatfs->table->data +
		  (sect - fatfs->table->addr)*fatfs->ssize + 
		  (clust * 2) % fatfs->ssize; 

		retval = getu16(fs, ptr) & FATFS_16_MASK;

		/* sanity check */
		if ((retval > (fatfs->lastclust)) &&
		  (retval < (0x0ffffff7 & FATFS_16_MASK)))
			error ("getFAT: return FAT16 cluster too large");

		break;

	  case MS32_FAT:
		/* Get sector in FAT for cluster and load if needed */
		sect = fatfs->firstfatsect + (clust * 4) / fatfs->ssize;
		if ((sect < fatfs->table->addr) || 
		  (sect >= (fatfs->table->addr + FAT_CACHE_S)) ||
		  (-1 == fatfs->table->addr) ) 
			fs->read_block (fs, fatfs->table, FAT_CACHE_B, sect, "getFAT FAT32");


		/* get pointer to entry in current buffer */
		ptr = fatfs->table->data +
		  (sect - fatfs->table->addr)*fatfs->ssize + 
		  (clust * 4) % fatfs->ssize; 

		retval = getu32(fs, ptr) & FATFS_32_MASK;

		/* sanity check */
		if ((retval > fatfs->lastclust) &&
		  (retval < (0x0ffffff7 & FATFS_32_MASK)))
			error ("getFAT: return cluster too large");
		
		break;
	}

	if (verbose)
		fprintf (logfp,
		  "fatfs_getFAT: Lookup Cluster %lu to %lu\n", 
		  (ULONG)clust, (ULONG)retval);


	return retval;
}


/* 
 * Identifies if a sector is allocated
 *
 * If it is less than the data area, then it is allocated
 * else the FAT table is consulted
 *
 */
u_int8_t
is_sectalloc(FATFS_INFO *fatfs, int sect) 
{
	/* If less than the first cluster sector, then it is allocated 
	 * otherwise check the FAT
	*/
	if (sect < fatfs->firstclustsect)
		return 1;

	return is_clustalloc(fatfs, FATFS_SECT_2_CLUST(fatfs, sect));
}


/* 
 * Identify if the dentry is a valid 8.3 name
 *
 * returns 1 if it is, 0 if it does not
 */
static u_int8_t
is_83_name(fatfs_dentry *de) 
{
	if (!de)
		return 0;

	/* The IS_NAME macro will fail if the value is 0x05, which is only
	 * valid in name[0], similarly with '.' */
	if ((de->name[0] != FATFS_SLOT_E5) && (de->name[0] != '.') && 
	  (de->name[0] != FATFS_SLOT_DELETED) && 
	  (FATFS_IS_83_NAME(de->name[0]) == 0))
			return 0;

	/* the second name field can only be . if the first one is a . */
	if (de->name[1] == '.') {
		if (de->name[0] != '.') 
			return 0;
	}
	else if (FATFS_IS_83_NAME(de->name[1]) == 0)
			return 0;

	if ( 
	  (FATFS_IS_83_NAME(de->name[2]) == 0) ||
	  (FATFS_IS_83_NAME(de->name[3]) == 0) || 
	  (FATFS_IS_83_NAME(de->name[4]) == 0) ||
	  (FATFS_IS_83_NAME(de->name[5]) == 0) ||
	  (FATFS_IS_83_NAME(de->name[6]) == 0) ||
	  (FATFS_IS_83_NAME(de->name[7]) == 0) ||
	  (FATFS_IS_83_NAME(de->ext[0]) == 0) || 
	  (FATFS_IS_83_NAME(de->ext[1]) == 0) || 
	  (FATFS_IS_83_NAME(de->ext[2]) == 0) )
		return 0;
	else
		return 1;
}

/*
 * Check if the given lfn entry has a valid long name
 * We are only looking at the ASCII equivalent of UNICODE
 *
 * The char set for lfn is larger than that of 8.3
 *
 * return 1 if valid name, 0 if not
 */
static u_int8_t
is_lfn_name(fatfs_dentry_lfn *de) 
{
	int i;
	if (!de)
		return 0;

	for (i=0; i < 10; i+=2) 
		if (FATFS_IS_LFN_NAME(de->part1[i]) == 0)
			return 0;
	for (i=0; i < 12; i+=2) 
		if (FATFS_IS_LFN_NAME(de->part2[i]) == 0)
			return 0;
	for (i=0; i < 4; i+=2) 
		if (FATFS_IS_LFN_NAME(de->part3[i]) == 0)
			return 0;

	return 1;
}


/**************************************************************************
 *
 * BLOCK WALKING
 * 
 *************************************************************************/
/* 
** Walk the sectors of the partition. 
**
** NOTE: This is by SECTORS and not CLUSTERS
** _flags: FS_FLAG_DATA_ALLOC, FS_FLAG_DATA_UNALLOC, FS_FLAG_DATA_META
**  FS_FLAG_DATA_CONT
**
** We do not use FS_FLAG_DATA_ALIGN
**
*/
void
fatfs_block_walk(FS_INFO *fs, DADDR_T start, DADDR_T last, int flags,
          FS_BLOCK_WALK_FN action, char *ptr)
{
    char   		*myname = "fatfs_block_walk";
    FATFS_INFO 	*fatfs = (FATFS_INFO *) fs;
    FS_BUF 		*fs_buf = fs_buf_alloc(fs->block_size);
    DADDR_T 	addr;
    int     	myflags;

    /*
     * Sanity checks.
     */
    if (start < fs->first_block || start > fs->last_block)
        error("%s: invalid start block number: %lu", myname, (ULONG) start);
    if (last < fs->first_block || last > fs->last_block)
        error("%s: invalid last block number: %lu", myname, (ULONG) last);

    if (verbose)
		fprintf (logfp,
		  "fatfs_block_walk: Block Walking %lu to %lu\n", 
		  (ULONG)start, (ULONG)last);

	/* cycle through block addresses */
	for (addr = start; addr <= last; addr++) {

		/* Identify its allocation status */
		myflags = ((is_sectalloc(fatfs, addr)) ?
			FS_FLAG_DATA_ALLOC : FS_FLAG_DATA_UNALLOC);


		/* Anything less than the first data sector is either the FAT 
		 * tables or super block stuff - therefore meta
		 */
		if (addr < fatfs->firstdatasect)
			myflags |= FS_FLAG_DATA_META;
		else
			myflags |= FS_FLAG_DATA_CONT;

		if ((flags & myflags) == myflags) {

				
			fs->read_block(fs, fs_buf, fs->block_size, addr, "block_walk: data block");
			if (WALK_STOP == action(fs, addr, fs_buf->data, myflags, ptr)) {
				fs_buf_free(fs_buf);
				return;
			}	
		}
	}

	fs_buf_free(fs_buf);
	return;
}


/*
** Convert the DOS time to the UNIX version
** 
** UNIX stores the time in seconds from 1970 in UTC
** FAT dates are the actual date with the year relative to 1980
** 
*/
static int
dos2unixtime(u_int16_t date, u_int16_t time)
{
	struct tm tm1;
	int ret;

	if (date == 0) 
		return 0;

	tm1.tm_sec = ((time & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) * 2;
	if ((tm1.tm_sec < 0) || (tm1.tm_sec > 60))
		tm1.tm_sec = 0;

	tm1.tm_min = ((time & FATFS_MIN_MASK) >> FATFS_MIN_SHIFT);
	if ((tm1.tm_min < 0) || (tm1.tm_min > 59))
		tm1.tm_min = 0;

	tm1.tm_hour = ((time & FATFS_HOUR_MASK) >> FATFS_HOUR_SHIFT);
	if ((tm1.tm_hour < 0) || (tm1.tm_hour > 23))
		tm1.tm_hour= 0;

	tm1.tm_mday = ((date & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT);
	if ((tm1.tm_mday < 1) || (tm1.tm_mday > 31))
		tm1.tm_mday = 0;

	tm1.tm_mon = ((date & FATFS_MON_MASK) >> FATFS_MON_SHIFT) - 1;
	if ((tm1.tm_mon < 0) || (tm1.tm_mon > 11))
		tm1.tm_mon = 0;

	tm1.tm_year = ((date & FATFS_YEAR_MASK) >> FATFS_YEAR_SHIFT) + 80;

	/* set the daylight savings variable to -1 so that mktime() figures
	 * it out */
	tm1.tm_isdst = -1;

	ret = mktime (&tm1);

	if (-1 == ret)  
		error ("dos2unixtime: Error running mktime(): %d:%d:%d %d/%d/%d",
	((time & FATFS_HOUR_MASK) >> FATFS_HOUR_SHIFT),
	((time & FATFS_MIN_MASK) >> FATFS_MIN_SHIFT),
	((time & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) * 2,
	((date & FATFS_MON_MASK) >> FATFS_MON_SHIFT) - 1,
	((date & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT),
	((date & FATFS_YEAR_MASK) >> FATFS_YEAR_SHIFT) + 80
		  );
	

	return ret;
}



/* 
 * convert the attribute list in FAT to a UNIX mode 
 */
static int
dos2unixmode(u_int16_t attr)
{
	int mode;

	/* every file is executable */
	mode = (MODE_IXUSR | MODE_IXGRP | MODE_IXOTH);

	/* file type */
	if (attr & FATFS_ATTR_DIRECTORY)
		mode |= FS_INODE_DIR;
	else
		mode |= FS_INODE_REG;

	if ((attr & FATFS_ATTR_READONLY) == 0)
		mode |= (MODE_IRUSR | MODE_IRGRP | MODE_IROTH);

	if ((attr & FATFS_ATTR_HIDDEN) == 0)
		mode |= (MODE_IWUSR | MODE_IWGRP | MODE_IWOTH);

	return mode;
}


/*
 * Copy the contents of a dentry into a FS_INFO structure
 *
 * The addr is the sector address of where the inode is from.  It is 
 * needed to determine the allocation status.
 */
static void
fatfs_copy_inode(FATFS_INFO *fatfs, FS_INODE *fs_inode, DADDR_T sect)
{
	fatfs_dentry    *in = fatfs->dep;
	int 		cnum, i;
	u_int32_t 	dcnt, clust;
	FS_INFO *fs = (FS_INFO *)&fatfs->fs_info;

	fs_inode->mode = dos2unixmode(in->attrib);

	/* No notion of UID, so set it to 0 */ 
	fs_inode->uid = 0;
	fs_inode->gid = 0;




	/* There is no notion of link in FAT, just deleted or not */
	if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
		fs_inode->nlink = 0;
		fs_inode->size = 0;
	}
	else {
		fs_inode->nlink = (in->name[0] == FATFS_SLOT_DELETED)? 0 : 1;
		fs_inode->size = (OFF_T) getu32(fs, in->size);
	}



	/* If these are valid dates, then convert to a unix date format */
	if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
		fs_inode->mtime = 0;
		fs_inode->atime = 0;
		fs_inode->ctime = 0;
	}
	else {

		if (FATFS_ISDATE(getu16(fs, in->wdate)))
			fs_inode->mtime = dos2unixtime(getu16(fs, in->wdate), 
			  getu16(fs, in->wtime));
		else
			fs_inode->mtime = 0;

		if (FATFS_ISDATE(getu16(fs, in->adate)))
			fs_inode->atime = dos2unixtime(getu16(fs, in->adate), 0);
		else
			fs_inode->atime = 0;


		/* cdate is the creation date in FAT and there is no change,
		 * so we just put in into change and set create to 0.  The other
		 * front-end code knows how to handle it and display it
		 */
		if (FATFS_ISDATE(getu16(fs, in->cdate)))
			fs_inode->ctime = 
			  dos2unixtime(getu16(fs, in->cdate), getu16(fs, in->ctime));
		else
			fs_inode->ctime = 0;
	}

	fs_inode->crtime = 0;
	fs_inode->dtime = 0;

	fs_inode->seq = 0;

	/* 
	 * add the 8.3 file name 
	 */
	if (fs_inode->name == NULL) {
		fs_inode->name = (FS_NAME *)mymalloc(sizeof(FS_NAME));	
		fs_inode->name->next = NULL;
	}

	if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
		int a;
		fatfs_dentry_lfn *lfn = (fatfs_dentry_lfn *)fatfs->dep;
		i = 0;
		
		for (a = 0; a < 10; a+=2) {
			if ((lfn->part1[a] != 0) && (lfn->part1[a] != 0xff)) {
				fs_inode->name->name[i++] = lfn->part1[a];
			}
		}
		for (a = 0; a < 12; a+=2) {
			if ((lfn->part2[a] != 0) && (lfn->part2[a] != 0xff)) {
				fs_inode->name->name[i++] = lfn->part2[a];
			}
		}
		for (a = 0; a < 4; a+=2) {
			if ((lfn->part3[a] != 0) && (lfn->part3[a] != 0xff)) {
				fs_inode->name->name[i++] = lfn->part3[a];
			}
		}
		fs_inode->name->name[i++] = '\0';
	} 
	else if ((in->attrib & FATFS_ATTR_VOLUME) == FATFS_ATTR_VOLUME) {
		int a;
		i = 0;
		for (a = 0; a < 8; a++) {
			if ((in->name[a] != 0x00) && (in->name[a] != 0xff))
				fs_inode->name->name[i++] = in->name[a];
		}
		for (a = 0; a < 3; a++) {
			if ((in->ext[a] != 0x00) && (in->ext[a] != 0xff))
				fs_inode->name->name[i++] = in->ext[a];
		}
		fs_inode->name->name[i] = '\0';

	}
	else {
		for (i = 0; (i < 8) && (in->name[i] != 0) && (in->name[i] != ' '); i++) {
			if ((i == 0) && (in->name[0] == FATFS_SLOT_DELETED))
				fs_inode->name->name[0] = '_';
			else if ((in->lowercase & FATFS_CASE_LOWER_BASE) && 
			  (in->name[i] >= 'A') && (in->name[i] <= 'Z'))
				fs_inode->name->name[i] = in->name[i] + 32;
			else
				fs_inode->name->name[i] = in->name[i];
		}

		if ((in->ext[0]) && (in->ext[0] != ' ')) {
			int a;
			fs_inode->name->name[i++] = '.';
			for (a = 0 ; (a < 3) && (in->ext[a] != 0) && (in->ext[a] != ' '); 
			  a++, i++) {
				if ((in->lowercase & FATFS_CASE_LOWER_EXT) && 
			  	  (in->ext[a] >= 'A') && (in->ext[a] <= 'Z'))
					fs_inode->name->name[i] = in->ext[a] + 32;
				else	
					fs_inode->name->name[i] = in->ext[a];
			}
		}
		fs_inode->name->name[i] = '\0';
	}

	/* get the starting cluster */
	if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
		fs_inode->direct_addr[0] = 0;
	}
	else {
		fs_inode->direct_addr[0] = FATFS_DENTRY_CLUST(fs, in) & fatfs->mask;
	}

	/* wipe the remaining fields */
	for (dcnt = 1 ; dcnt < fs_inode->direct_count; dcnt++)
		fs_inode->direct_addr[dcnt] = 0;
	for (dcnt = 0 ; dcnt < fs_inode->indir_count; dcnt++)
		fs_inode->indir_addr[dcnt] = 0;

	/* FAT does not store a size for its directories so make one based
	 * on the number of allocated sectors 
	 */
	if ((in->attrib & FATFS_ATTR_DIRECTORY) && 
	  ((in->attrib & FATFS_ATTR_LFN) != FATFS_ATTR_LFN)) {

		/* count the total number of clusters in this file */
		clust = FATFS_DENTRY_CLUST(fs, in);
		cnum = 0;
		while ((clust) && (0 == FATFS_ISEOF(clust, fatfs->mask))) {
			cnum++;
			clust = getFAT(fatfs, clust);
		}

		/* we are going to store the sectors, not clusters so calc
		 * that value 
		 */
		fs_inode->size = (OFF_T)(cnum * fatfs->csize * fatfs->ssize);

	}

	/* Use the allocation status of the sector to determine if the
	 * dentry is allocated or not */
	if (1 == is_sectalloc(fatfs, sect)) {
		fs_inode->flags = ((in->name[0] == FATFS_SLOT_DELETED)? 
		  FS_FLAG_META_UNALLOC : FS_FLAG_META_ALLOC);
	}
	else {
		fs_inode->flags = FS_FLAG_META_UNALLOC;
	}

	fs_inode->flags |= (FS_FLAG_META_USED);

	return;
}

/*
 * Since FAT does not give an 'inode' or directory entry to the
 * root directory, this function makes one up for it 
 */
void
fatfs_make_root(FATFS_INFO *fatfs, FS_INODE *fs_inode)
{
	int 		snum, cnum, i;
	u_int32_t 	clust;

	fs_inode->mode = (FS_INODE_DIR);

	fs_inode->nlink =  1;

	fs_inode->flags = (FS_FLAG_META_USED | FS_FLAG_META_ALLOC);

    fs_inode->uid = fs_inode->gid = 0;
	fs_inode->mtime = fs_inode->atime = fs_inode->ctime = fs_inode->dtime = 0;

	if (fs_inode->name == NULL) {
		fs_inode->name = (FS_NAME *)mymalloc(sizeof(FS_NAME));
		fs_inode->name->next = NULL;
	}
	fs_inode->name->name[0] = '\0';

	for (i = 1; i < fs_inode->direct_count; i++) 
		fs_inode->direct_addr[i] = 0;

	/* FAT12 and FAT16 don't use the FAT for root directory, so 
	 * we will have to fake it.
	 */
	if (fatfs->fs_info.ftype != MS32_FAT) {

		/* Other code will have to check this as a special condition 
		 */
		fs_inode->direct_addr[0] = 1;

		/* difference between end of FAT and start of clusters */
    	snum = fatfs->firstclustsect - fatfs->firstdatasect;

		/* number of bytes */
    	fs_inode->size = snum * fatfs->ssize; 
	}
	else {
		/* Get the number of allocated clusters */

		/* base cluster */
		clust = FATFS_SECT_2_CLUST(fatfs, fatfs->rootsect);
		fs_inode->direct_addr[0] = clust;

		cnum = 0;
		while ((clust) && (0 == FATFS_ISEOF(clust, FATFS_32_MASK))) {
			cnum++;
			clust = getFAT(fatfs, clust);
		}

    	fs_inode->size = cnum * fatfs->csize * fatfs->ssize; 
	}
}



/* 
 * Is the pointed to buffer a directory entry buffer? 
 *
 * Returns 1 if it is, 0 if not
 */
u_int8_t
fatfs_isdentry(FATFS_INFO *fatfs, fatfs_dentry *de) 
{
	FS_INFO *fs = (FS_INFO *)&fatfs->fs_info;
	if (!de)
		return 0;

	/* LFN Do not have these values
	*/
	if ((de->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
		return is_lfn_name((fatfs_dentry_lfn *)de);
	}
	else {
		if (de->lowercase & ~(FATFS_CASE_LOWER_ALL))
			return 0;
		else if (de->attrib & ~(FATFS_ATTR_ALL))
			return 0;

		/* The ctime, cdate, and adate fields are optional and 
		 * therefore 0 is a valid value
		 */
		if ( (getu16(fs, de->ctime) != 0) && 
		  (FATFS_ISTIME(getu16(fs, de->ctime)) == 0) ) 
			return 0;
		else if ( (getu16(fs, de->wtime) != 0) && 
		  (FATFS_ISTIME(getu16(fs, de->wtime)) == 0) ) 
			return 0;
		else if ( (getu16(fs, de->cdate) != 0) && 
		  (FATFS_ISDATE(getu16(fs, de->cdate)) == 0) ) 
			return 0;
		else if ( (getu16(fs, de->adate) != 0) && 
		  (FATFS_ISDATE(getu16(fs, de->adate)) == 0) ) 
			return 0;
		else if (FATFS_ISDATE(getu16(fs, de->wdate)) == 0) 
			return 0;

		/* verify the starting cluster is small enough */
		else if ((FATFS_DENTRY_CLUST(fs, de) > (fatfs->lastclust)) &&
		  (FATFS_ISEOF(FATFS_DENTRY_CLUST(fs, de), fatfs->mask) == 0)) 
			return 0;

		return is_83_name(de);
	}
}


/**************************************************************************
 *
 * INODE WALKING
 * 
 *************************************************************************/
/*
 * walk the inodes
 *
 * Flags that are used: FS_FLAG_META_ALLOC, FS_FLAG_META_UNALLOC,
 * FS_FLAG_META_USED, FS_FLAG_META_UNUSED
 *
 * NOT: FS_FLAG_META_LINK, FS_FLAG_META_UNLINK (no notion of link)
 *
 */
void
fatfs_inode_walk(FS_INFO *fs, INUM_T start, INUM_T last, int flags,
                      FS_INODE_WALK_FN action, char *ptr)
{
    char   	*myname = "fatfs_inode_walk";
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    INUM_T  	inum;
    FS_INODE *fs_inode = fs_inode_alloc(FATFS_NDADDR,FATFS_NIADDR);
	u_int32_t	sect, ssect, lsect, myflags, didx;


    /*
     * Sanity checks.
     */
    if (start < fs->first_inum || start > fs->last_inum)
        error("%s: invalid start inode number: %lu", myname, (ULONG) start);
    if (last < fs->first_inum || last > fs->last_inum || last < start)
        error("%s: invalid last inode number: %lu", myname, (ULONG) last);

    if (verbose)
		fprintf (logfp,
		  "fatfs_inode_walk: Inode Walking %lu to %lu\n", 
		  (ULONG)start, (ULONG)last);

	/* The root_inum is reserved for the root directory, which does
	 * not have a dentry in FAT, so we make one up
	 */
	if ((start == fs->root_inum) && 
	  ((FS_FLAG_META_ALLOC & flags) == FS_FLAG_META_ALLOC) && 
	  ((FS_FLAG_META_USED & flags) == FS_FLAG_META_USED)) {

		int myflags = FS_FLAG_META_ALLOC | FS_FLAG_META_USED;

		fatfs_make_root(fatfs, fs_inode);
		if (WALK_STOP == action(fs, start, fs_inode, myflags, ptr)) {
			fs_inode_free(fs_inode);
			return;
		}

		if (start == last) {
			fs_inode_free(fs_inode);
			return;
		}
	}

	/* advance it so that it is a valid starting point */
	if (start == fs->root_inum)
		start++;

	/* As FAT does not give numbers to the directory entries, we will make
	 * them up.  Start from one larger then the root inode number (which we
	 * made up) and number each entry in each cluster
	 */

	/* start analyzing each sector
	 *
	 * Perform a test on the first 32 bytes of each sector to identify if
	 * the sector contains directory entries.  If it does, then continue
	 * to analyze it.  If not, then read the next sector 
	 */


	/* identify the sector numbers that the starting and ending inodes are 
	 * in
	 */
	ssect = FATFS_INODE_2_SECT(fatfs, start);
	lsect = FATFS_INODE_2_SECT(fatfs, last);

	/* cycle through the sectors and look for dentries */
	for (sect = ssect; sect <= lsect; sect++) {
		int sectalloc;

		/* if the sector is not allocated, then do not go into it if we 
		 * only want allocated/link entries
		 * If it is allocated, then go into it no matter what
		 */
		sectalloc = is_sectalloc(fatfs, sect);
		if ((sectalloc == 0) && ((flags & FS_FLAG_META_UNALLOC) == 0))
		  	continue;

		/* read it */
		fs->read_block(fs, fatfs->dinodes, fatfs->ssize, sect, 
		  "fatfs_inode_walk: block of inodes");

		/* if it is not a bunch of dentries, then skip it */
		if (0 == fatfs_isdentry(fatfs, (fatfs_dentry *)fatfs->dinodes->data)) 
			continue;

		/* get the base inode address */
		inum = FATFS_SECT_2_INODE(fatfs, sect);

	    if (verbose)
			fprintf (logfp,
			  "fatfs_inode_walk: Processing sector %lu starting at inode %lu\n", 
			  (ULONG)sect, (ULONG)inum);

		fatfs->dep = (fatfs_dentry *)fatfs->dinodes->data;

		/* cycle through the directory entries */
		for (didx = 0; didx < fatfs->dentry_cnt_se; 
		   didx++, inum++, fatfs->dep++) {

			/* If less, then move on */
			if (inum < start) 
				continue;

			/* If we are done, then return  */
			if (inum > last) {
				fs_inode_free(fs_inode);
				return;
			}


			/* if this is a long file name entry, then skip it and 
			 * wait for the short name */
			if ((fatfs->dep->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN)
				continue;


			/* we don't care about . and .. entries because they
			 * are redundant of other 'inode' entries */
			if (((fatfs->dep->attrib & FATFS_ATTR_DIRECTORY) 
			   == FATFS_ATTR_DIRECTORY) && (fatfs->dep->name[0] == '.'))
				continue;


			/* Allocation status 
			 * This is determined first by the sector allocation status
			 * an then the dentry flag.  When a directory is deleted, the
			 * contents are not always set to unallocated
			 */
			if (sectalloc == 1) {
				myflags = ((fatfs->dep->name[0] == FATFS_SLOT_DELETED)? 
				  FS_FLAG_META_UNALLOC : FS_FLAG_META_ALLOC);
			}
			else {
				myflags = FS_FLAG_META_UNALLOC;
			}

			if ((flags & myflags) != myflags)
				continue;

			/* Slot has not been used yet */
			myflags |= ((fatfs->dep->name[0] == FATFS_SLOT_EMPTY) ?
			  FS_FLAG_META_UNUSED : FS_FLAG_META_USED);

			if ((flags & myflags) != myflags)
				continue;


			/* Do a final sanity check */
			if (0 == fatfs_isdentry(fatfs, fatfs->dep))
				continue;

			fatfs_copy_inode(fatfs, fs_inode, sect);
			fs_inode->flags = myflags;
					
    		if (verbose)
				fprintf (logfp,
				  "fatfs_inode_walk: Directory Entry %lu (%lu) at sector %lu\n",
					  (ULONG)inum, (ULONG)didx, (ULONG)sect);

			if (WALK_STOP == action(fs, inum, fs_inode, myflags, ptr)) {
				fs_inode_free(fs_inode);
				return;
			}

		} /* dentries */

	} /* clusters */

	fs_inode_free(fs_inode);
	return;

} /* end of inode_walk */


/*
 * return the contents of a specific inode
 *
 * An error is called if the entry is not a valid inode
 *
 */
static FS_INODE *
fatfs_inode_lookup(FS_INFO *fs, INUM_T inum)
{
	FATFS_INFO *fatfs = (FATFS_INFO *) fs;
	FS_INODE *fs_inode = fs_inode_alloc(FATFS_NDADDR,FATFS_NIADDR);

	 /* 
	 * Sanity check.
	 */
	if (inum < fs->first_inum || inum > fs->last_inum)
		error("invalid inode number: %lu", (ULONG) inum);


	/* As there is no real root inode in FAT, use the made up one */
	if (inum == fs->root_inum) {
		fatfs_make_root(fatfs, fs_inode);
	}
	else {
		u_int32_t sect, off;

		/* Get the sector that this inode would be in and its offset */
		sect = FATFS_INODE_2_SECT (fatfs, inum);
		off = FATFS_INODE_2_OFF (fatfs, inum);

		fs->read_block(fs, fatfs->dinodes, fatfs->ssize, sect, 
		  "fatfs_inode_lookup");

		fatfs->dep = (fatfs_dentry *) &fatfs->dinodes->data[off]; 
		if (fatfs_isdentry(fatfs, fatfs->dep)) {
			fatfs_copy_inode(fatfs, fs_inode, sect);
		}
		else {
			error ("%d is not an inode", inum);
		}
	}

	return fs_inode;
}




/**************************************************************************
 *
 * FILE WALKING
 * 
 *************************************************************************/

/* 
 * Flags: FS_FLAG_FILE_SLACK, FS_FLAT_FILE_NOABORT, FS_FLAG_FILE_AONLY
 * FS_FLAG_FILE_RECOVER
 *
 * no notion of SPARSE or META
 *
 *
 * flags on action: FS_FLAG_DATA_CONT, FS_FLAG_DATA_META, 
 * FS_FLAG_DATA_ALLOC, FS_FLAG_DATA_UNALLOC
 */
static void
fatfs_file_walk(FS_INFO *fs, FS_INODE *fs_inode, u_int32_t type, u_int16_t id,
    int flags, FS_FILE_WALK_FN action, char *ptr)
{
    FATFS_INFO 	*fatfs = (FATFS_INFO *) fs;
	int 		i;
	OFF_T		size, sbase, clust;
	u_int32_t	len;
	FS_BUF		*fs_buf;

	fs_buf = fs_buf_alloc(fatfs->ssize);
	if (flags & FS_FLAG_FILE_SLACK)
		size = roundup(fs_inode->size, fatfs->csize * fatfs->ssize);
	else
		size = fs_inode->size;

	clust = fs_inode->direct_addr[0];

	if ((clust > (fatfs->lastclust)) &&
	  (FATFS_ISEOF(clust, fatfs->mask) == 0)) {

		if (flags & FS_FLAG_FILE_NOABORT) {
			if (verbose) {
				fprintf(logfp, 
				  "fatfs_file_walk: Warning: Invalid starting cluster address in Directory Entry (too large): %lu",
			  	  (ULONG)clust);
			}
			return;
		}
		else {
			error("fatfs_file_walk: Invalid starting cluster address in Directory Entry (too large): %lu",
			  (ULONG)clust);
		}
	}

	/* this is the root directory entry, special case: it is not in the FAT */
	if ((fs->ftype != MS32_FAT) && (clust == 1)) {
		int snum = fatfs->firstclustsect - fatfs->firstdatasect;

		if (verbose)
			fprintf (logfp,
			  "fatfs_file_walk: Walking Root Directory\n");

		for (i = 0; i < snum; i++) {
			int myflags = (FS_FLAG_DATA_CONT | FS_FLAG_DATA_ALLOC);

			if ((flags & FS_FLAG_FILE_AONLY) == 0)
				fs->read_block(fs, fs_buf, fatfs->ssize, 
				  fatfs->rootsect + i, "file_walk: root directory");

			action (fs, fatfs->rootsect + i, fs_buf->data, fatfs->ssize, 
			  myflags, ptr);
		}
	}

	/* A deleted file that we want to recover */
	else if ((fs_inode->flags & FS_FLAG_META_UNALLOC) && 
	  (flags & FS_FLAG_FILE_RECOVER)) {

		OFF_T startclust = clust;
		OFF_T recoversize = size;


		/* We know the size and the starting cluster
		 *
		 * We are going to take the clusters from the starting cluster
		 * onwards and skip the clusters that are current allocated
		 */

		/* Sanity checks on the starting cluster */
		/* Convert the cluster addr to a sector addr */
		sbase = FATFS_CLUST_2_SECT(fatfs, startclust);

		if (sbase > fs->last_block) {
			fs_buf_free(fs_buf);
			if (flags & FS_FLAG_FILE_NOABORT) {
				if (verbose) {
					fprintf(logfp, 
					  "Invalid starting cluster during FAT recovery (too large): %lu",
					  (ULONG)sbase);
				}
				return;
			}
			else
				error ("Invalid starting cluster during FAT recovery (too large): %lu",
				  (ULONG)sbase);
		}

		/* If the starting cluster is already allocated then we can't
		 * recover it */
		if (is_clustalloc(fatfs, startclust)) {
			if (verbose) {
				fprintf(logfp, "Starting cluster of deleted file is allocated - exiting\n");
			}
			return;
		}

	
		/* Part 1 is to make sure there are enough unallocated clusters
		 * for the size of the file 
		 */
		clust = startclust;
		size = recoversize;
		while (size > 0) {
			sbase = FATFS_CLUST_2_SECT(fatfs, clust);

			/* Are we past the end of the FS? 
			 * that means we could not find enough unallocated clusters
			 * for the file size */
			if (sbase > fs->last_block) {
				if (verbose)
					fprintf(logfp, "Could not find enough unallocated sectors to recover with - existing\n");

				return;
			}

			/* Skip allocated clusters */
			if (is_clustalloc(fatfs, clust)) {
				clust++;
				continue;
			}

			/* We can use this sector */
			size -= (fatfs->csize * fatfs->ssize);
			clust++;

		}

		/* If we got this far, then we can recover the file */
		clust = startclust;
		size = recoversize;
		while (size > 0) {
			int myflags = FS_FLAG_DATA_CONT | FS_FLAG_DATA_UNALLOC;

			sbase = FATFS_CLUST_2_SECT(fatfs, clust);
			/* Are we past the end of the FS? */
			if (sbase > fs->last_block) {
				error ("Recover went past end of FS - should have been caught");
			}

			/* Skip allocated clusters */
			if (is_clustalloc(fatfs, clust)) {
				clust++;
				continue;
			}

			/* Go through each sector */
			for (i = 0; i < fatfs->csize && size > 0; i++) {
				if (flags & FS_FLAG_FILE_SLACK)
					len = fatfs->ssize;
				else
					len = (size < fatfs->ssize) ? size : fatfs->ssize;

				if (verbose)
					fprintf (logfp,
					  "fatfs_file_walk: Processing %d bytes of sector %lu for recovery\n",
					  len, (ULONG)(sbase + 1));

				if ((flags & FS_FLAG_FILE_AONLY) == 0)
					fs->read_block(fs, fs_buf, fatfs->ssize, sbase + i, 
					  "file_walk: sectors");

				action (fs, sbase + i, fs_buf->data, len, myflags, ptr);
				size -= len;
			}
			clust++;
		}
	}

	/* Normal cluster chain walking */
	else {
		/* Cycle through the cluster chain */
		while ((clust & fatfs->mask) > 0 && size > 0 && 
		  (0 == FATFS_ISEOF(clust, fatfs->mask)) )  {
			int myflags;

			/* Convert the cluster addr to a sector addr */
			sbase = FATFS_CLUST_2_SECT(fatfs, clust);

			if (sbase > fs->last_block) {
				fs_buf_free(fs_buf);
				if (flags & FS_FLAG_FILE_NOABORT) {
					if (verbose) {
						fprintf(logfp, 
						  "fatfs_file_walk: Invalid sector address in FAT (too large): %lu",
						  (ULONG)sbase);
					}
					return;
				}
				else
					error ("fatfs_file_walk: Invalid sector address in FAT (too large): %lu",
					  (ULONG)sbase);
			}

			myflags = FS_FLAG_DATA_CONT;
			if (is_clustalloc(fatfs, clust)) {
				myflags |= FS_FLAG_DATA_ALLOC;
			}
			else {
				myflags |= FS_FLAG_DATA_UNALLOC;
			}

			/* Go through each sector */
			for (i = 0; i < fatfs->csize && size > 0; i++) {
				if (flags & FS_FLAG_FILE_SLACK)
					len = fatfs->ssize;
				else
					len = (size < fatfs->ssize) ? size : fatfs->ssize;

				if (verbose)
					fprintf (logfp,
					  "fatfs_file_walk: Processing %d bytes of sector %lu\n",
					  len, (ULONG)(sbase + 1));

				if ((flags & FS_FLAG_FILE_AONLY) == 0)
					fs->read_block(fs, fs_buf, fatfs->ssize, sbase + i, 
					  "file_walk: sectors");

				action (fs, sbase + i, fs_buf->data, len, myflags, ptr);
				size -= len;
			}
			if (size > 0) 
				clust = getFAT(fatfs, clust);
		}
	}

	fs_buf_free(fs_buf);
}


static void
fatfs_fscheck(FS_INFO *fs, FILE *hFile)
{
	error ("fscheck not implemented for FAT yet");


	/* Check that allocated dentries point to start of allcated cluster chain */


	/* Size of file is consistent with cluster chain length */


	/* Allocated cluster chains have a corresponding alloc dentry */


	/* Non file dentries have no clusters */


	/* Only one volume label */


	/* Dump Bad Sector Addresses */


	/* Dump unused sector addresses 
	 * Reserved area, end of FAT, end of Data Area */


}


static void
fatfs_fsstat(FS_INFO *fs, FILE *hFile)
{
	int i, a, cnt;
	u_int32_t	next, snext, sstart, send;
	FATFS_INFO *fatfs = (FATFS_INFO *)fs;
	fatfs_sb *sb = fatfs->sb;
	FS_BUF *fs_buf = fs_buf_alloc(fatfs->ssize);
	fatfs_dentry *de;

	/* Read the root directory sector so that we can get the volume
	 * label from it */
	fs->read_block(fs, fs_buf, fatfs->ssize, 
	  fatfs->rootsect, "root directory");

	/* Find the dentry that is set as the volume label */
	de = (fatfs_dentry *)fs_buf->data;
	for (i = 0; i < fatfs->ssize; i += sizeof (*de)) {
		if (de->attrib == FATFS_ATTR_VOLUME) 
			break;
		de++;
	}
	/* If we didn't find it, then reset de */
	if (de->attrib != FATFS_ATTR_VOLUME) 
		de = NULL;



	/* Print the general file system information */

	fprintf(hFile, "FILE SYSTEM INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");

	fprintf(hFile, "File System Type: FAT\n");

	fprintf(hFile, "\nOEM Name: %c%c%c%c%c%c%c%c\n", sb->oemname[0], 
	  sb->oemname[1], sb->oemname[2], sb->oemname[3], sb->oemname[4],
	  sb->oemname[5], sb->oemname[6], sb->oemname[7]);
	

	if (fatfs->fs_info.ftype != MS32_FAT) {
		fprintf(hFile, "Volume ID: 0x%x\n", getu32(fs, sb->a.f16.vol_id));

		fprintf(hFile, "Volume Label (Boot Sector): %c%c%c%c%c%c%c%c%c%c%c\n", 
		  sb->a.f16.vol_lab[0], sb->a.f16.vol_lab[1], sb->a.f16.vol_lab[2],
		  sb->a.f16.vol_lab[3], sb->a.f16.vol_lab[4], sb->a.f16.vol_lab[5],
		  sb->a.f16.vol_lab[6], sb->a.f16.vol_lab[7], sb->a.f16.vol_lab[8],
		  sb->a.f16.vol_lab[9], sb->a.f16.vol_lab[10]);

		if ((de) && (de->name)) {
			fprintf(hFile, "Volume Label (Root Directory): %c%c%c%c%c%c%c%c%c%c%c\n", 
			  de->name[0], de->name[1], de->name[2], de->name[3],
			  de->name[4], de->name[5], de->name[6], de->name[7],
			  de->name[8], de->name[9], de->name[10]);
		} else {
			fprintf(hFile, "Volume Label (Root Directory):\n");
		}

		fprintf(hFile, "File System Type Label: %c%c%c%c%c%c%c%c\n", 
		  sb->a.f16.fs_type[0], sb->a.f16.fs_type[1], sb->a.f16.fs_type[2],
		  sb->a.f16.fs_type[3], sb->a.f16.fs_type[4], sb->a.f16.fs_type[5],
		  sb->a.f16.fs_type[6], sb->a.f16.fs_type[7]);
	}
	else {

    	FS_BUF *fat_fsinfo_buf = fs_buf_alloc(sizeof(fatfs_fsinfo));
		fatfs_fsinfo *fat_info;

		fprintf(hFile, "Volume ID: 0x%x\n", getu32(fs, sb->a.f32.vol_id));

		fprintf(hFile, "Volume Label (Boot Sector): %c%c%c%c%c%c%c%c%c%c%c\n", 
		  sb->a.f32.vol_lab[0], sb->a.f32.vol_lab[1], sb->a.f32.vol_lab[2],
		  sb->a.f32.vol_lab[3], sb->a.f32.vol_lab[4], sb->a.f32.vol_lab[5],
		  sb->a.f32.vol_lab[6], sb->a.f32.vol_lab[7], sb->a.f32.vol_lab[8],
		  sb->a.f32.vol_lab[9], sb->a.f32.vol_lab[10]);

		if ((de) && (de->name)) {
			fprintf(hFile, "Volume Label (Root Directory): %c%c%c%c%c%c%c%c%c%c%c\n", 
			  de->name[0], de->name[1], de->name[2], de->name[3],
			  de->name[4], de->name[5], de->name[6], de->name[7],
			  de->name[8], de->name[9], de->name[10]);
		} else {
			fprintf(hFile, "Volume Label (Root Directory):\n");
		}

		fprintf(hFile, "File System Type Label: %c%c%c%c%c%c%c%c\n", 
		  sb->a.f32.fs_type[0], sb->a.f32.fs_type[1], sb->a.f32.fs_type[2],
		  sb->a.f32.fs_type[3], sb->a.f32.fs_type[4], sb->a.f32.fs_type[5],
		  sb->a.f32.fs_type[6], sb->a.f32.fs_type[7]);

		fs->read_block(fs, fat_fsinfo_buf, sizeof(fatfs_fsinfo), 
		  getu16(fs, sb->a.f32.fsinfo), 
		  "read fs_info");

		fat_info = (fatfs_fsinfo *)fat_fsinfo_buf->data;
		fprintf(hFile, "Next Free Sector (FS Info): %lu\n",
		  (ULONG)FATFS_CLUST_2_SECT(fatfs, getu32(fs, fat_info->nextfree)));

		fprintf(hFile, "Free Sector Count (FS Info): %lu\n",
		  (ULONG)
		  (getu32(fs, fat_info->freecnt) * fatfs->csize));

		fs_buf_free(fat_fsinfo_buf);
	}

	fs_buf_free(fs_buf);

	fprintf(hFile, "\nSectors before file system: %d\n",
		getu32(fs, sb->prevsect));

	fprintf(hFile, "\nFile System Layout (in sectors)\n");

	fprintf(hFile, "Total Range: %lu - %lu\n", (ULONG)fs->first_block, 
	  (ULONG)fs->last_block);

	fprintf(hFile, "* Reserved: 0 - %d\n",
	  fatfs->firstfatsect - 1);

	fprintf(hFile, "** Boot Sector: 0\n");

	if (fatfs->fs_info.ftype == MS32_FAT) {
		fprintf(hFile, "** FS Info Sector: %lu\n",
		  (ULONG)getu16(fs, sb->a.f32.fsinfo));

		fprintf(hFile, "** Backup Boot Sector: %lu\n",
		  (ULONG)getu32(fs, sb->a.f32.bs_backup));
	}

	for (i = 0; i < fatfs->numfat; i++) {
		u_int32_t base = fatfs->firstfatsect + i * (fatfs->sectperfat);

		fprintf(hFile, "* FAT %d: %lu - %lu\n", i, (ULONG)base,
		   (ULONG)(base + fatfs->sectperfat - 1));
	}

	fprintf(hFile, "* Data Area: %lu - %lu\n", 
	  (ULONG)fatfs->firstdatasect, (ULONG)fs->last_block);

	if (fatfs->fs_info.ftype != MS32_FAT) {
		u_int32_t x = fatfs->csize * (fatfs->lastclust - 1);

		fprintf(hFile, "** Root Directory: %lu - %lu\n",
		  (ULONG)fatfs->firstdatasect, (ULONG)fatfs->firstclustsect - 1);

		fprintf(hFile, "** Cluster Area: %lu - %lu\n",
		  (ULONG)fatfs->firstclustsect, 
		  (ULONG)(fatfs->firstclustsect + x - 1));

		if ((fatfs->firstclustsect + x - 1) != fs->last_block) {
			fprintf(hFile, "** Non-clustered: %lu - %lu\n",
			  (ULONG)(fatfs->firstclustsect + x),
			  (ULONG)fs->last_block);
		}
	}
	else {
		u_int32_t x = fatfs->csize * (fatfs->lastclust - 1);

		fprintf(hFile, "** Cluster Area: %lu - %lu\n",
		  (ULONG)fatfs->firstclustsect, 
		  (ULONG)(fatfs->firstclustsect + x - 1));

		if ((fatfs->firstclustsect + x - 1) != fs->last_block) {
			fprintf(hFile, "** Non-clustered: %lu - %lu\n",
			  (ULONG)(fatfs->firstclustsect + x),
			  (ULONG)fs->last_block);
		}
	}


	fprintf(hFile, "\nMETA-DATA INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");

	fprintf(hFile, "Range: %lu - %lu\n", (ULONG)fs->first_inum, 
	  (ULONG)fs->last_inum);
	fprintf(hFile, "Root Directory: %lu\n", (ULONG)fs->root_inum);


	fprintf(hFile, "\nCONTENT-DATA INFORMATION\n");
	fprintf(hFile, "--------------------------------------------\n");
	fprintf(hFile, "Sector Size: %d\n", fatfs->ssize);
	fprintf(hFile, "Cluster Size: %d\n", fatfs->csize * fatfs->ssize);

	fprintf(hFile, "Total Cluster Range: 2 - %lu\n", (ULONG) (fatfs->lastclust));

	
	/* cycle via cluster and look at each cluster in the FAT*/
	cnt = 0;
	for (i = 2; i <= fatfs->lastclust; i++) {
		u_int32_t entry, sect;

		/* Get the FAT table entry */
		entry = getFAT(fatfs, i);	
	
		if (FATFS_ISBAD(entry, fatfs->mask) == 0) {
			continue;
		}

		if (cnt == 0) 
			fprintf(hFile, "Bad Sectors: ");

		sect = FATFS_CLUST_2_SECT(fatfs, i);
		for (a = 0; a < fatfs->csize; a++) {
			fprintf(hFile, "%lu ", (ULONG)sect + a);
			if ((++cnt % 8) == 0)
				fprintf(hFile, "\n");
		}
	}
	if ((cnt > 0) && ((cnt % 8) != 0))
		fprintf(hFile, "\n");



	/* Display the FAT Table */
	fprintf(hFile, "\nFAT CONTENTS (in sectors)\n");
	fprintf(hFile, "--------------------------------------------\n");

	/* 'sstart' marks the first sector of the current run to print */
	sstart = fatfs->firstclustsect;

	/* cycle via cluster and look at each cluster in the FAT*/
	for (i = 2; i <= fatfs->lastclust; i++) {
		
		/* 'send' marks the end sector of the current run, which will extend
		 * when the current cluster continues to the next 
		 */
		send = FATFS_CLUST_2_SECT(fatfs, i + 1) - 1;

		/* get the next cluster */
		next = getFAT(fatfs, i);	
		snext = FATFS_CLUST_2_SECT(fatfs, next);

		/* we are also using the next sector (clust) */
		if ((next & fatfs->mask) == (i + 1)) {
			continue;
		}

		/* The next clust is either further away or the clust is available,
		 * print it if is further away 
		 */
		else if ((next & fatfs->mask)) {
			if (FATFS_ISEOF(next, fatfs->mask)) 
				fprintf (hFile, "%d-%d (%d) -> EOF\n", sstart, send, 
				  send - sstart + 1);
			else if (FATFS_ISBAD(next, fatfs->mask)) 
				fprintf (hFile, "%d-%d (%d) -> BAD\n", sstart, send,
				  send - sstart + 1);
			else
				fprintf (hFile, "%d-%d (%d) -> %d\n", sstart, send, 
				  send - sstart + 1, snext);
		}

		/* reset the starting counter */
		sstart = send + 1;
	}

	return;
}


/************************* istat *******************************/

/* Callback action for file_walk to print the sector addresses
 * of a file
 */
static int g_printidx = 0;
static int g_istat_seen = 0;
#define WIDTH   8

static u_int8_t
print_addr_act (FS_INFO *fs, DADDR_T addr, char *buf,
  int size, int flags, char *ptr)
{
    FILE *hFile = (FILE *)ptr;

	fprintf(hFile, "%lu ", (unsigned long) addr);

	if (++g_printidx == WIDTH) {
		fprintf(hFile, "\n");
		g_printidx = 0;
    }
	g_istat_seen = 1;

    return WALK_CONT;
}


static void
fatfs_istat (FS_INFO *fs, FILE *hFile, INUM_T inum, int numblock,
  int32_t sec_skew)
{
	FS_INODE *fs_inode;
	FS_NAME *fs_name;
	FATFS_INFO *fatfs = (FATFS_INFO *)fs;

	fs_inode = fatfs_inode_lookup (fs, inum);
	fprintf(hFile, "Directory Entry: %lu\n", (ULONG) inum);

	fprintf(hFile, "%sAllocated\n",
	  (fs_inode->flags & FS_FLAG_META_UNALLOC) ? "Not " : "");

	fprintf(hFile, "File Attributes: ");

	/* This should only be null if we have the root directory */
	if (fatfs->dep == NULL) {
		if (inum == fs->root_inum)
			fprintf(hFile, "Directory\n");
		else 
			fprintf(hFile, "File\n");
	}
	else if ((fatfs->dep->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
		fprintf(hFile, "Long File Name\n");
	}
	else {
		if (fatfs->dep->attrib & FATFS_ATTR_DIRECTORY)
			fprintf(hFile, "Directory");
		else if (fatfs->dep->attrib & FATFS_ATTR_VOLUME)
			fprintf(hFile, "Volume Label");
		else
			fprintf(hFile, "File");

		if (fatfs->dep->attrib & FATFS_ATTR_READONLY)
			fprintf(hFile, ", Read Only");
		if (fatfs->dep->attrib & FATFS_ATTR_HIDDEN)
			fprintf(hFile, ", Hidden");
		if (fatfs->dep->attrib & FATFS_ATTR_SYSTEM)
			fprintf(hFile, ", System");
		if (fatfs->dep->attrib & FATFS_ATTR_ARCHIVE)
			fprintf(hFile, ", Archive");

		fprintf(hFile, "\n");
	}

	fprintf(hFile, "Size: %lu\n", (ULONG) fs_inode->size);
	fprintf(hFile, "Num of links: %lu\n", (ULONG) fs_inode->nlink);

	if (fs_inode->name) {
		fs_name = fs_inode->name;
		fprintf(hFile, "Name: %s\n", fs_name->name);
	}

	if (sec_skew != 0) {
		fprintf(hFile, "\nAdjusted Directory Entry Times:\n");
		fs_inode->mtime -= sec_skew;
		fs_inode->atime -= sec_skew;
		fs_inode->ctime -= sec_skew;
   
		fprintf(hFile, "Written:\t%s", ctime(&fs_inode->mtime));
		fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
		fprintf(hFile, "Created:\t%s", ctime(&fs_inode->ctime));

		fs_inode->mtime += sec_skew;
		fs_inode->atime += sec_skew;
		fs_inode->ctime += sec_skew;

		fprintf(hFile, "\nOriginal Directory Entry Times:\n"); 
	}
	else
		fprintf(hFile, "\nDirectory Entry Times:\n");

	fprintf(hFile, "Written:\t%s", ctime(&fs_inode->mtime));
	fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
	fprintf(hFile, "Created:\t%s", ctime(&fs_inode->ctime));

	fprintf (hFile, "\nSectors:\n");

	/* A bad hack to force a specified number of blocks */
	if (numblock > 0)
		fs_inode->size = numblock * fs->block_size;

	g_istat_seen = 0;
	g_printidx = 0;
	fs->file_walk(fs, fs_inode, 0, 0, 
	  (FS_FLAG_FILE_AONLY | FS_FLAG_FILE_SLACK),
	  print_addr_act, (char *)hFile);

	if (g_printidx != 0)
		fprintf(hFile, "\n");

	/* Display the recovery information if we can */
	if (fs_inode->flags & FS_FLAG_META_UNALLOC) {
		fprintf (hFile, "\nRecovery:\n");

		g_istat_seen = 0;
		g_printidx = 0;
		fs->file_walk(fs, fs_inode, 0, 0, 
		  (FS_FLAG_FILE_AONLY | FS_FLAG_FILE_SLACK | FS_FLAG_FILE_RECOVER),
		  print_addr_act, (char *)hFile);

		if (g_istat_seen == 0) {
			fprintf(hFile, "File recovery not possible\n");	
		}
		else if (g_printidx != 0)
			fprintf(hFile, "\n");

	}
	return;
}


/* fatfs_close - close an fatfs file system */
static void
fatfs_close(FS_INFO *fs)
{
	FATFS_INFO *fatfs = (FATFS_INFO *)fs;
    fs->io->close(fs->io);
	fs_buf_free(fatfs->dinodes);
	fs_buf_free(fatfs->table);
	free(fatfs->sb);
    free(fs);
}


/* fatfs_open - open a fatfs file system image */
FS_INFO *
fatfs_open(IO_INFO *io, unsigned char ftype)
{
	char   		*myname = "fatfs_open";
	FATFS_INFO 	*fatfs = (FATFS_INFO *) mymalloc(sizeof(*fatfs));
	int     	len;
	FS_INFO 	*fs = &(fatfs->fs_info);
	fatfs_sb	*fatsb;
	fs->io=io;
	u_int32_t	clustcnt, sectors;

	
	if ((ftype & FSMASK) != FATFS_TYPE) {
		return(NULL);
		error ("%s: Invalid FS Type in fatfs_open", myname);
	};

	//if ((fs->fd = open(name, O_RDONLY)) < 0)
	//	error("%s: open %s: %m", myname, name);

	fs->ftype = ftype;

	/*
	* Read the super block.
	*/
	len = sizeof(fatfs_sb);
	fatsb = fatfs->sb = (fatfs_sb *)mymalloc (len);

   /* Commented out in favour of generic io_subsystem calls
	if (read(fs->fd, (char *)fatsb, len) != len)
		error("%s: read superblock: %m", name);
    */
    fs->io->read_random(fs->io,(char *)fatsb,len,0,"Checking for FATFS");

	/* Check the magic value  and ID endian ordering */
	if (guessu16(fs, fatsb->magic, FATFS_FS_MAGIC)) {
		return(NULL);
		//error ("Error: %s is not a FATFS file system", name);
	}

	fatfs->ssize = getu16(fs, fatsb->ssize);
	if (fatfs->ssize % FATFS_DEV_BSIZE) {
		error ("Error: sector size (%d) is not a multiple of device size (%d)\nDo you have a disk image instead of a partition image?",
		  fatfs->ssize, FATFS_DEV_BSIZE);
	}

	fatfs->csize = fatsb->csize;				/* cluster size */
	if (fatfs->csize == 0) 
		error ("Error: This is not a FATFS file system (cluster size)"); 

	fatfs->numfat = fatsb->numfat;				/* number of tables */
	if (fatfs->numfat == 0) 
		error ("Error: This is not a FATFS file system (number of FATs)"); 

	/* We can't do a sanity check on this b.c. FAT32 has a value of 0 */
	fatfs->numroot = getu16(fs, fatsb->numroot);	/* num of root entries */


	/* if sectors16 is 0, then the number of sectors is stored in sectors32 */
	if (0 == (sectors = getu16(fs, fatsb->sectors16)))
		sectors = getu32(fs, fatsb->sectors32);

	/* if secperfat16 is 0, then read sectperfat32 */
	if (0 == (fatfs->sectperfat = getu16(fs, fatsb->sectperfat16)))
		fatfs->sectperfat = getu32(fs, fatsb->a.f32.sectperfat32);

	if (fatfs->sectperfat == 0) 
		return NULL;
//		error ("Error: %s is not a FATFS file system (invalid sectors per FAT)",
//		  name);

	fatfs->firstfatsect = getu16(fs, fatsb->reserved); 	
	if ((fatfs->firstfatsect == 0) || (fatfs->firstfatsect > sectors))
		return NULL;
//		error ("Error: %s is not a FATFS file system (invalid first FAT sector %lu)", 
//		  name, (ULONG)fatfs->firstfatsect);

	/* The sector of the begining of the data area  - which is 
	 * after all of the FATs
	 *
	 * For FAT12 and FAT16, the data area starts with the root
	 * directory entries and then the first cluster.  For FAT32,
	 * the data area starts with clusters and the root directory
	 * is somewhere in the data area
	 */
	fatfs->firstdatasect = fatfs->firstfatsect + 
		fatfs->sectperfat * fatfs->numfat;

	/* The sector where the first cluster is located.  It will be used
	 * to translate cluster addresses to sector addresses 
	 *
	 * For FAT32, the first cluster is the start of the data area and
	 * it is after the root directory for FAT12 and FAT16.  At this
	 * point in the program, numroot is set to 0 for FAT32
	 */
	fatfs->firstclustsect = fatfs->firstdatasect + 
	  ((fatfs->numroot * 32 + fatfs->ssize - 1) / fatfs->ssize);

	/* total number of clusters */
	clustcnt = (sectors - fatfs->firstclustsect) / 
	  fatfs->csize;

	/* the first cluster is #2, so the final cluster is: */
	fatfs->lastclust = 1 + clustcnt;


	/* identify the FAT type by the total number of data clusters
	 * this calculation is from the MS FAT Overview Doc
	 *
	 * A FAT file system made by another OS could use different values
	 */
	if (ftype == MSAUTO_FAT) {

		if (clustcnt < 4085) {
			ftype = MS12_FAT;
		}
		else if (clustcnt < 65525) {
			ftype = MS16_FAT;
		}
		else {
			ftype = MS32_FAT;
		}

		fatfs->fs_info.ftype = ftype;
	}

	/* Some sanity checks */
	else {
		if ((ftype == MS12_FAT) && (clustcnt >= 4085)) 
			error ("Too many sectors for FAT12: try auto-detect mode");
	}

	if ((ftype == MS32_FAT) && (fatfs->numroot != 0))
		error ("Invalid FAT32 image (numroot != 0)");

	if ((ftype != MS32_FAT) && (fatfs->numroot == 0))
		error ("Invalid FAT image (numroot == 0, and not FAT32)");


	/* Set the mask to use on the cluster values */
	if (ftype == MS12_FAT)
		fatfs->mask = FATFS_12_MASK;
	else if (ftype == MS16_FAT)
		fatfs->mask = FATFS_16_MASK;
	else if (ftype == MS32_FAT)
		fatfs->mask = FATFS_32_MASK;
	else
		error ("Unknown FAT type in fatfs_open: %d\n", ftype);

	/* the root directories are always after the FAT for FAT12 and FAT16,
	 * but are dynamically located for FAT32
	 */
	if (ftype == MS32_FAT) 
		fatfs->rootsect = FATFS_CLUST_2_SECT(fatfs, 
		  getu32(fs, fatsb->a.f32.rootclust));
	else 
		fatfs->rootsect = fatfs->firstdatasect;

	fatfs->table = fs_buf_alloc(FAT_CACHE_B);

	/* allocate a buffer for inodes */
    fatfs->dinodes = fs_buf_alloc(fatfs->ssize);


    /*
	 * block calculations : although there are no blocks in fat, we will
	 * use these fields for sector calculations
     */
    fs->first_block = 0;
    fs->block_count = sectors;
    fs->last_block = fs->block_count - 1;
	fs->block_size = fs->file_bsize = fatfs->ssize;
	fs->dev_bsize = FATFS_DEV_BSIZE;


	/*
	 * inode calculations
	 */

	/* maximum number of dentries in a sector & cluster */
	fatfs->dentry_cnt_se = fatfs->ssize / sizeof (fatfs_dentry);
	fatfs->dentry_cnt_cl = fatfs->dentry_cnt_se * fatfs->csize;


	/* can we handle this image (due to our meta data addressing scheme?)
	* 2^28 is because we have 2^32 for directory entry addresses and 
	* there are 2^4 entries per sector.  So, we can handle 2^28 sectors
	*/
	if (sectors > (0x1 << 28)) 
		error ("FAT Volume too large for analysis");

	fs->root_inum = FATFS_ROOTINO;
	fs->first_inum = FATFS_FIRSTINO;
	fs->inum_count = fatfs->dentry_cnt_cl * clustcnt;
	fs->last_inum = fs->first_inum + fs->inum_count;


	/* long file name support */
	fatfs->lfn = NULL;
	fatfs->lfn_len = 0;
	fatfs->lfn_chk = 0;


	/*
	 * Other initialization: caches, callbacks.
	 */
	fs->seek_pos = -1;

	fs->inode_walk = fatfs_inode_walk;
	fs->read_block = fs_read_block;
	fs->block_walk = fatfs_block_walk;
	fs->inode_lookup = fatfs_inode_lookup;
	fs->dent_walk = fatfs_dent_walk;
	fs->file_walk = fatfs_file_walk;
	fs->fsstat = fatfs_fsstat;
	fs->fscheck = fatfs_fscheck;
	fs->istat = fatfs_istat;
	fs->close = fatfs_close;

	return (fs);
}
