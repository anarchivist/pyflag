/*
** fatfs
** The Sleuth Kit 
**
** $Date: 2007/05/17 19:32:28 $
**
** Content and meta data layer support for the FAT file system 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All Rights reserved
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

/**
 * \file fatfs.c
 * FAT file system code to handle basic file system processing for opening
 * file system, processing sectors, and directory entries. 
 */
#include "fs_tools_i.h"
#include "fatfs.h"


/*
 * Implementation NOTES 
 *
 * TSK_FS_INODE contains the first cluster.  file_walk will return sector
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




/* TTL is 0 if the entry has not been used.  TTL of 1 means it was the
 * most recently used, and TTL of FAT_CACHE_N means it was the least 
 * recently used.  This function has a LRU replacement algo
 */
// return -1 on error, or cache index on success (0 to FAT_CACHE_N)

static int
getFATCacheIdx(FATFS_INFO * fatfs, DADDR_T sect)
{
    int i, cidx;
    SSIZE_T cnt;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;

    // see if we already have it in the cache
    for (i = 0; i < FAT_CACHE_N; i++) {
        if ((fatfs->fatc_ttl[i] > 0) &&
            (sect >= fatfs->fatc_addr[i]) &&
            (sect < (fatfs->fatc_addr[i] + FAT_CACHE_S))) {
            int a;

            // update the TTLs to push i to the front
            for (a = 0; a < FAT_CACHE_N; a++) {
                if (fatfs->fatc_ttl[a] == 0)
                    continue;

                if (fatfs->fatc_ttl[a] < fatfs->fatc_ttl[i])
                    fatfs->fatc_ttl[a]++;
            }
            fatfs->fatc_ttl[i] = 1;
//          fprintf(stdout, "FAT Hit: %d\n", sect);
//          fflush(stdout);
            return i;
        }
    }

//    fprintf(stdout, "FAT Miss: %d\n", (int)sect);
//    fflush(stdout);

    // Look for an unused entry or an entry with a TTL of FAT_CACHE_N
    cidx = 0;
    for (i = 0; i < FAT_CACHE_N; i++) {
        if ((fatfs->fatc_ttl[i] == 0) ||
            (fatfs->fatc_ttl[i] >= FAT_CACHE_N)) {
            cidx = i;
        }
    }
//    fprintf(stdout, "FAT Removing: %d\n", (int)fatfs->fatc_addr[cidx]);
    //   fflush(stdout);

    // read the data
    cnt =
        tsk_fs_read_random(fs, fatfs->fatc_buf[cidx], FAT_CACHE_B,
        sect * fs->block_size);
    if (cnt != FAT_CACHE_B) {
        if (cnt != -1) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_READ;
        }
        snprintf(tsk_errstr2, TSK_ERRSTR_L,
            "getFATCacheIdx: FAT: %" PRIuDADDR, sect);
        return -1;
    }

    // update the TTLs
    if (fatfs->fatc_ttl[cidx] == 0)     // special case for unused entry
        fatfs->fatc_ttl[cidx] = FAT_CACHE_N + 1;

    for (i = 0; i < FAT_CACHE_N; i++) {
        if (fatfs->fatc_ttl[i] == 0)
            continue;

        if (fatfs->fatc_ttl[i] < fatfs->fatc_ttl[cidx])
            fatfs->fatc_ttl[i]++;
    }

    fatfs->fatc_ttl[cidx] = 1;
    fatfs->fatc_addr[cidx] = sect;
    return cidx;
}


/*
 * Set *value to the entry in the File Allocation Table (FAT) 
 * for the given cluster
 *
 * *value is in clusters and may need to be coverted to
 * sectors by the calling function
 *
 * Invalid values in the FAT (i.e. greater than the largest
 * cluster have a value of 0 returned and a 0 return value.
 *
 * Return 1 on error and 0 on success
 */
static uint8_t
getFAT(FATFS_INFO * fatfs, DADDR_T clust, DADDR_T * value)
{
    uint8_t *ptr;
    uint16_t tmp16;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;
    DADDR_T sect, offs;
    SSIZE_T cnt;
    int cidx;

    /* Sanity Check */
    if (clust > fatfs->lastclust) {
        /* silently ignore requests for the unclustered sectors... */
        if ((clust == fatfs->lastclust + 1) &&
            ((fatfs->firstclustsect + fatfs->csize * fatfs->clustcnt -
                    1) != fs->last_block)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "getFAT: Ignoring request for non-clustered sector\n");
            return 0;
        }

        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "getFAT: invalid cluster address: %" PRIuDADDR, clust);
        return 1;
    }

    switch (fatfs->fs_info.ftype) {
    case TSK_FS_INFO_TYPE_FAT_12:
        if (clust & 0xf000) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_ARG;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "getFAT: TSK_FS_INFO_TYPE_FAT_12 Cluster %" PRIuDADDR
                " too large", clust);
            return 1;
        }

        /* id the sector in the FAT */
        sect = fatfs->firstfatsect +
            ((clust + (clust >> 1)) >> fatfs->ssize_sh);

        /* Load the FAT if we don't have it */
        // see if it is in the cache
        if (-1 == (cidx = getFATCacheIdx(fatfs, sect)))
            return 1;

        /* get the offset into the cache */
        offs = ((sect - fatfs->fatc_addr[cidx]) << fatfs->ssize_sh) +
            (clust + (clust >> 1)) % fatfs->ssize;

        /* special case when the 12-bit value goes across the cache
         * we load the cache to start at this sect.  The cache
         * size must therefore be at least 2 sectors large 
         */
        if (offs == (FAT_CACHE_B - 1)) {

            // read the data -- TTLs will already have been updated
            cnt =
                tsk_fs_read_random(fs, fatfs->fatc_buf[cidx], FAT_CACHE_B,
                sect * fs->block_size);
            if (cnt != FAT_CACHE_B) {
                if (cnt != -1) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "getFAT: TSK_FS_INFO_TYPE_FAT_12 FAT overlap: %"
                    PRIuDADDR, sect);
                return 1;
            }
            fatfs->fatc_addr[cidx] = sect;

            offs = (clust + (clust >> 1)) % fatfs->ssize;
        }

        /* get pointer to entry in current buffer */
        ptr = (uint8_t *) fatfs->fatc_buf[cidx] + offs;

        tmp16 = tsk_getu16(fs->endian, ptr);

        /* slide it over if it is one of the odd clusters */
        if (clust & 1)
            tmp16 >>= 4;

        *value = tmp16 & FATFS_12_MASK;

        /* sanity check */
        if ((*value > (fatfs->lastclust)) &&
            (*value < (0x0ffffff7 & FATFS_12_MASK))) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "getFAT: TSK_FS_INFO_TYPE_FAT_12 cluster (%" PRIuDADDR
                    ") too large (%" PRIuDADDR ") - resetting\n", clust,
                    *value);
            *value = 0;
        }
        return 0;

    case TSK_FS_INFO_TYPE_FAT_16:
        /* Get sector in FAT for cluster and load it if needed */
        sect = fatfs->firstfatsect + ((clust << 1) >> fatfs->ssize_sh);
        if (-1 == (cidx = getFATCacheIdx(fatfs, sect)))
            return 1;

        /* get pointer to entry in the cache buffer */
        ptr = (uint8_t *) fatfs->fatc_buf[cidx] +
            ((sect - fatfs->fatc_addr[cidx]) << fatfs->ssize_sh) +
            ((clust << 1) % fatfs->ssize);

        *value = tsk_getu16(fs->endian, ptr) & FATFS_16_MASK;

        /* sanity check */
        if ((*value > (fatfs->lastclust)) &&
            (*value < (0x0ffffff7 & FATFS_16_MASK))) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "getFAT: contents of TSK_FS_INFO_TYPE_FAT_16 entry %"
                    PRIuDADDR " too large - resetting\n", clust);
            *value = 0;
        }
        return 0;

    case TSK_FS_INFO_TYPE_FAT_32:
        /* Get sector in FAT for cluster and load if needed */
        sect = fatfs->firstfatsect + ((clust << 2) >> fatfs->ssize_sh);
        if (-1 == (cidx = getFATCacheIdx(fatfs, sect)))
            return 1;

        /* get pointer to entry in current buffer */
        ptr = (uint8_t *) fatfs->fatc_buf[cidx] +
            ((sect - fatfs->fatc_addr[cidx]) << fatfs->ssize_sh) +
            (clust << 2) % fatfs->ssize;

        *value = tsk_getu32(fs->endian, ptr) & FATFS_32_MASK;

        /* sanity check */
        if ((*value > fatfs->lastclust) &&
            (*value < (0x0ffffff7 & FATFS_32_MASK))) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "getFAT: contents of entry %" PRIuDADDR
                    " too large - resetting\n", clust);

            *value = 0;
        }
        return 0;

    default:
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "getFAT: Unknown FAT type: %d", fatfs->fs_info.ftype);
        return 1;
    }
}


/* Return 1 if allocated, 0 if unallocated, and -1 if error */
int8_t
is_clustalloc(FATFS_INFO * fatfs, DADDR_T clust)
{
    DADDR_T content;
    if (getFAT(fatfs, clust, &content))
        return -1;
    else if (content == FATFS_UNALLOC)
        return 0;
    else
        return 1;
}


/* 
 * Identifies if a sector is allocated
 *
 * If it is less than the data area, then it is allocated
 * else the FAT table is consulted
 *
 * Return 1 if allocated, 0 if unallocated, and -1 if error 
 */
int8_t
is_sectalloc(FATFS_INFO * fatfs, DADDR_T sect)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) fatfs;
    /* If less than the first cluster sector, then it is allocated 
     * otherwise check the FAT
     */
    if (sect < fatfs->firstclustsect)
        return 1;

    /* If we are in the unused area, then we are "unalloc" */
    if ((sect <= fs->last_block) &&
        (sect >= (fatfs->firstclustsect + fatfs->csize * fatfs->clustcnt)))
        return 0;

    return is_clustalloc(fatfs, FATFS_SECT_2_CLUST(fatfs, sect));
}


/* 
 * Identify if the dentry is a valid 8.3 name
 *
 * returns 1 if it is, 0 if it does not
 */
static uint8_t
is_83_name(fatfs_dentry * de)
{
    if (!de)
        return 0;

    /* The IS_NAME macro will fail if the value is 0x05, which is only
     * valid in name[0], similarly with '.' */
    if ((de->name[0] != FATFS_SLOT_E5) && (de->name[0] != '.') &&
        (FATFS_IS_83_NAME(de->name[0]) == 0))
        return 0;

    /* the second name field can only be . if the first one is a . */
    if (de->name[1] == '.') {
        if (de->name[0] != '.')
            return 0;
    }
    else if (FATFS_IS_83_NAME(de->name[1]) == 0)
        return 0;

    if ((FATFS_IS_83_NAME(de->name[2]) == 0) ||
        (FATFS_IS_83_NAME(de->name[3]) == 0) ||
        (FATFS_IS_83_NAME(de->name[4]) == 0) ||
        (FATFS_IS_83_NAME(de->name[5]) == 0) ||
        (FATFS_IS_83_NAME(de->name[6]) == 0) ||
        (FATFS_IS_83_NAME(de->name[7]) == 0) ||
        (FATFS_IS_83_NAME(de->ext[0]) == 0) ||
        (FATFS_IS_83_NAME(de->ext[1]) == 0) ||
        (FATFS_IS_83_NAME(de->ext[2]) == 0))
        return 0;
    else
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
** _flags: TSK_FS_BLOCK_FLAG_ALLOC, TSK_FS_BLOCK_FLAG_UNALLOC, TSK_FS_BLOCK_FLAG_META
**  TSK_FS_BLOCK_FLAG_CONT
**
** We do not use TSK_FS_BLOCK_FLAG_ALIGN
**
*/
uint8_t
fatfs_block_walk(TSK_FS_INFO * fs, DADDR_T start_blk, DADDR_T end_blk,
    TSK_FS_BLOCK_FLAG_ENUM flags, TSK_FS_BLOCK_WALK_CB action, void *ptr)
{
    char *myname = "fatfs_block_walk";
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    TSK_DATA_BUF *data_buf = NULL;
    SSIZE_T cnt;

    DADDR_T addr;
    int myflags, i;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (start_blk < fs->first_block || start_blk > fs->last_block) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: Start block: %" PRIuDADDR "", myname, start_blk);
        return 1;
    }
    if (end_blk < fs->first_block || end_blk > fs->last_block) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: End block: %" PRIuDADDR "", myname, end_blk);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_block_walk: Block Walking %" PRIuDADDR " to %"
            PRIuDADDR "\n", start_blk, end_blk);


    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((flags & TSK_FS_BLOCK_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_BLOCK_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_UNALLOC);
    }


    /* cycle through block addresses - we will go by sections of the file system */
    addr = start_blk;

    /* Do we have anything in the non-data area ? */
    if ((start_blk < fatfs->firstclustsect)
        && ((flags & TSK_FS_BLOCK_FLAG_ALLOC) == TSK_FS_BLOCK_FLAG_ALLOC)) {

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_block_walk: Walking non-data area (pre %"
                PRIuDADDR "\n", fatfs->firstclustsect);

        if ((data_buf = tsk_data_buf_alloc(fs->block_size * 8)) == NULL) {
            return 1;
        }

        /* Read 8 sectors at a time to be faster */
        for (; addr < fatfs->firstclustsect && addr <= end_blk;) {

            cnt =
                tsk_fs_read_block(fs, data_buf, fs->block_size * 8, addr);
            if (cnt != fs->block_size * 8) {
                if (cnt != -1) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "fatfs_block_walk: pre-data area block: %"
                    PRIuDADDR, addr);
                tsk_data_buf_free(data_buf);
                return 1;
            }

            /* Process the sectors until we get to the clusters, 
             * end of target, or end of buffer */
            for (i = 0;
                i < 8 && (addr) <= end_blk
                && (addr) < fatfs->firstclustsect; i++, addr++) {

                myflags = TSK_FS_BLOCK_FLAG_ALLOC;

                /* stuff before the first data sector is the 
                 * FAT and boot sector */
                if (addr < fatfs->firstdatasect)
                    myflags |= TSK_FS_BLOCK_FLAG_META;
                /* This must be the root directory for TSK_FS_INFO_TYPE_FAT_12/16 */
                else
                    myflags |= TSK_FS_BLOCK_FLAG_CONT;

                if ((flags & myflags) == myflags) {
                    int retval;

                    retval = action(fs, addr,
                        &data_buf->data[i * fs->block_size], myflags, ptr);
                    if (retval == TSK_WALK_STOP) {
                        tsk_data_buf_free(data_buf);
                        return 0;
                    }
                    else if (retval == TSK_WALK_ERROR) {
                        tsk_data_buf_free(data_buf);
                        return 1;
                    }
                }
            }
        }

        tsk_data_buf_free(data_buf);

        /* Was that it? */
        if (addr >= end_blk) {
            return 0;
        }
    }
    /* Reset the first sector to the start of the data area if we did
     * not examine it - the next calculation will screw up otherwise */
    else if (addr < fatfs->firstclustsect) {
        addr = fatfs->firstclustsect;
    }


    /* Now we read in the clusters in cluster-sized chunks,
     * sectors are too small
     */

    /* Determine the base sector of the cluster where the first 
     * sector is located */
    addr = FATFS_CLUST_2_SECT(fatfs, (FATFS_SECT_2_CLUST(fatfs, addr)));

    if ((data_buf =
            tsk_data_buf_alloc(fs->block_size * fatfs->csize)) == NULL) {
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_block_walk: Walking data area blocks (%" PRIuDADDR
            " to %" PRIuDADDR ")\n", addr, end_blk);

    for (; addr <= end_blk; addr += fatfs->csize) {
        int retval;

        /* Identify its allocation status */
        retval = is_sectalloc(fatfs, addr);
        if (retval == -1) {
            tsk_data_buf_free(data_buf);
            return 1;
        }
        else if (retval == 1) {
            myflags = TSK_FS_BLOCK_FLAG_ALLOC;
        }
        else {
            myflags = TSK_FS_BLOCK_FLAG_UNALLOC;
        }


        /* At this point, there should be no more meta - just content */
        myflags |= TSK_FS_BLOCK_FLAG_CONT;

        /* We want this cluster */
        if ((flags & myflags) == myflags) {
            DADDR_T read_size;

            /* The final cluster may not be full */
            if (end_blk - addr + 1 < fatfs->csize)
                read_size = end_blk - addr + 1;
            else
                read_size = fatfs->csize;

            cnt = tsk_fs_read_block
                (fs, data_buf, fs->block_size * read_size, addr);
            if (cnt != fs->block_size * read_size) {
                if (cnt != -1) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "fatfs_block_walk: block: %" PRIuDADDR, addr);
                tsk_data_buf_free(data_buf);
                return 1;
            }

            /* go through each sector in the cluster */
            for (i = 0; i < read_size; i++) {
                int retval;

                if (addr + i < start_blk)
                    continue;
                else if (addr + i > end_blk)
                    break;

                retval = action(fs, addr + i,
                    &data_buf->data[i * fs->block_size], myflags, ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_data_buf_free(data_buf);
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_data_buf_free(data_buf);
                    return 1;
                }
            }
        }
    }

    tsk_data_buf_free(data_buf);
    return 0;
}


/*
** Convert the DOS time to the UNIX version
** 
** UNIX stores the time in seconds from 1970 in UTC
** FAT dates are the actual date with the year relative to 1980
** 
*/
static time_t
dos2unixtime(uint16_t date, uint16_t time)
{
    struct tm tm1;
    time_t ret;

    if (date == 0)
        return 0;

    memset(&tm1, 0, sizeof(struct tm));

    tm1.tm_sec = ((time & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) * 2;
    if ((tm1.tm_sec < 0) || (tm1.tm_sec > 60))
        tm1.tm_sec = 0;

    tm1.tm_min = ((time & FATFS_MIN_MASK) >> FATFS_MIN_SHIFT);
    if ((tm1.tm_min < 0) || (tm1.tm_min > 59))
        tm1.tm_min = 0;

    tm1.tm_hour = ((time & FATFS_HOUR_MASK) >> FATFS_HOUR_SHIFT);
    if ((tm1.tm_hour < 0) || (tm1.tm_hour > 23))
        tm1.tm_hour = 0;

    tm1.tm_mday = ((date & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT);
    if ((tm1.tm_mday < 1) || (tm1.tm_mday > 31))
        tm1.tm_mday = 0;

    tm1.tm_mon = ((date & FATFS_MON_MASK) >> FATFS_MON_SHIFT) - 1;
    if ((tm1.tm_mon < 0) || (tm1.tm_mon > 11))
        tm1.tm_mon = 0;

    /* There is a limit to the year because the UNIX time value is
     * a 32-bit value 
     * the maximum UNIX time is Tue Jan 19 03:14:07 2038
     */
    tm1.tm_year = ((date & FATFS_YEAR_MASK) >> FATFS_YEAR_SHIFT) + 80;
    if ((tm1.tm_year < 0) || (tm1.tm_year > 137))
        tm1.tm_year = 0;

    /* set the daylight savings variable to -1 so that mktime() figures
     * it out */
    tm1.tm_isdst = -1;

    ret = mktime(&tm1);

    if (ret < 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "dos2unixtime: Error running mktime(): %d:%d:%d %d/%d/%d",
                ((time & FATFS_HOUR_MASK) >> FATFS_HOUR_SHIFT),
                ((time & FATFS_MIN_MASK) >> FATFS_MIN_SHIFT),
                ((time & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) * 2,
                ((date & FATFS_MON_MASK) >> FATFS_MON_SHIFT) - 1,
                ((date & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT),
                ((date & FATFS_YEAR_MASK) >> FATFS_YEAR_SHIFT) + 80);
        return 0;
    }

    return ret;
}



/* 
 * convert the attribute list in FAT to a UNIX mode 
 */
static int
dos2unixmode(uint16_t attr)
{
    int mode;

    /* every file is executable */
    mode =
        (TSK_FS_INODE_MODE_IXUSR | TSK_FS_INODE_MODE_IXGRP |
        TSK_FS_INODE_MODE_IXOTH);

    /* file type */
    if (attr & FATFS_ATTR_DIRECTORY)
        mode |= TSK_FS_INODE_MODE_DIR;
    else
        mode |= TSK_FS_INODE_MODE_REG;

    if ((attr & FATFS_ATTR_READONLY) == 0)
        mode |=
            (TSK_FS_INODE_MODE_IRUSR | TSK_FS_INODE_MODE_IRGRP |
            TSK_FS_INODE_MODE_IROTH);

    if ((attr & FATFS_ATTR_HIDDEN) == 0)
        mode |=
            (TSK_FS_INODE_MODE_IWUSR | TSK_FS_INODE_MODE_IWGRP |
            TSK_FS_INODE_MODE_IWOTH);

    return mode;
}


/** 
 * Copy the contents of a raw directry entry into a TSK_FS_INFO structure.
 *
 * @param fatfs File system that directory entry is from
 * @param fs_inode Generic inode structure to copy data into
 * @param in Directory entry to copy data from
 * @param sect Sector address where directory entry is from -- used
 * to determine allocation status.
 * @param inum Address of the inode.
 *
 * @returns 1 on error and 0 on success.  Errors should only occur for
 * Unicode conversion problems and when this occurs the name will be
 * NULL terminated (but with unknown contents). 
 *
 */
uint8_t
fatfs_dinode_copy(FATFS_INFO * fatfs, TSK_FS_INODE * fs_inode,
    fatfs_dentry * in, DADDR_T sect, INUM_T inum)
{
    int dcnt;
    int retval;
    int i;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;

    fs_inode->mode = dos2unixmode(in->attrib);
    fs_inode->addr = inum;

    if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        /* LFN entries don't have these values */
        fs_inode->nlink = 0;
        fs_inode->size = 0;
        fs_inode->mtime = 0;
        fs_inode->atime = 0;
        fs_inode->ctime = 0;
    }
    else {
        /* There is no notion of link in FAT, just deleted or not */
        fs_inode->nlink = (in->name[0] == FATFS_SLOT_DELETED) ? 0 : 1;
        fs_inode->size = (OFF_T) tsk_getu32(fs->endian, in->size);

        /* If these are valid dates, then convert to a unix date format */
        if (FATFS_ISDATE(tsk_getu16(fs->endian, in->wdate)))
            fs_inode->mtime =
                dos2unixtime(tsk_getu16(fs->endian, in->wdate),
                tsk_getu16(fs->endian, in->wtime));
        else
            fs_inode->mtime = 0;

        if (FATFS_ISDATE(tsk_getu16(fs->endian, in->adate)))
            fs_inode->atime =
                dos2unixtime(tsk_getu16(fs->endian, in->adate), 0);
        else
            fs_inode->atime = 0;


        /* cdate is the creation date in FAT and there is no change,
         * so we just put in into change and set create to 0.  The other
         * front-end code knows how to handle it and display it
         */
        if (FATFS_ISDATE(tsk_getu16(fs->endian, in->cdate)))
            fs_inode->ctime =
                dos2unixtime(tsk_getu16(fs->endian, in->cdate),
                tsk_getu16(fs->endian, in->ctime));
        else
            fs_inode->ctime = 0;
    }

    /* Values that do not exist in FAT */
    fs_inode->crtime = 0;
    fs_inode->dtime = 0;
    fs_inode->uid = 0;
    fs_inode->gid = 0;
    fs_inode->seq = 0;


    /* We will be copying a name, so allocate a structure */
    if (fs_inode->name == NULL) {
        if ((fs_inode->name = (TSK_FS_INODE_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_INODE_NAME_LIST))) == NULL)
            return 1;
        fs_inode->name->next = NULL;
    }

    /* If we have a LFN entry, then we need to convert the three
     * parts of the name to UTF-8 and copy it into the name structure .
     */
    if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        fatfs_dentry_lfn *lfn = (fatfs_dentry_lfn *) in;

        /* Convert the first part of the name */
        UTF8 *name8 = (UTF8 *) fs_inode->name->name;
        UTF16 *name16 = (UTF16 *) lfn->part1;

        int retVal = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
            (UTF16 *) & lfn->part1[10],
            &name8,
            (UTF8 *) ((uintptr_t) fs_inode->name->name +
                sizeof(fs_inode->name->name)),
            TSKlenientConversion);

        if (retVal != TSKconversionOK) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_UNICODE;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "fatfs_dinode_copy: Error converting FAT LFN (1) to UTF8: %d",
                retVal);
            *name8 = '\0';

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fatfs_dinode_copy: Error converting FAT LFN (1) to UTF8: %d",
                    retVal);
            return 1;
        }

        /* Convert the second part of the name */
        name16 = (UTF16 *) lfn->part2;
        retVal = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
            (UTF16 *) & lfn->part2[12],
            &name8,
            (UTF8 *) ((uintptr_t) fs_inode->name->
                name + sizeof(fs_inode->name->name)),
            TSKlenientConversion);

        if (retVal != TSKconversionOK) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_UNICODE;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "fatfs_dinode_copy: Error converting FAT LFN (2) to UTF8: %d",
                retVal);
            *name8 = '\0';

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fatfs_dinode_copy: Error converting FAT LFN (2) to UTF8: %d",
                    retVal);
            return 1;
        }

        /* Convert the third part of the name */
        name16 = (UTF16 *) lfn->part3;
        retVal = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &name16,
            (UTF16 *) & lfn->part3[4],
            &name8,
            (UTF8 *) ((uintptr_t) fs_inode->name->
                name + sizeof(fs_inode->name->name)),
            TSKlenientConversion);

        if (retVal != TSKconversionOK) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_UNICODE;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "fatfs_dinode_copy: Error converting FAT LFN (3) to UTF8: %d",
                retVal);
            *name8 = '\0';

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fatfs_dinode_copy: Error converting FAT LFN (3) to UTF8: %d",
                    retVal);
            return 1;
        }

        /* Make sure it is NULL Terminated */
        if ((uintptr_t) name8 >
            (uintptr_t) fs_inode->name->name +
            sizeof(fs_inode->name->name))
            fs_inode->name->name[sizeof(fs_inode->name->name) - 1] = '\0';
        else
            *name8 = '\0';
    }
    /* If the entry is for a volume label, then copy the name and
     * append a special label 
     */
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
    /* If the entry is a normal short entry, then copy the name
     * and add the '.' for the extension
     */
    else {
        for (i = 0; (i < 8) && (in->name[i] != 0) && (in->name[i] != ' ');
            i++) {
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
            for (a = 0;
                (a < 3) && (in->ext[a] != 0) && (in->ext[a] != ' ');
                a++, i++) {
                if ((in->lowercase & FATFS_CASE_LOWER_EXT)
                    && (in->ext[a] >= 'A') && (in->ext[a] <= 'Z'))
                    fs_inode->name->name[i] = in->ext[a] + 32;
                else
                    fs_inode->name->name[i] = in->ext[a];
            }
        }
        fs_inode->name->name[i] = '\0';
    }

    /* Clean up name to remove control characters */
    i = 0;
    while (fs_inode->name->name[i] != '\0') {
        if (TSK_IS_CNTRL(fs_inode->name->name[i]))
            fs_inode->name->name[i] = '^';
        i++;
    }

    /* get the starting cluster */
    if ((in->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        fs_inode->direct_addr[0] = 0;
    }
    else {
        fs_inode->direct_addr[0] =
            FATFS_DENTRY_CLUST(fs, in) & fatfs->mask;
    }

    /* wipe the remaining block address fields */
    for (dcnt = 1; dcnt < fs_inode->direct_count; dcnt++)
        fs_inode->direct_addr[dcnt] = 0;

    for (dcnt = 0; dcnt < fs_inode->indir_count; dcnt++)
        fs_inode->indir_addr[dcnt] = 0;

    /* FAT does not store a size for its directories so make one based
     * on the number of allocated sectors 
     */
    if ((in->attrib & FATFS_ATTR_DIRECTORY) &&
        ((in->attrib & FATFS_ATTR_LFN) != FATFS_ATTR_LFN)) {
        TSK_LIST *list_seen = NULL;

        /* count the total number of clusters in this file */
        DADDR_T clust = FATFS_DENTRY_CLUST(fs, in);
        int cnum = 0;

        while ((clust) && (0 == FATFS_ISEOF(clust, fatfs->mask))) {
            DADDR_T nxt;

            /* Make sure we do not get into an infinite loop */
            if (tsk_list_find(list_seen, clust)) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "Loop found while determining directory size\n");
                break;
            }
            if (tsk_list_add(&list_seen, clust)) {
                tsk_list_free(list_seen);
                list_seen = NULL;
                return 1;
            }

            cnum++;

            if (getFAT(fatfs, clust, &nxt))
                break;
            else
                clust = nxt;
        }

        tsk_list_free(list_seen);
        list_seen = NULL;

        /* we are going to store the sectors, not clusters so calc
         * that value 
         */
        fs_inode->size =
            (OFF_T) ((cnum * fatfs->csize) << fatfs->ssize_sh);
    }

    /* Use the allocation status of the sector to determine if the
     * dentry is allocated or not */
    retval = is_sectalloc(fatfs, sect);
    if (retval == -1) {
        return 1;
    }
    else if (retval == 1) {
        fs_inode->flags = ((in->name[0] == FATFS_SLOT_DELETED) ?
            TSK_FS_INODE_FLAG_UNALLOC : TSK_FS_INODE_FLAG_ALLOC);
    }
    else {
        fs_inode->flags = TSK_FS_INODE_FLAG_UNALLOC;
    }

    /* Slot has not been used yet */
    fs_inode->flags |= ((in->name[0] == FATFS_SLOT_EMPTY) ?
        TSK_FS_INODE_FLAG_UNUSED : TSK_FS_INODE_FLAG_USED);

    return 0;
}

/**
 * Create an FS_INODE structure for the root directory.  FAT does
 * not have a directory entry for the root directory, but this
 * function collects the needed data to make one. 
 *
 * @param fatfs File system to analyze
 * @param fs_inode Inode structure to copy root directory information into.
 * @return 1 on error and 0 on success
 */
uint8_t
fatfs_make_root(FATFS_INFO * fatfs, TSK_FS_INODE * fs_inode)
{
    int i;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) fatfs;

    fs_inode->mode = (TSK_FS_INODE_MODE_DIR);
    fs_inode->nlink = 1;
    fs_inode->addr = fs->root_inum;
    fs_inode->flags = (TSK_FS_INODE_FLAG_USED | TSK_FS_INODE_FLAG_ALLOC);
    fs_inode->uid = fs_inode->gid = 0;
    fs_inode->mtime = fs_inode->atime = fs_inode->ctime = fs_inode->dtime =
        0;

    if (fs_inode->name == NULL) {
        if ((fs_inode->name = (TSK_FS_INODE_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_INODE_NAME_LIST))) == NULL)
            return 1;
        fs_inode->name->next = NULL;
    }
    fs_inode->name->name[0] = '\0';

    for (i = 1; i < fs_inode->direct_count; i++)
        fs_inode->direct_addr[i] = 0;

    /* TSK_FS_INFO_TYPE_FAT_12 and TSK_FS_INFO_TYPE_FAT_16 don't use the FAT for root directory, so 
     * we will have to fake it.
     */
    if (fatfs->fs_info.ftype != TSK_FS_INFO_TYPE_FAT_32) {
        DADDR_T snum;

        /* Other code will have to check this as a special condition 
         */
        fs_inode->direct_addr[0] = 1;

        /* difference between end of FAT and start of clusters */
        snum = fatfs->firstclustsect - fatfs->firstdatasect;

        /* number of bytes */
        fs_inode->size = snum << fatfs->ssize_sh;
    }
    else {
        /* Get the number of allocated clusters */
        DADDR_T cnum;
        DADDR_T clust;
        TSK_LIST *list_seen = NULL;

        /* base cluster */
        clust = FATFS_SECT_2_CLUST(fatfs, fatfs->rootsect);
        fs_inode->direct_addr[0] = clust;

        cnum = 0;
        while ((clust) && (0 == FATFS_ISEOF(clust, FATFS_32_MASK))) {
            DADDR_T nxt;

            /* Make sure we do not get into an infinite loop */
            if (tsk_list_find(list_seen, clust)) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "Loop found while determining root directory size\n");
                break;
            }
            if (tsk_list_add(&list_seen, clust)) {
                tsk_list_free(list_seen);
                list_seen = NULL;
                return 1;
            }

            cnum++;
            if (getFAT(fatfs, clust, &nxt))
                break;
            else
                clust = nxt;
        }
        tsk_list_free(list_seen);
        list_seen = NULL;
        fs_inode->size = (cnum * fatfs->csize) << fatfs->ssize_sh;
    }
    return 0;
}



/* 
 * Is the pointed to buffer a directory entry buffer? 
 *
 * Returns 1 if it is, 0 if not
 */
uint8_t
fatfs_isdentry(FATFS_INFO * fatfs, fatfs_dentry * de)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & fatfs->fs_info;
    if (!de)
        return 0;

    /* LFN have their own checks, which are pretty weak since most
     * fields are UTF16 */
    if ((de->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        fatfs_dentry_lfn *de_lfn = (fatfs_dentry_lfn *) de;

        if ((de_lfn->seq > (FATFS_LFN_SEQ_FIRST | 0x0f))
            && (de_lfn->seq != FATFS_SLOT_DELETED))
            return 0;

        return 1;
    }
    else {
        if (de->lowercase & ~(FATFS_CASE_LOWER_ALL))
            return 0;
        else if (de->attrib & ~(FATFS_ATTR_ALL))
            return 0;

        /* The ctime, cdate, and adate fields are optional and 
         * therefore 0 is a valid value
         */
        if ((tsk_getu16(fs->endian, de->ctime) != 0) &&
            (FATFS_ISTIME(tsk_getu16(fs->endian, de->ctime)) == 0))
            return 0;
        else if ((tsk_getu16(fs->endian, de->wtime) != 0) &&
            (FATFS_ISTIME(tsk_getu16(fs->endian, de->wtime)) == 0))
            return 0;
        else if ((tsk_getu16(fs->endian, de->cdate) != 0) &&
            (FATFS_ISDATE(tsk_getu16(fs->endian, de->cdate)) == 0))
            return 0;
        else if ((tsk_getu16(fs->endian, de->adate) != 0) &&
            (FATFS_ISDATE(tsk_getu16(fs->endian, de->adate)) == 0))
            return 0;
        else if (FATFS_ISDATE(tsk_getu16(fs->endian, de->wdate)) == 0)
            return 0;

        /* verify the starting cluster is small enough */
        else if ((FATFS_DENTRY_CLUST(fs, de) > (fatfs->lastclust)) &&
            (FATFS_ISEOF(FATFS_DENTRY_CLUST(fs, de), fatfs->mask) == 0))
            return 0;

        /* Verify the file size is smaller than the data area */
        else if (tsk_getu32(fs->endian, de->size) >
            ((fatfs->clustcnt * fatfs->csize) << fatfs->ssize_sh))
            return 0;

        return is_83_name(de);
        //return 1;
    }
}



/**************************************************************************
 *
 * INODE WALKING
 * 
 *************************************************************************/
/* Mark the sector used in the bitmap */
static uint8_t
inode_walk_file_act(TSK_FS_INFO * fs, DADDR_T addr, char *buf,
    size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    setbit((uint8_t *) ptr, addr);
    return TSK_WALK_CONT;
}

/* The inode_walk call back for each file.  we want only the directories */
static uint8_t
inode_walk_dent_act(TSK_FS_INFO * fs, TSK_FS_DENT * fs_dent, void *ptr)
{
    if ((fs_dent->fsi == NULL)
        || ((fs_dent->fsi->mode & TSK_FS_INODE_MODE_FMT) !=
            TSK_FS_INODE_MODE_DIR))
        return TSK_WALK_CONT;

    /* Get the sector addresses & ignore any errors */
    if (fs->file_walk(fs, fs_dent->fsi, 0, 0,
            TSK_FS_FILE_FLAG_SLACK | TSK_FS_FILE_FLAG_AONLY |
            TSK_FS_FILE_FLAG_RECOVER, inode_walk_file_act, ptr)) {
        tsk_error_reset();
    }

    return TSK_WALK_CONT;
}

static uint8_t
inode_walk_dent_orphan_act(TSK_FS_INFO * fs, TSK_FS_DENT * fs_dent,
    void *ptr)
{
    if ((fs_dent->fsi)
        && (fs_dent->fsi->flags & TSK_FS_INODE_FLAG_UNALLOC)) {
        if (tsk_list_add(&fs->list_inum_named, fs_dent->fsi->addr))
            return TSK_WALK_STOP;
    }
    return TSK_WALK_CONT;
}

/*
 * walk the inodes
 *
 * Flags that are used: TSK_FS_INODE_FLAG_ALLOC, TSK_FS_INODE_FLAG_UNALLOC,
 * TSK_FS_INODE_FLAG_USED, TSK_FS_INODE_FLAG_UNUSED, TSK_FS_INODE_FLAG_ORPHAN
 *
 */
uint8_t
fatfs_inode_walk(TSK_FS_INFO * fs, INUM_T start_inum, INUM_T end_inum,
    TSK_FS_INODE_FLAG_ENUM flags, TSK_FS_INODE_WALK_CB action, void *ptr)
{
    char *myname = "fatfs_inode_walk";
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    INUM_T inum;
    TSK_FS_INODE *fs_inode;
    DADDR_T sect, ssect, lsect, base_read;
    fatfs_dentry *dep;
    unsigned int myflags, didx, i;
    uint8_t *sect_alloc;
    SSIZE_T cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum || start_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: Start inode:  %" PRIuINUM "", myname, start_inum);
        return 1;
    }
    else if (end_inum < fs->first_inum || end_inum > fs->last_inum
        || end_inum < start_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "%s: End inode: %" PRIuINUM "", myname, end_inum);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_inode_walk: Inode Walking %" PRIuINUM " to %"
            PRIuINUM "\n", start_inum, end_inum);

    /* If ORPHAN is wanted, then make sure that the flags are correct */
    if (flags & TSK_FS_INODE_FLAG_ORPHAN) {
        flags |= TSK_FS_INODE_FLAG_UNALLOC;
        flags &= ~TSK_FS_INODE_FLAG_ALLOC;
    }

    else if (((flags & TSK_FS_INODE_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_INODE_FLAG_UNALLOC) == 0)) {
        flags |= (TSK_FS_INODE_FLAG_ALLOC | TSK_FS_INODE_FLAG_UNALLOC);
    }

    /* If neither of the USED or UNUSED flags are set, then set them 
     * both
     */
    if (((flags & TSK_FS_INODE_FLAG_USED) == 0) &&
        ((flags & TSK_FS_INODE_FLAG_UNUSED) == 0)) {
        flags |= (TSK_FS_INODE_FLAG_USED | TSK_FS_INODE_FLAG_UNUSED);
    }


    /* If we are looking for orphan files and have not yet filled
     * in the list of unalloc inodes that are pointed to, then fill
     * in the list 
     */
    if ((flags & TSK_FS_INODE_FLAG_ORPHAN)
        && (fs->list_inum_named == NULL)) {

        if (fatfs_dent_walk(fs, fs->root_inum,
                TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_UNALLOC |
                TSK_FS_DENT_FLAG_RECURSE, inode_walk_dent_orphan_act,
                NULL)) {
            strncat(tsk_errstr2,
                " - fatfs_inode_walk: identifying inodes allocated by file names",
                TSK_ERRSTR_L);
            return 1;
        }

    }

    if ((fs_inode =
            tsk_fs_inode_alloc(FATFS_NDADDR, FATFS_NIADDR)) == NULL)
        return 1;

    /* The root_inum is reserved for the root directory, which does
     * not have a dentry in FAT, so we make one up
     */
    if ((start_inum == fs->root_inum) &&
        ((TSK_FS_INODE_FLAG_ALLOC & flags) == TSK_FS_INODE_FLAG_ALLOC) &&
        ((TSK_FS_INODE_FLAG_USED & flags) == TSK_FS_INODE_FLAG_USED) &&
        ((TSK_FS_INODE_FLAG_ORPHAN & flags) == 0)) {
        int retval;

        if (fatfs_make_root(fatfs, fs_inode)) {
            tsk_fs_inode_free(fs_inode);
            return 1;
        }

        retval = action(fs, fs_inode, ptr);
        if (retval == TSK_WALK_STOP) {
            tsk_fs_inode_free(fs_inode);
            return 0;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_inode_free(fs_inode);
            return 1;
        }
    }

    /* advance it so that it is a valid starting point */
    if (start_inum == fs->root_inum) {
        // exit if we only wanted the root inode 
        if (end_inum == fs->root_inum) {
            tsk_fs_inode_free(fs_inode);
            return 0;
        }
        start_inum++;
    }

    /* We are going to be looking at each sector to see if it has 
     * dentries.  First, run dent_walk to find all sectors that are 
     * from allocated directories.  We'll be make sure to print those */
    if ((sect_alloc =
            (uint8_t *) tsk_malloc((size_t) ((fs->block_count +
                        7) / 8))) == NULL) {
        tsk_fs_inode_free(fs_inode);
        return 1;
    }

    memset((char *) sect_alloc, 0, (size_t) ((fs->block_count + 7) / 8));

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_inode_walk: Walking directories to collect sector info\n");

    /* We need to make a special run of the Root directory to get its sectors */
    if (fatfs_make_root(fatfs, fs_inode)) {
        tsk_fs_inode_free(fs_inode);
        free(sect_alloc);
        return 1;
    }

    if (fs->file_walk(fs, fs_inode, 0, 0,
            TSK_FS_FILE_FLAG_SLACK | TSK_FS_FILE_FLAG_AONLY |
            TSK_FS_FILE_FLAG_RECOVER, inode_walk_file_act,
            (void *) sect_alloc)) {
        tsk_fs_inode_free(fs_inode);
        free(sect_alloc);
        return 1;
    }

    if (fatfs_dent_walk(fs, fs->root_inum,
            TSK_FS_DENT_FLAG_ALLOC | TSK_FS_DENT_FLAG_RECURSE,
            inode_walk_dent_act, (void *) sect_alloc)) {
        strncat(tsk_errstr2, " - fatfs_inode_walk: mapping directories",
            TSK_ERRSTR_L);
        tsk_fs_inode_free(fs_inode);
        free(sect_alloc);
        return 1;
    }



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

    /* identify the starting and ending inodes sector addrs */
    ssect = FATFS_INODE_2_SECT(fatfs, start_inum);
    lsect = FATFS_INODE_2_SECT(fatfs, end_inum);

    if (ssect > fs->last_block) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_inode_walk: Starting inode in sector too big for image: %"
            PRIuDADDR, ssect);
        tsk_fs_inode_free(fs_inode);
        free(sect_alloc);
        return 1;
    }
    else if (lsect > fs->last_block) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_inode_walk: Ending inode in sector too big for image: %"
            PRIuDADDR, lsect);
        tsk_fs_inode_free(fs_inode);
        free(sect_alloc);
        return 1;
    }

    sect = ssect;

    /* This occurs for the root directory of TSK_FS_INFO_TYPE_FAT_12/16 
     * 
     * We are going to process the image in clusters, so take care of the root
     * directory seperately.
     */
    if ((sect < fatfs->firstclustsect) &&
        ((flags & TSK_FS_INODE_FLAG_ORPHAN) == 0)) {

        /* Read these as sectors - so we do them independently */
        for (; sect <= lsect && sect < fatfs->firstclustsect; sect++) {

            /* read the sector */
            cnt =
                tsk_fs_read_block(fs, fatfs->dinodes, fatfs->ssize, sect);
            if (cnt != fatfs->ssize) {
                if (cnt != -1) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "fatfs_inode_walk: sector: %" PRIuDADDR, sect);
                tsk_fs_inode_free(fs_inode);
                free(sect_alloc);
                return 1;
            }

            /* get the base inode address of this sector */
            inum = FATFS_SECT_2_INODE(fatfs, sect);

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fatfs_inode_walk: Processing sector %" PRIuDADDR
                    " (pre data area) starting at inode %" PRIuINUM
                    "\n", sect, inum);

            dep = (fatfs_dentry *) fatfs->dinodes->data;

            /* cycle through the directory entries */
            for (didx = 0; didx < fatfs->dentry_cnt_se;
                didx++, inum++, dep++) {
                int retval;

                /* If less, then move on */
                if (inum < start_inum)
                    continue;

                /* If we are done, then return  */
                if (inum > end_inum) {
                    tsk_fs_inode_free(fs_inode);
                    free(sect_alloc);
                    return 0;
                }


                /* if this is a long file name entry, then skip it and 
                 * wait for the short name */
                if ((dep->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN)
                    continue;


                /* we don't care about . and .. entries because they
                 * are redundant of other 'inode' entries */
                if (((dep->attrib & FATFS_ATTR_DIRECTORY)
                        == FATFS_ATTR_DIRECTORY)
                    && (dep->name[0] == '.'))
                    continue;


                /* Allocation status 
                 * This is determined by the name only since this
                 * is the root directory
                 */
                myflags =
                    ((dep->name[0] ==
                        FATFS_SLOT_DELETED) ? TSK_FS_INODE_FLAG_UNALLOC :
                    TSK_FS_INODE_FLAG_ALLOC);

                if ((flags & myflags) != myflags)
                    continue;

                /* Slot has not been used yet */
                myflags |= ((dep->name[0] == FATFS_SLOT_EMPTY) ?
                    TSK_FS_INODE_FLAG_UNUSED : TSK_FS_INODE_FLAG_USED);

                if ((flags & myflags) != myflags)
                    continue;


                /* Do a final sanity check */
                if (0 == fatfs_isdentry(fatfs, dep))
                    continue;

                if (fatfs_dinode_copy(fatfs, fs_inode, dep, sect, inum)) {
                    /* Ignore this error and continue */
                    if (tsk_errno == TSK_ERR_FS_UNICODE) {
                        tsk_error_reset();
                        continue;
                    }
                    else {
                        tsk_fs_inode_free(fs_inode);
                        free(sect_alloc);
                        return 1;
                    }
                }

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "fatfs_inode_walk: Directory Entry %" PRIuINUM
                        " (%u) at sector %" PRIuDADDR "\n", inum, didx,
                        sect);

                retval = action(fs, fs_inode, ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_fs_inode_free(fs_inode);
                    free(sect_alloc);
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_fs_inode_free(fs_inode);
                    free(sect_alloc);
                    return 1;
                }
            }                   /* dentries */
        }

        /* We are done */
        if (sect >= lsect) {
            tsk_fs_inode_free(fs_inode);
            free(sect_alloc);
            return 0;
        }
    }
    /* update sect if we did not go into the previous case
     * because the ORPHAN flag was set */
    else if (sect < fatfs->firstclustsect) {
        sect = fatfs->firstclustsect;
    }

    /* get the base sector for the cluster in which the first inode exists */
    base_read =
        FATFS_CLUST_2_SECT(fatfs, (FATFS_SECT_2_CLUST(fatfs, sect)));

    /* cycle through the sectors and look for dentries
     * Read by cluster since they are bigger and more effecient
     */
    for (sect = base_read; sect <= lsect; sect += fatfs->csize) {
        DADDR_T read_size;
        int clustalloc;

        /* if the cluster is not allocated, then do not go into it if we 
         * only want allocated/link entries
         * If it is allocated, then go into it no matter what
         */
        clustalloc = is_sectalloc(fatfs, sect);
        if (clustalloc == -1) {
            tsk_fs_inode_free(fs_inode);
            free(sect_alloc);
            return 1;
        }
        else if ((clustalloc == 0)
            && ((flags & TSK_FS_INODE_FLAG_UNALLOC) == 0)) {
            continue;
        }


        /* If it is allocated, but we know it is not allocated to a
         * directory then skip it.  NOTE: This will miss unallocated
         * entries in slack space of the file...
         */
        if ((clustalloc == 1) && (isset(sect_alloc, sect) == 0))
            continue;

        /* The final cluster may not be full */
        if (lsect - sect + 1 < fatfs->csize)
            read_size = lsect - sect + 1;
        else
            read_size = fatfs->csize;

        /* read the full cluster */
        cnt = tsk_fs_read_block
            (fs, fatfs->dinodes, read_size << fatfs->ssize_sh, sect);
        if (cnt != (read_size << fatfs->ssize_sh)) {
            if (cnt != -1) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "fatfs_inode_walk: sector: %" PRIuDADDR, sect);
            tsk_fs_inode_free(fs_inode);
            free(sect_alloc);
            return 1;
        }

        for (i = 0; i < read_size; i++) {

            /* if we know it is not part of a directory and it is not valid dentires,
             * then skip it */
            if ((isset(sect_alloc, sect) == 0) &&
                (fatfs_isdentry(fatfs,
                        (fatfs_dentry *) & fatfs->dinodes->data[i <<
                            fatfs->ssize_sh])
                    == 0))
                continue;

            /* See if the last inode in this block is smaller than the starting */
            if (FATFS_SECT_2_INODE(fatfs, sect + i + 1) < start_inum)
                continue;

            /* get the base inode address of this sector */
            inum = FATFS_SECT_2_INODE(fatfs, sect + i);

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "fatfs_inode_walk: Processing sector %" PRIuDADDR
                    " starting at inode %" PRIuINUM "\n", sect + i, inum);

            dep =
                (fatfs_dentry *) & fatfs->dinodes->data[i << fatfs->
                ssize_sh];

            /* cycle through the directory entries */
            for (didx = 0; didx < fatfs->dentry_cnt_se;
                didx++, inum++, dep++) {
                int retval;


                /* If less, then move on */
                if (inum < start_inum)
                    continue;

                /* If we are done, then return  */
                if (inum > end_inum) {
                    tsk_fs_inode_free(fs_inode);
                    free(sect_alloc);
                    return 0;
                }

                /* if this is a long file name entry, then skip it and 
                 * wait for the short name */
                if ((dep->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN)
                    continue;


                /* we don't care about . and .. entries because they
                 * are redundant of other 'inode' entries */
                if (((dep->attrib & FATFS_ATTR_DIRECTORY)
                        == FATFS_ATTR_DIRECTORY)
                    && (dep->name[0] == '.'))
                    continue;


                /* Allocation status 
                 * This is determined first by the sector allocation status
                 * an then the dentry flag.  When a directory is deleted, the
                 * contents are not always set to unallocated
                 */
                if (clustalloc == 1) {
                    myflags =
                        ((dep->name[0] ==
                            FATFS_SLOT_DELETED) ? TSK_FS_INODE_FLAG_UNALLOC
                        : TSK_FS_INODE_FLAG_ALLOC);
                }
                else {
                    myflags = TSK_FS_INODE_FLAG_UNALLOC;
                }

                if ((flags & myflags) != myflags)
                    continue;

                /* Slot has not been used yet */
                myflags |= ((dep->name[0] == FATFS_SLOT_EMPTY) ?
                    TSK_FS_INODE_FLAG_UNUSED : TSK_FS_INODE_FLAG_USED);

                if ((flags & myflags) != myflags)
                    continue;

                /* If we want only orphans, then check if this
                 * inode is in the seen list 
                 */
                if ((myflags & TSK_FS_INODE_FLAG_UNALLOC) &&
                    (flags & TSK_FS_INODE_FLAG_ORPHAN) &&
                    (tsk_list_find(fs->list_inum_named, inum))) {
                    continue;
                }

                /* Do a final sanity check */
                if (0 == fatfs_isdentry(fatfs, dep))
                    continue;

                if (fatfs_dinode_copy(fatfs, fs_inode, dep, sect, inum)) {
                    if (tsk_errno == TSK_ERR_FS_UNICODE) {
                        tsk_error_reset();
                        continue;
                    }
                    else {
                        tsk_fs_inode_free(fs_inode);
                        free(sect_alloc);
                        return 1;
                    }
                }

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "fatfs_inode_walk: Directory Entry %" PRIuINUM
                        " (%u) at sector %" PRIuDADDR "\n", inum, didx,
                        sect + i);

                retval = action(fs, fs_inode, ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_fs_inode_free(fs_inode);
                    free(sect_alloc);
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_fs_inode_free(fs_inode);
                    free(sect_alloc);
                    return 1;
                }
            }
        }                       /* dentries */
    }                           /* clusters */

    free(sect_alloc);
    tsk_fs_inode_free(fs_inode);
    return 0;
}                               /* end of inode_walk */


/*
 * return the contents of a specific inode
 *
 * NULL is returned if an error occurs or if the entry is not
 * a valid inode
 */
static TSK_FS_INODE *
fatfs_inode_lookup(TSK_FS_INFO * fs, INUM_T inum)
{
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    TSK_FS_INODE *fs_inode;
    SSIZE_T cnt;
    DADDR_T sect;
    uint32_t off;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /* 
     * Sanity check.
     */
    if (inum < fs->first_inum || inum > fs->last_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_INODE_NUM;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_inode_lookup: %" PRIuINUM " too large/small", inum);
        return NULL;
    }

    if ((fs_inode =
            tsk_fs_inode_alloc(FATFS_NDADDR, FATFS_NIADDR)) == NULL)
        return NULL;

    /* As there is no real root inode in FAT, use the made up one */
    if (inum == fs->root_inum) {
        if (fatfs_make_root(fatfs, fs_inode))
            return NULL;
        else
            return fs_inode;
    }

    /* Get the sector that this inode would be in and its offset */
    sect = FATFS_INODE_2_SECT(fatfs, inum);
    off = FATFS_INODE_2_OFF(fatfs, inum);

    if (sect > fs->last_block) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_INODE_NUM;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_inode_lookup: Inode %" PRIuINUM
            " in sector too big for image: %" PRIuDADDR, inum, sect);
        return NULL;
    }


    if (tsk_verbose)
        tsk_fprintf(stderr,
            "fatfs_inode_lookup: reading sector %" PRIuDADDR
            " for inode %" PRIuINUM "\n", sect, inum);

    cnt = tsk_fs_read_block(fs, fatfs->dinodes, fatfs->ssize, sect);
    if (cnt != fatfs->ssize) {
        if (cnt != -1) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_READ;
        }
        snprintf(tsk_errstr2, TSK_ERRSTR_L,
            "fatfs_inode_lookup: block: %" PRIuDADDR, sect);
        return NULL;
    }

    fatfs->dep = (fatfs_dentry *) & fatfs->dinodes->data[off];
    if (fatfs_isdentry(fatfs, fatfs->dep)) {
        if (fatfs_dinode_copy(fatfs, fs_inode, fatfs->dep, sect, inum)) {
            /* If there was a unicode conversion error, 
             * then still return the inode */
            if (tsk_errno != TSK_ERR_FS_UNICODE)
                return NULL;
            else
                tsk_error_reset();
        }
        return fs_inode;
    }
    else {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_INODE_NUM;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_inode_lookup: %" PRIuINUM " is not an inode", inum);
        return NULL;
    }
}




/**************************************************************************
 *
 * FILE WALKING
 * 
 *************************************************************************/

/* 
 * Flags: TSK_FS_FILE_FLAG_SLACK, TSK_FS_FILE_FLAG_AONLY
 * TSK_FS_FILE_FLAG_RECOVER
 *
 * no notion of NOSPARSE or META
 *
 *
 * flags on action: TSK_FS_BLOCK_FLAG_CONT, TSK_FS_BLOCK_FLAG_META, 
 * TSK_FS_BLOCK_FLAG_ALLOC, TSK_FS_BLOCK_FLAG_UNALLOC
 *
 * Return 1 on error and 0 on success
 */
static uint8_t
fatfs_file_walk(TSK_FS_INFO * fs, TSK_FS_INODE * fs_inode, uint32_t type,
    uint16_t id, TSK_FS_FILE_FLAG_ENUM flags, TSK_FS_FILE_WALK_CB action,
    void *ptr)
{
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    unsigned int i;
    OFF_T size;
    DADDR_T clust, sbase;
    uint32_t len;
    TSK_DATA_BUF *data_buf;
    SSIZE_T cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((data_buf =
            tsk_data_buf_alloc(fatfs->csize << fatfs->ssize_sh)) == NULL)
        return 1;

    if (flags & TSK_FS_FILE_FLAG_SLACK)
        size = roundup(fs_inode->size, fatfs->csize << fatfs->ssize_sh);
    else
        size = fs_inode->size;

    clust = fs_inode->direct_addr[0];

    if ((clust > (fatfs->lastclust)) &&
        (FATFS_ISEOF(clust, fatfs->mask) == 0)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_INODE_INT;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "fatfs_file_walk: Starting cluster address too large: %"
            PRIuDADDR, clust);
        tsk_data_buf_free(data_buf);
        return 1;
    }

    /* this is the root directory entry, special case: it is not in the FAT */
    if ((fs->ftype != TSK_FS_INFO_TYPE_FAT_32) && (clust == 1)) {
        DADDR_T snum = fatfs->firstclustsect - fatfs->firstdatasect;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_file_walk: Walking Root Directory\n");

        for (i = 0; i < snum; i++) {
            int retval;
            int myflags =
                (TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_ALLOC);

            if ((flags & TSK_FS_FILE_FLAG_AONLY) == 0) {
                cnt = tsk_fs_read_block(fs, data_buf, fatfs->ssize,
                    fatfs->rootsect + i);
                if (cnt != fatfs->ssize) {
                    if (cnt != -1) {
                        tsk_error_reset();
                        tsk_errno = TSK_ERR_FS_READ;
                    }
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "fatfs_file_walk: Root directory block: %"
                        PRIuDADDR, fatfs->rootsect + i);
                    tsk_data_buf_free(data_buf);
                    return 1;
                }
            }

            retval =
                action(fs, fatfs->rootsect + i, data_buf->data,
                fatfs->ssize, myflags, ptr);
            if (retval == TSK_WALK_STOP) {
                tsk_data_buf_free(data_buf);
                return 0;
            }
            else if (retval == TSK_WALK_ERROR) {
                tsk_data_buf_free(data_buf);
                return 1;
            }
        }
    }

    /* A deleted file that we want to recover 
     * In this case, we could get a lot of errors because of inconsistent
     * data.  TO make it clear that these are from a recovery, we set most
     * error codes to _RECOVER so that they can be more easily suppressed.
     */
    else if ((fs_inode->flags & TSK_FS_INODE_FLAG_UNALLOC) &&
        (flags & TSK_FS_FILE_FLAG_RECOVER)) {

        DADDR_T startclust = clust;
        OFF_T recoversize = size;
        int retval;


        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_file_walk: Walking deleted file %" PRIuINUM
                " in recovery mode\n", fs_inode->addr);

        /* We know the size and the starting cluster
         *
         * We are going to take the clusters from the starting cluster
         * onwards and skip the clusters that are current allocated
         */

        /* Sanity checks on the starting cluster */
        /* Convert the cluster addr to a sector addr */
        sbase = FATFS_CLUST_2_SECT(fatfs, startclust);

        if (sbase > fs->last_block) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_RECOVER;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "fatfs_file_walk: Starting cluster address too large (recovery): %"
                PRIuDADDR, sbase);
            tsk_data_buf_free(data_buf);
            return 1;
        }

        /* If the starting cluster is already allocated then we can't
         * recover it */
        retval = is_clustalloc(fatfs, startclust);
        if (retval == -1) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_RECOVER;
            tsk_data_buf_free(data_buf);
            return 1;
        }
        else if (retval == 1) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_RECOVER;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "Starting cluster of deleted file is allocated");
            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "Starting cluster of deleted file is allocated - aborting\n");
            }
            tsk_data_buf_free(data_buf);
            return 1;
        }


        /* Part 1 is to make sure there are enough unallocated clusters
         * for the size of the file 
         */
        clust = startclust;
        size = recoversize;

        // we could make this negative so sign it for the comparison
        while ((int64_t) size > 0) {
            int retval;
            sbase = FATFS_CLUST_2_SECT(fatfs, clust);

            /* Are we past the end of the FS? 
             * that means we could not find enough unallocated clusters
             * for the file size */
            if (sbase > fs->last_block) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_RECOVER;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "Could not find enough unallocated sectors to recover with");

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "Could not find enough unallocated sectors to recover with - aborting\n");

                tsk_data_buf_free(data_buf);
                return 1;
            }

            /* Skip allocated clusters */
            retval = is_clustalloc(fatfs, clust);
            if (retval == -1) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_RECOVER;
                tsk_data_buf_free(data_buf);
                return 1;
            }
            else if (retval == 1) {
                clust++;
                continue;
            }

            /* We can use this sector */
            size -= (fatfs->csize << fatfs->ssize_sh);
            clust++;
        }

        /* If we got this far, then we can recover the file */
        clust = startclust;
        size = recoversize;
        while ((int64_t) size > 0) {
            int myflags =
                TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_UNALLOC;

            sbase = FATFS_CLUST_2_SECT(fatfs, clust);
            /* Are we past the end of the FS? */
            if (sbase > fs->last_block) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_RECOVER;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "Recover went past end of FS - should have been caught");
                tsk_data_buf_free(data_buf);
                return 1;
            }

            /* Skip allocated clusters */
            retval = is_clustalloc(fatfs, clust);
            if (retval == -1) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_RECOVER;
                tsk_data_buf_free(data_buf);
                return 1;
            }
            else if (retval == 1) {
                clust++;
                continue;
            }

            /* Read the cluster */
            if ((flags & TSK_FS_FILE_FLAG_AONLY) == 0) {
                cnt = tsk_fs_read_block
                    (fs, data_buf, fatfs->csize << fatfs->ssize_sh, sbase);
                if (cnt != (fatfs->csize << fatfs->ssize_sh)) {
                    if (cnt != -1) {
                        tsk_error_reset();
                        tsk_errno = TSK_ERR_FS_READ;
                    }
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "fatfs_file_walk: block during recovery: %"
                        PRIuDADDR, sbase);
                    tsk_data_buf_free(data_buf);
                    return 1;
                }
            }


            /* Go through each sector in the cluster we read */
            for (i = 0; i < fatfs->csize && (int64_t) size > 0; i++) {
                int retval;

                if (flags & TSK_FS_FILE_FLAG_SLACK)
                    len = fatfs->ssize;
                else
                    len =
                        (size < fatfs->ssize) ? (int) size : fatfs->ssize;

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "fatfs_file_walk: Processing %" PRIu32
                        " bytes of sector %" PRIuDADDR " for recovery\n",
                        len, (sbase + i));

                retval =
                    action(fs, sbase + i,
                    &data_buf->data[i << fatfs->ssize_sh], len, myflags,
                    ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_data_buf_free(data_buf);
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_data_buf_free(data_buf);
                    return 1;
                }
                size -= len;
            }
            clust++;
        }
    }

    /* Normal cluster chain walking */
    else {
        TSK_LIST *list_seen = NULL;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fatfs_file_walk: Walking file %" PRIuINUM
                " in normal mode\n", fs_inode->addr);

        /* Cycle through the cluster chain */
        while ((clust & fatfs->mask) > 0 && (int64_t) size > 0 &&
            (0 == FATFS_ISEOF(clust, fatfs->mask))) {
            int myflags;
            int retval;

            /* Convert the cluster addr to a sector addr */
            sbase = FATFS_CLUST_2_SECT(fatfs, clust);

            if (sbase > fs->last_block) {
                tsk_data_buf_free(data_buf);
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_INODE_INT;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "fatfs_file_walk: Invalid sector address in FAT (too large): %"
                    PRIuDADDR, sbase);
                return 1;
            }

            myflags = TSK_FS_BLOCK_FLAG_CONT;
            retval = is_clustalloc(fatfs, clust);
            if (retval == -1) {
                tsk_data_buf_free(data_buf);
                return 1;
            }
            else if (retval == 1) {
                myflags |= TSK_FS_BLOCK_FLAG_ALLOC;
            }
            else {
                myflags |= TSK_FS_BLOCK_FLAG_UNALLOC;
            }

            /* Read the cluster */
            if ((flags & TSK_FS_FILE_FLAG_AONLY) == 0) {
                cnt = tsk_fs_read_block
                    (fs, data_buf, fatfs->csize << fatfs->ssize_sh, sbase);
                if (cnt != (fatfs->csize << fatfs->ssize_sh)) {
                    if (cnt != -1) {
                        tsk_error_reset();
                        tsk_errno = TSK_ERR_FS_READ;
                    }
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "fatfs_file_walk: sector: %" PRIuDADDR, sbase);
                    tsk_data_buf_free(data_buf);
                    return 1;
                }
            }

            /* Go through each sector in the cluster we read */
            for (i = 0; i < fatfs->csize && (int64_t) size > 0; i++) {
                int retval;

                if (flags & TSK_FS_FILE_FLAG_SLACK)
                    len = fatfs->ssize;
                else
                    len =
                        (size < fatfs->ssize) ? (int) size : fatfs->ssize;

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "fatfs_file_walk: Processing %" PRIu32
                        " bytes of sector %" PRIuDADDR "\n", len,
                        (sbase + i));

                retval =
                    action(fs, sbase + i,
                    &data_buf->data[i << fatfs->ssize_sh], len, myflags,
                    ptr);
                if (retval == TSK_WALK_STOP) {
                    tsk_data_buf_free(data_buf);
                    tsk_list_free(list_seen);
                    list_seen = NULL;
                    return 0;
                }
                else if (retval == TSK_WALK_ERROR) {
                    tsk_data_buf_free(data_buf);
                    tsk_list_free(list_seen);
                    list_seen = NULL;
                    return 1;
                }
                size -= len;
            }
            if ((int64_t) size > 0) {
                DADDR_T nxt;
                if (getFAT(fatfs, clust, &nxt)) {
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "file walk: Inode: %" PRIuINUM "  cluster: %"
                        PRIuDADDR, fs_inode->addr, clust);
                    tsk_list_free(list_seen);
                    list_seen = NULL;
                    return 1;
                }
                clust = nxt;

                /* Make sure we do not get into an infinite loop */
                if (tsk_list_find(list_seen, clust)) {
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "Loop found while walking file\n");
                    break;
                }

                if (tsk_list_add(&list_seen, clust)) {
                    tsk_list_free(list_seen);
                    list_seen = NULL;
                    return 1;
                }
            }
        }
        tsk_list_free(list_seen);
        list_seen = NULL;
    }

    tsk_data_buf_free(data_buf);
    return 0;
}


/* return 1 on error and 0 on success */
static uint8_t
fatfs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
        "fscheck not implemented for FAT yet");
    return 1;

    /* Check that allocated dentries point to start of allcated cluster chain */


    /* Size of file is consistent with cluster chain length */


    /* Allocated cluster chains have a corresponding alloc dentry */


    /* Non file dentries have no clusters */


    /* Only one volume label */


    /* Dump Bad Sector Addresses */


    /* Dump unused sector addresses 
     * Reserved area, end of FAT, end of Data Area */

}


/* Return 1 on error and 0 on success */
static uint8_t
fatfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    unsigned int i;
    int a;
    DADDR_T next, snext, sstart, send;
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    fatfs_sb *sb = fatfs->sb;
    TSK_DATA_BUF *data_buf;
    fatfs_dentry *de;
    SSIZE_T cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((data_buf = tsk_data_buf_alloc(fatfs->ssize)) == NULL) {
        return 1;
    }


    /* Read the root directory sector so that we can get the volume
     * label from it */
    cnt = tsk_fs_read_block(fs, data_buf, fatfs->ssize, fatfs->rootsect);
    if (cnt != fatfs->ssize) {
        if (cnt != -1) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_READ;
        }
        snprintf(tsk_errstr2, TSK_ERRSTR_L,
            "fatfs_fsstat: root directory: %" PRIuDADDR, fatfs->rootsect);
        tsk_data_buf_free(data_buf);
        return 1;
    }


    /* Find the dentry that is set as the volume label */
    de = (fatfs_dentry *) data_buf->data;
    for (i = 0; i < fatfs->ssize; i += sizeof(*de)) {
        if (de->attrib == FATFS_ATTR_VOLUME)
            break;
        de++;
    }
    /* If we didn't find it, then reset de */
    if (de->attrib != FATFS_ATTR_VOLUME)
        de = NULL;


    /* Print the general file system information */

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "File System Type: FAT");
    if (fs->ftype == TSK_FS_INFO_TYPE_FAT_12)
        tsk_fprintf(hFile, "12\n");
    else if (fs->ftype == TSK_FS_INFO_TYPE_FAT_16)
        tsk_fprintf(hFile, "16\n");
    else if (fs->ftype == TSK_FS_INFO_TYPE_FAT_32)
        tsk_fprintf(hFile, "32\n");
    else
        tsk_fprintf(hFile, "\n");

    tsk_fprintf(hFile, "\nOEM Name: %c%c%c%c%c%c%c%c\n", sb->oemname[0],
        sb->oemname[1], sb->oemname[2], sb->oemname[3], sb->oemname[4],
        sb->oemname[5], sb->oemname[6], sb->oemname[7]);


    if (fatfs->fs_info.ftype != TSK_FS_INFO_TYPE_FAT_32) {
        tsk_fprintf(hFile, "Volume ID: 0x%" PRIx32 "\n",
            tsk_getu32(fs->endian, sb->a.f16.vol_id));

        tsk_fprintf(hFile,
            "Volume Label (Boot Sector): %c%c%c%c%c%c%c%c%c%c%c\n",
            sb->a.f16.vol_lab[0], sb->a.f16.vol_lab[1],
            sb->a.f16.vol_lab[2], sb->a.f16.vol_lab[3],
            sb->a.f16.vol_lab[4], sb->a.f16.vol_lab[5],
            sb->a.f16.vol_lab[6], sb->a.f16.vol_lab[7],
            sb->a.f16.vol_lab[8], sb->a.f16.vol_lab[9],
            sb->a.f16.vol_lab[10]);

        if ((de) && (de->name)) {
            tsk_fprintf(hFile,
                "Volume Label (Root Directory): %c%c%c%c%c%c%c%c%c%c%c\n",
                de->name[0], de->name[1], de->name[2], de->name[3],
                de->name[4], de->name[5], de->name[6], de->name[7],
                de->name[8], de->name[9], de->name[10]);
        }
        else {
            tsk_fprintf(hFile, "Volume Label (Root Directory):\n");
        }

        tsk_fprintf(hFile, "File System Type Label: %c%c%c%c%c%c%c%c\n",
            sb->a.f16.fs_type[0], sb->a.f16.fs_type[1],
            sb->a.f16.fs_type[2], sb->a.f16.fs_type[3],
            sb->a.f16.fs_type[4], sb->a.f16.fs_type[5],
            sb->a.f16.fs_type[6], sb->a.f16.fs_type[7]);
    }
    else {

        TSK_DATA_BUF *fat_fsinfo_buf;
        fatfs_fsinfo *fat_info;

        if ((fat_fsinfo_buf =
                tsk_data_buf_alloc(sizeof(fatfs_fsinfo))) == NULL) {
            tsk_data_buf_free(data_buf);
            return 1;
        }

        tsk_fprintf(hFile, "Volume ID: 0x%" PRIx32 "\n",
            tsk_getu32(fs->endian, sb->a.f32.vol_id));

        tsk_fprintf(hFile,
            "Volume Label (Boot Sector): %c%c%c%c%c%c%c%c%c%c%c\n",
            sb->a.f32.vol_lab[0], sb->a.f32.vol_lab[1],
            sb->a.f32.vol_lab[2], sb->a.f32.vol_lab[3],
            sb->a.f32.vol_lab[4], sb->a.f32.vol_lab[5],
            sb->a.f32.vol_lab[6], sb->a.f32.vol_lab[7],
            sb->a.f32.vol_lab[8], sb->a.f32.vol_lab[9],
            sb->a.f32.vol_lab[10]);

        if ((de) && (de->name)) {
            tsk_fprintf(hFile,
                "Volume Label (Root Directory): %c%c%c%c%c%c%c%c%c%c%c\n",
                de->name[0], de->name[1], de->name[2], de->name[3],
                de->name[4], de->name[5], de->name[6], de->name[7],
                de->name[8], de->name[9], de->name[10]);
        }
        else {
            tsk_fprintf(hFile, "Volume Label (Root Directory):\n");
        }

        tsk_fprintf(hFile, "File System Type Label: %c%c%c%c%c%c%c%c\n",
            sb->a.f32.fs_type[0], sb->a.f32.fs_type[1],
            sb->a.f32.fs_type[2], sb->a.f32.fs_type[3],
            sb->a.f32.fs_type[4], sb->a.f32.fs_type[5],
            sb->a.f32.fs_type[6], sb->a.f32.fs_type[7]);


        /* Process the FS info */
        if (tsk_getu16(fs->endian, sb->a.f32.fsinfo)) {
            cnt =
                tsk_fs_read_block(fs, fat_fsinfo_buf, sizeof(fatfs_fsinfo),
                (DADDR_T) tsk_getu16(fs->endian, sb->a.f32.fsinfo));

            if (cnt != sizeof(fatfs_fsinfo)) {
                if (cnt != -1) {
                    tsk_error_reset();
                    tsk_errno = TSK_ERR_FS_READ;
                }
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "fatfs_fsstat: TSK_FS_INFO_TYPE_FAT_32 FSINFO block: %"
                    PRIuDADDR, (DADDR_T) tsk_getu16(fs->endian,
                        sb->a.f32.fsinfo));
                tsk_data_buf_free(data_buf);
                tsk_data_buf_free(fat_fsinfo_buf);
                return 1;
            }


            fat_info = (fatfs_fsinfo *) fat_fsinfo_buf->data;
            tsk_fprintf(hFile,
                "Next Free Sector (FS Info): %" PRIuDADDR "\n",
                FATFS_CLUST_2_SECT(fatfs, tsk_getu32(fs->endian,
                        fat_info->nextfree)));

            tsk_fprintf(hFile,
                "Free Sector Count (FS Info): %" PRIu32 "\n",
                (tsk_getu32(fs->endian,
                        fat_info->freecnt) * fatfs->csize));

            tsk_data_buf_free(fat_fsinfo_buf);
        }
    }

    tsk_data_buf_free(data_buf);

    tsk_fprintf(hFile, "\nSectors before file system: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->prevsect));

    tsk_fprintf(hFile, "\nFile System Layout (in sectors)\n");

    tsk_fprintf(hFile, "Total Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fs->first_block, fs->last_block);

    tsk_fprintf(hFile, "* Reserved: 0 - %" PRIuDADDR "\n",
        fatfs->firstfatsect - 1);

    tsk_fprintf(hFile, "** Boot Sector: 0\n");

    if (fatfs->fs_info.ftype == TSK_FS_INFO_TYPE_FAT_32) {
        tsk_fprintf(hFile, "** FS Info Sector: %" PRIu16 "\n",
            tsk_getu16(fs->endian, sb->a.f32.fsinfo));

        tsk_fprintf(hFile, "** Backup Boot Sector: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb->a.f32.bs_backup));
    }

    for (i = 0; i < fatfs->numfat; i++) {
        DADDR_T base = fatfs->firstfatsect + i * (fatfs->sectperfat);

        tsk_fprintf(hFile, "* FAT %d: %" PRIuDADDR " - %" PRIuDADDR "\n",
            i, base, (base + fatfs->sectperfat - 1));
    }

    tsk_fprintf(hFile, "* Data Area: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fatfs->firstdatasect, fs->last_block);

    if (fatfs->fs_info.ftype != TSK_FS_INFO_TYPE_FAT_32) {
        DADDR_T x = fatfs->csize * fatfs->clustcnt;

        tsk_fprintf(hFile,
            "** Root Directory: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fatfs->firstdatasect, fatfs->firstclustsect - 1);

        tsk_fprintf(hFile,
            "** Cluster Area: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fatfs->firstclustsect, (fatfs->firstclustsect + x - 1));

        if ((fatfs->firstclustsect + x - 1) != fs->last_block) {
            tsk_fprintf(hFile,
                "** Non-clustered: %" PRIuDADDR " - %" PRIuDADDR "\n",
                (fatfs->firstclustsect + x), fs->last_block);
        }
    }
    else {
        TSK_LIST *list_seen = NULL;
        DADDR_T x = fatfs->csize * (fatfs->lastclust - 1);
        DADDR_T clust, clust_p;

        tsk_fprintf(hFile,
            "** Cluster Area: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fatfs->firstclustsect, (fatfs->firstclustsect + x - 1));


        clust_p = fatfs->rootsect;
        clust = FATFS_SECT_2_CLUST(fatfs, fatfs->rootsect);
        while ((clust) && (0 == FATFS_ISEOF(clust, FATFS_32_MASK))) {
            DADDR_T nxt;
            clust_p = clust;

            /* Make sure we do not get into an infinite loop */
            if (tsk_list_find(list_seen, clust)) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "Loop found while determining root directory size\n");
                break;
            }
            if (tsk_list_add(&list_seen, clust)) {
                tsk_list_free(list_seen);
                list_seen = NULL;
                return 1;
            }

            if (getFAT(fatfs, clust, &nxt))
                break;
            clust = nxt;
        }
        tsk_list_free(list_seen);
        list_seen = NULL;

        tsk_fprintf(hFile,
            "*** Root Directory: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fatfs->rootsect, (FATFS_CLUST_2_SECT(fatfs, clust_p + 1) - 1));

        if ((fatfs->firstclustsect + x - 1) != fs->last_block) {
            tsk_fprintf(hFile,
                "** Non-clustered: %" PRIuDADDR " - %" PRIuDADDR "\n",
                (fatfs->firstclustsect + x), fs->last_block);
        }
    }


    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Range: %" PRIuINUM " - %" PRIuINUM "\n",
        fs->first_inum, fs->last_inum);
    tsk_fprintf(hFile, "Root Directory: %" PRIuINUM "\n", fs->root_inum);


    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Sector Size: %" PRIu16 "\n", fatfs->ssize);
    tsk_fprintf(hFile, "Cluster Size: %" PRIu32 "\n",
        (uint32_t) fatfs->csize << fatfs->ssize_sh);

    tsk_fprintf(hFile, "Total Cluster Range: 2 - %" PRIuDADDR "\n",
        fatfs->lastclust);


    /* cycle via cluster and look at each cluster in the FAT 
     * for clusters marked as bad */
    cnt = 0;
    for (i = 2; i <= fatfs->lastclust; i++) {
        DADDR_T entry;
        DADDR_T sect;

        /* Get the FAT table entry */
        if (getFAT(fatfs, i, &entry))
            break;

        if (FATFS_ISBAD(entry, fatfs->mask) == 0) {
            continue;
        }

        if (cnt == 0)
            tsk_fprintf(hFile, "Bad Sectors: ");

        sect = FATFS_CLUST_2_SECT(fatfs, i);
        for (a = 0; a < fatfs->csize; a++) {
            tsk_fprintf(hFile, "%" PRIuDADDR " ", sect + a);
            if ((++cnt % 8) == 0)
                tsk_fprintf(hFile, "\n");
        }
    }
    if ((cnt > 0) && ((cnt % 8) != 0))
        tsk_fprintf(hFile, "\n");



    /* Display the FAT Table */
    tsk_fprintf(hFile, "\nFAT CONTENTS (in sectors)\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    /* 'sstart' marks the first sector of the current run to print */
    sstart = fatfs->firstclustsect;

    /* cycle via cluster and look at each cluster in the FAT  to make runs */
    for (i = 2; i <= fatfs->lastclust; i++) {

        /* 'send' marks the end sector of the current run, which will extend
         * when the current cluster continues to the next 
         */
        send = FATFS_CLUST_2_SECT(fatfs, i + 1) - 1;

        /* get the next cluster */
        if (getFAT(fatfs, i, &next))
            break;

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
                tsk_fprintf(hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> EOF\n", sstart, send, send - sstart + 1);
            else if (FATFS_ISBAD(next, fatfs->mask))
                tsk_fprintf(hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> BAD\n", sstart, send, send - sstart + 1);
            else
                tsk_fprintf(hFile,
                    "%" PRIuDADDR "-%" PRIuDADDR " (%" PRIuDADDR
                    ") -> %" PRIuDADDR "\n", sstart, send,
                    send - sstart + 1, snext);
        }

        /* reset the starting counter */
        sstart = send + 1;
    }

    return 0;
}


/************************* istat *******************************/

/* Callback action for file_walk to print the sector addresses
 * of a file
 */

typedef struct {
    FILE *hFile;
    int idx;
    int istat_seen;
} FATFS_PRINT_ADDR;

static uint8_t
print_addr_act(TSK_FS_INFO * fs, DADDR_T addr, char *buf,
    size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    FATFS_PRINT_ADDR *print = (FATFS_PRINT_ADDR *) ptr;

    tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr);

    if (++(print->idx) == 8) {
        tsk_fprintf(print->hFile, "\n");
        print->idx = 0;
    }
    print->istat_seen = 1;

    return TSK_WALK_CONT;
}


/* Return 1 on error  and 0 on success */
static uint8_t
fatfs_istat(TSK_FS_INFO * fs, FILE * hFile, INUM_T inum, DADDR_T numblock,
    int32_t sec_skew)
{
    TSK_FS_INODE *fs_inode;
    TSK_FS_INODE_NAME_LIST *fs_name;
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    FATFS_PRINT_ADDR print;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((fs_inode = fatfs_inode_lookup(fs, inum)) == NULL) {
        return 1;
    }
    tsk_fprintf(hFile, "Directory Entry: %" PRIuINUM "\n", inum);

    tsk_fprintf(hFile, "%sAllocated\n",
        (fs_inode->flags & TSK_FS_INODE_FLAG_UNALLOC) ? "Not " : "");

    tsk_fprintf(hFile, "File Attributes: ");

    /* This should only be null if we have the root directory */
    if (fatfs->dep == NULL) {
        if (inum == fs->root_inum)
            tsk_fprintf(hFile, "Directory\n");
        else
            tsk_fprintf(hFile, "File\n");
    }
    else if ((fatfs->dep->attrib & FATFS_ATTR_LFN) == FATFS_ATTR_LFN) {
        tsk_fprintf(hFile, "Long File Name\n");
    }
    else {
        if (fatfs->dep->attrib & FATFS_ATTR_DIRECTORY)
            tsk_fprintf(hFile, "Directory");
        else if (fatfs->dep->attrib & FATFS_ATTR_VOLUME)
            tsk_fprintf(hFile, "Volume Label");
        else
            tsk_fprintf(hFile, "File");

        if (fatfs->dep->attrib & FATFS_ATTR_READONLY)
            tsk_fprintf(hFile, ", Read Only");
        if (fatfs->dep->attrib & FATFS_ATTR_HIDDEN)
            tsk_fprintf(hFile, ", Hidden");
        if (fatfs->dep->attrib & FATFS_ATTR_SYSTEM)
            tsk_fprintf(hFile, ", System");
        if (fatfs->dep->attrib & FATFS_ATTR_ARCHIVE)
            tsk_fprintf(hFile, ", Archive");

        tsk_fprintf(hFile, "\n");
    }

    tsk_fprintf(hFile, "Size: %" PRIuOFF "\n", fs_inode->size);
    /* This value is fake in FAT, so there is no point in printing it here */
    //tsk_fprintf(hFile, "Num of links: %lu\n", (ULONG) fs_inode->nlink);

    if (fs_inode->name) {
        fs_name = fs_inode->name;
        tsk_fprintf(hFile, "Name: %s\n", fs_name->name);
    }

    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted Directory Entry Times:\n");
        fs_inode->mtime -= sec_skew;
        fs_inode->atime -= sec_skew;
        fs_inode->ctime -= sec_skew;

        tsk_fprintf(hFile, "Written:\t%s", ctime(&fs_inode->mtime));
        tsk_fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
        tsk_fprintf(hFile, "Created:\t%s", ctime(&fs_inode->ctime));

        fs_inode->mtime += sec_skew;
        fs_inode->atime += sec_skew;
        fs_inode->ctime += sec_skew;

        tsk_fprintf(hFile, "\nOriginal Directory Entry Times:\n");
    }
    else
        tsk_fprintf(hFile, "\nDirectory Entry Times:\n");

    tsk_fprintf(hFile, "Written:\t%s", ctime(&fs_inode->mtime));
    tsk_fprintf(hFile, "Accessed:\t%s", ctime(&fs_inode->atime));
    tsk_fprintf(hFile, "Created:\t%s", ctime(&fs_inode->ctime));

    tsk_fprintf(hFile, "\nSectors:\n");

    /* A bad hack to force a specified number of blocks */
    if (numblock > 0)
        fs_inode->size = numblock * fs->block_size;

    print.istat_seen = 0;
    print.idx = 0;
    print.hFile = hFile;

    if (fs->file_walk(fs, fs_inode, 0, 0,
            (TSK_FS_FILE_FLAG_AONLY | TSK_FS_FILE_FLAG_SLACK |
                TSK_FS_FILE_FLAG_NOID), print_addr_act, (void *) &print)) {
        tsk_fprintf(hFile, "\nError reading file\n");
        tsk_error_print(hFile);
        tsk_error_reset();
    }
    else if (print.idx != 0) {
        tsk_fprintf(hFile, "\n");
    }

    /* Display the recovery information if we can */
    if (fs_inode->flags & TSK_FS_INODE_FLAG_UNALLOC) {
        tsk_fprintf(hFile, "\nRecovery:\n");


        print.istat_seen = 0;
        print.idx = 0;
        if (fs->file_walk(fs, fs_inode, 0, 0,
                (TSK_FS_FILE_FLAG_AONLY | TSK_FS_FILE_FLAG_SLACK |
                    TSK_FS_FILE_FLAG_RECOVER | TSK_FS_FILE_FLAG_NOID),
                print_addr_act, (void *) &print)) {
            if (tsk_errno != TSK_ERR_FS_RECOVER)
                tsk_fprintf(hFile, "\nError reading file\n");
            tsk_error_reset();
        }

        if (print.istat_seen == 0) {
            tsk_fprintf(hFile, "File recovery not possible\n");
        }
        else if (print.idx != 0)
            tsk_fprintf(hFile, "\n");

    }

    tsk_fs_inode_free(fs_inode);
    return 0;
}


/* return 1 on error and 0 on success */
uint8_t
fatfs_jopen(TSK_FS_INFO * fs, INUM_T inum)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "FAT does not have a journal\n");
    return 1;
}

/* return 1 on error and 0 on success */
uint8_t
fatfs_jentry_walk(TSK_FS_INFO * fs, int flags,
    TSK_FS_JENTRY_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "FAT does not have a journal\n");
    return 1;
}


/* return 1 on error and 0 on success */
uint8_t
fatfs_jblk_walk(TSK_FS_INFO * fs, DADDR_T start, DADDR_T end, int flags,
    TSK_FS_JBLK_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_errno = TSK_ERR_FS_FUNC;
    snprintf(tsk_errstr, TSK_ERRSTR_L, "FAT does not have a journal\n");
    return 1;
}


/* fatfs_close - close an fatfs file system */
static void
fatfs_close(TSK_FS_INFO * fs)
{
    FATFS_INFO *fatfs = (FATFS_INFO *) fs;
    tsk_data_buf_free(fatfs->dinodes);
    tsk_list_free(fs->list_inum_named);
    fs->list_inum_named = NULL;
    free(fatfs->sb);
    free(fs);
}


/* fatfs_open - open a fatfs file system image 
 *
 * return NULL on error or not FAT file system
 * */
TSK_FS_INFO *
fatfs_open(TSK_IMG_INFO * img_info, SSIZE_T offset,
    TSK_FS_INFO_TYPE_ENUM ftype, uint8_t test)
{
    char *myname = "fatfs_open";
    FATFS_INFO *fatfs;
    unsigned int len;
    TSK_FS_INFO *fs;
    fatfs_sb *fatsb;
    DADDR_T sectors;
    SSIZE_T cnt;
    int i;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((ftype & TSK_FS_INFO_TYPE_FS_MASK) != TSK_FS_INFO_TYPE_FAT_TYPE) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "%s: Invalid FS Type", myname);
        return NULL;
    }

    if ((fatfs = (FATFS_INFO *) tsk_malloc(sizeof(*fatfs))) == NULL)
        return NULL;

    fs = &(fatfs->fs_info);
    fs->ftype = ftype;

    fs->img_info = img_info;
    fs->offset = offset;

    /*
     * Read the super block.
     */
    len = sizeof(fatfs_sb);
    fatsb = fatfs->sb = (fatfs_sb *) tsk_malloc(len);
    if (fatsb == NULL) {
        free(fatfs);
        return NULL;
    }

    cnt = tsk_fs_read_random(fs, (char *) fatsb, len, (DADDR_T) 0);
    if (cnt != len) {
        if (cnt != -1) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_READ;
        }
        snprintf(tsk_errstr2, TSK_ERRSTR_L, "%s: boot sector", myname);
        free(fatfs->sb);
        free(fatfs);
        return NULL;
    }

    /* Check the magic value  and ID endian ordering */
    if (tsk_fs_guessu16(fs, fatsb->magic, FATFS_FS_MAGIC)) {
        free(fatsb);
        free(fatfs);
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Not a FATFS file system (magic)");
        return NULL;
    }

    fs->dev_bsize = FATFS_DEV_BSIZE;
    fatfs->ssize = tsk_getu16(fs->endian, fatsb->ssize);

    if (fatfs->ssize == 512) {
        fatfs->ssize_sh = 9;
    }
    else if (fatfs->ssize == 1024) {
        fatfs->ssize_sh = 10;
    }
    else if (fatfs->ssize == 2048) {
        fatfs->ssize_sh = 11;
    }
    else if (fatfs->ssize == 4096) {
        fatfs->ssize_sh = 12;
    }
    else {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Error: sector size (%d) is not a multiple of device size (%d)\nDo you have a disk image instead of a partition image?",
            fatfs->ssize, fs->dev_bsize);
        free(fatsb);
        free(fatfs);
        return NULL;
    }

    fatfs->csize = fatsb->csize;        /* cluster size */
    if ((fatfs->csize != 0x01) &&
        (fatfs->csize != 0x02) &&
        (fatfs->csize != 0x04) &&
        (fatfs->csize != 0x08) &&
        (fatfs->csize != 0x10) &&
        (fatfs->csize != 0x20) &&
        (fatfs->csize != 0x40) && (fatfs->csize != 0x80)) {
        free(fatsb);
        free(fatfs);
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Not a FATFS file system (cluster size)");
        return NULL;
    }

    fatfs->numfat = fatsb->numfat;      /* number of tables */
    if ((fatfs->numfat == 0) || (fatfs->numfat > 8)) {
        free(fatsb);
        free(fatfs);
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Not a FATFS file system (number of FATs)");
        return NULL;
    }

    /* We can't do a sanity check on this b.c. TSK_FS_INFO_TYPE_FAT_32 has a value of 0 */
    /* num of root entries */
    fatfs->numroot = tsk_getu16(fs->endian, fatsb->numroot);


    /* if sectors16 is 0, then the number of sectors is stored in sectors32 */
    if (0 == (sectors = tsk_getu16(fs->endian, fatsb->sectors16)))
        sectors = tsk_getu32(fs->endian, fatsb->sectors32);

    /* if secperfat16 is 0, then read sectperfat32 */
    if (0 == (fatfs->sectperfat =
            tsk_getu16(fs->endian, fatsb->sectperfat16)))
        fatfs->sectperfat =
            tsk_getu32(fs->endian, fatsb->a.f32.sectperfat32);

    if (fatfs->sectperfat == 0) {
        free(fatsb);
        free(fatfs);
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Not a FATFS file system (invalid sectors per FAT)");
        return NULL;
    }

    fatfs->firstfatsect = tsk_getu16(fs->endian, fatsb->reserved);
    if ((fatfs->firstfatsect == 0) || (fatfs->firstfatsect > sectors)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Not a FATFS file system (invalid first FAT sector %"
            PRIuDADDR ")", fatfs->firstfatsect);
        free(fatsb);
        free(fatfs);
        return NULL;
    }

    /* The sector of the begining of the data area  - which is 
     * after all of the FATs
     *
     * For TSK_FS_INFO_TYPE_FAT_12 and TSK_FS_INFO_TYPE_FAT_16, the data area starts with the root
     * directory entries and then the first cluster.  For TSK_FS_INFO_TYPE_FAT_32,
     * the data area starts with clusters and the root directory
     * is somewhere in the data area
     */
    fatfs->firstdatasect = fatfs->firstfatsect +
        fatfs->sectperfat * fatfs->numfat;

    /* The sector where the first cluster is located.  It will be used
     * to translate cluster addresses to sector addresses 
     *
     * For TSK_FS_INFO_TYPE_FAT_32, the first cluster is the start of the data area and
     * it is after the root directory for TSK_FS_INFO_TYPE_FAT_12 and TSK_FS_INFO_TYPE_FAT_16.  At this
     * point in the program, numroot is set to 0 for TSK_FS_INFO_TYPE_FAT_32
     */
    fatfs->firstclustsect = fatfs->firstdatasect +
        ((fatfs->numroot * 32 + fatfs->ssize - 1) / fatfs->ssize);

    /* total number of clusters */
    fatfs->clustcnt = (sectors - fatfs->firstclustsect) / fatfs->csize;

    /* the first cluster is #2, so the final cluster is: */
    fatfs->lastclust = 1 + fatfs->clustcnt;


    /* identify the FAT type by the total number of data clusters
     * this calculation is from the MS FAT Overview Doc
     *
     * A FAT file system made by another OS could use different values
     */
    if (ftype == TSK_FS_INFO_TYPE_FAT_AUTO) {

        if (fatfs->clustcnt < 4085) {
            ftype = TSK_FS_INFO_TYPE_FAT_12;
        }
        else if (fatfs->clustcnt < 65525) {
            ftype = TSK_FS_INFO_TYPE_FAT_16;
        }
        else {
            ftype = TSK_FS_INFO_TYPE_FAT_32;
        }

        fatfs->fs_info.ftype = ftype;
    }

    /* Some sanity checks */
    else {
        if ((ftype == TSK_FS_INFO_TYPE_FAT_12)
            && (fatfs->clustcnt >= 4085)) {
            free(fatsb);
            free(fatfs);
            tsk_error_reset();
            tsk_errno = TSK_ERR_FS_MAGIC;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "Too many sectors for TSK_FS_INFO_TYPE_FAT_12: try auto-detect mode");
            return NULL;
        }
    }

    if ((ftype == TSK_FS_INFO_TYPE_FAT_32) && (fatfs->numroot != 0)) {
        free(fatsb);
        free(fatfs);
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Invalid TSK_FS_INFO_TYPE_FAT_32 image (numroot != 0)");
        return NULL;
    }

    if ((ftype != TSK_FS_INFO_TYPE_FAT_32) && (fatfs->numroot == 0)) {
        free(fatsb);
        free(fatfs);
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Invalid FAT image (numroot == 0, and not TSK_FS_INFO_TYPE_FAT_32)");
        return NULL;
    }


    /* Set the mask to use on the cluster values */
    if (ftype == TSK_FS_INFO_TYPE_FAT_12) {
        fatfs->mask = FATFS_12_MASK;
    }
    else if (ftype == TSK_FS_INFO_TYPE_FAT_16) {
        fatfs->mask = FATFS_16_MASK;
    }
    else if (ftype == TSK_FS_INFO_TYPE_FAT_32) {
        fatfs->mask = FATFS_32_MASK;
    }
    else {
        free(fatsb);
        free(fatfs);
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Unknown FAT type in fatfs_open: %d\n", ftype);
        return NULL;
    }
    fs->duname = "Sector";

    /* the root directories are always after the FAT for TSK_FS_INFO_TYPE_FAT_12 and TSK_FS_INFO_TYPE_FAT_16,
     * but are dynamically located for TSK_FS_INFO_TYPE_FAT_32
     */
    if (ftype == TSK_FS_INFO_TYPE_FAT_32)
        fatfs->rootsect = FATFS_CLUST_2_SECT(fatfs,
            tsk_getu32(fs->endian, fatsb->a.f32.rootclust));
    else
        fatfs->rootsect = fatfs->firstdatasect;

    for (i = 0; i < FAT_CACHE_N; i++) {
        fatfs->fatc_addr[i] = 0;
        fatfs->fatc_ttl[i] = 0;
    }

    /* allocate a cluster-sized buffer for inodes */
    if ((fatfs->dinodes =
            tsk_data_buf_alloc(fatfs->csize << fatfs->ssize_sh)) == NULL) {

        free(fatsb);
        free(fatfs);
        return NULL;
    }


    /*
     * block calculations : although there are no blocks in fat, we will
     * use these fields for sector calculations
     */
    fs->first_block = 0;
    fs->block_count = sectors;
    fs->last_block = fs->block_count - 1;
    fs->block_size = fatfs->ssize;

    /*
     * inode calculations
     */

    /* maximum number of dentries in a sector & cluster */
    fatfs->dentry_cnt_se = fatfs->ssize / sizeof(fatfs_dentry);
    fatfs->dentry_cnt_cl = fatfs->dentry_cnt_se * fatfs->csize;

    fs->root_inum = FATFS_ROOTINO;
    fs->first_inum = FATFS_FIRSTINO;
    fs->inum_count =
        (fs->block_count - fatfs->firstdatasect) * fatfs->dentry_cnt_se;
    fs->last_inum = fs->first_inum + fs->inum_count;


    /*
     * Other initialization: caches, callbacks.
     */
    fs->inode_walk = fatfs_inode_walk;
    fs->block_walk = fatfs_block_walk;
    fs->inode_lookup = fatfs_inode_lookup;
    fs->dent_walk = fatfs_dent_walk;
    fs->file_walk = fatfs_file_walk;
    fs->fsstat = fatfs_fsstat;
    fs->fscheck = fatfs_fscheck;
    fs->istat = fatfs_istat;
    fs->close = fatfs_close;

    fs->jblk_walk = fatfs_jblk_walk;
    fs->jentry_walk = fatfs_jentry_walk;
    fs->jopen = fatfs_jopen;
    fs->journ_inum = 0;

    fs->list_inum_named = NULL;

    return (fs);
}
