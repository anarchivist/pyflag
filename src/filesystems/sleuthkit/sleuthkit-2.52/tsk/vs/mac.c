/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/20 16:18:12 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file mac.c
 * Contains the functions to process and load a Mac partition table.
 */
#include "tsk_vs_i.h"
#include "tsk_mac.h"


/* 
 * Process the partition table at the sector address 
 * 
 * It is loaded into the internal sorted list 
 *
 * Return 1 on error and 0 on success
 */
static uint8_t
mac_load_table(TSK_MM_INFO * mm)
{
    mac_part part;
    char *table_str;
    uint32_t idx, max_part;
    TSK_DADDR_T taddr = mm->offset / mm->block_size + MAC_PART_SOFFSET;
    TSK_DADDR_T max_addr = (mm->img_info->size - mm->offset) / mm->block_size;      // max sector

    if (tsk_verbose)
        tsk_fprintf(stderr, "mac_load_table: Sector: %" PRIuDADDR "\n",
            taddr);

    /* The table can be variable length, so we loop on it 
     * The idx variable shows which round it is
     * Each structure is 512-bytes each
     */

    max_part = 1;               /* set it to 1 and it will be set in the first loop */
    for (idx = 0; idx < max_part; idx++) {
        uint32_t part_start;
        uint32_t part_size;
        char *str;
        ssize_t cnt;


        /* Read the entry */
        cnt = tsk_mm_read_block_nobuf
            (mm, (char *) &part, sizeof(part), MAC_PART_SOFFSET + idx);

        /* If -1, then tsk_errno is already set */
        if (cnt != sizeof(part)) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_MM_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "MAC Partition entry %" PRIuDADDR, taddr + idx);
            return 1;
        }


        /* Sanity Check */
        if (idx == 0) {
            /* Set the endian ordering the first time around */
            if (tsk_mm_guessu16(mm, part.magic, MAC_MAGIC)) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_MM_MAGIC;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "Mac partition table entry (Sector: %"
                    PRIuDADDR ") %" PRIx16,
                    (taddr + idx), tsk_getu16(mm->endian, part.magic));
                return 1;
            }

            /* Get the number of partitions */
            max_part = tsk_getu32(mm->endian, part.pmap_size);
        }
        else if (tsk_getu16(mm->endian, part.magic) != MAC_MAGIC) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_MM_MAGIC;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "Mac partition table entry (Sector: %"
                PRIuDADDR ") %" PRIx16, (taddr + idx),
                tsk_getu16(mm->endian, part.magic));
            return 1;
        }


        part_start = tsk_getu32(mm->endian, part.start_sec);
        part_size = tsk_getu32(mm->endian, part.size_sec);

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "mac_load: %" PRIu32 "  Starting Sector: %" PRIu32
                "  Size: %" PRIu32 " Type: %s\n", idx, part_start,
                part_size, part.type);

        if (part_size == 0)
            continue;

        if (part_start > max_addr) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_MM_BLK_NUM;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "mac_load_table: Starting sector too large for image");
            return 1;
        }


        if ((str = talloc_size(NULL, sizeof(part.name))) == NULL)
            return 1;

        strncpy(str, (char *) part.type, sizeof(part.name));

        if (NULL == tsk_mm_part_add(mm, (TSK_DADDR_T) part_start,
                (TSK_DADDR_T) part_size, TSK_MM_PART_TYPE_VOL, str, -1, idx)) {
            talloc_free(str);
            return 1;
        }
        talloc_free(str);
    }

    /* Add an entry for the table length */
    if ((table_str = talloc_size(NULL, 16)) == NULL)
        return 1;

    snprintf(table_str, 16, "Table");
    if (NULL == tsk_mm_part_add(mm, taddr, max_part, TSK_MM_PART_TYPE_DESC,
            table_str, -1, -1)) {
        talloc_free(table_str);
        return 1;
    }
    talloc_free(table_str);

    return 0;
}


/* 
 * Walk the partitions that have already been loaded during _open
 *
 * return 0 on success and 1 on error
 */
uint8_t
mac_part_walk(TSK_MM_INFO * mm, TSK_PNUM_T start, TSK_PNUM_T last, int flags,
    TSK_MM_PART_WALK_CB action, void *ptr)
{
    TSK_MM_PART *part;
    unsigned int cnt = 0;

    if (start < mm->first_part || start > mm->last_part) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "mac_part_walk: Start partition: %" PRIuPNUM "", start);
        return 1;
    }

    if (last < mm->first_part || last > mm->last_part) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "mac_part_walk: Ending partition: %" PRIuPNUM "", last);
        return 1;
    }

    part = mm->part_list;
    while ((part != NULL) && (cnt <= last)) {

        if (cnt >= start) {
            int retval = action(mm, cnt, part, 0, ptr);
            if (retval == TSK_WALK_STOP)
                return 0;
            else if (retval == TSK_WALK_ERROR)
                return 1;
        }

        part = part->next;
        cnt++;
    }

    return 0;
}


void
mac_close(TSK_MM_INFO * mm)
{
    talloc_free(mm);
}

/* 
 * Process img_info as a Mac disk.  Initialize mm_info or return
 * NULL on error
 * */
TSK_MM_INFO *
tsk_mm_mac_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset)
{
    TSK_MM_INFO *mm;

    // clean up any errors that are lying around
    tsk_error_reset();

    mm = talloc(NULL, TSK_MM_INFO);
    if (mm == NULL)
        return NULL;

    mm->img_info = img_info;
    mm->mmtype = TSK_MM_INFO_TYPE_MAC;
    mm->str_type = "MAC Partition Map";

    /* If an offset was given, then use that too */
    mm->offset = offset;

    //mm->sect_offset = offset + MAC_PART_OFFSET;

    /* inititialize settings */
    mm->part_list = NULL;
    mm->first_part = mm->last_part = 0;
    mm->endian = 0;
    mm->dev_bsize = 512;
    mm->block_size = 512;

    /* Assign functions */
    mm->part_walk = mac_part_walk;
    mm->close = mac_close;

    /* Load the partitions into the sorted list */
    if (mac_load_table(mm)) {
        mac_close(mm);
        return NULL;
    }

    /* fill in the sorted list with the 'unknown' values */
    if (tsk_mm_part_unused(mm)) {
        mac_close(mm);
        return NULL;
    }

    return mm;
}
