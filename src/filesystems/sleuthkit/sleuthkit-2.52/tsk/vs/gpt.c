/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/20 21:24:23 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2004-2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file gpt.c
 * The functions required to process the GPT GUID Partiition Table.
 */
#include "tsk_vs_i.h"
#include "tsk_gpt.h"
#include "tsk_dos.h"


/* 
 * Process the partition table at the sector address 
 * 
 * It is loaded into the internal sorted list 
 */
static uint8_t
gpt_load_table(TSK_MM_INFO * mm)
{
    gpt_head head;
    gpt_entry *ent;
    dos_sect dos_part;
    unsigned int i, a;
    uint32_t ent_size;
    char *safe_str, *head_str, *tab_str, *ent_buf;
    ssize_t cnt;
    TSK_DADDR_T taddr = mm->offset / mm->block_size + GPT_PART_SOFFSET;
    TSK_DADDR_T max_addr = (mm->img_info->size - mm->offset) / mm->block_size;      // max sector

    if (tsk_verbose)
        tsk_fprintf(stderr, "gpt_load_table: Sector: %" PRIuDADDR "\n",
            taddr);

    cnt = tsk_mm_read_block_nobuf
        (mm, (char *) &dos_part, sizeof(dos_part), GPT_PART_SOFFSET);
    /* if -1, then tsk_errno is already set */
    if (cnt != sizeof(dos_part)) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_MM_READ;
        }
        snprintf(tsk_errstr2, TSK_ERRSTR_L,
            "Error reading DOS safety partition table in Sector: %"
            PRIuDADDR, taddr);
        return 1;
    }

    /* Sanity Check */
    if (tsk_mm_guessu16(mm, dos_part.magic, DOS_MAGIC)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Missing DOS safety partition (invalid magic) (Sector: %"
            PRIuDADDR ")", taddr);
        return 1;
    }

    if (dos_part.ptable[0].ptype != GPT_DOS_TYPE) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Missing DOS safety partition (invalid type in table: %d)",
            dos_part.ptable[0].ptype);
        return 1;
    }

    if ((safe_str = tsk_malloc(16)) == NULL)
        return 1;

    snprintf(safe_str, 16, "Safety Table");
    if (NULL == tsk_mm_part_add(mm, (TSK_DADDR_T) 0, (TSK_DADDR_T) 1,
            TSK_MM_PART_TYPE_DESC, safe_str, -1, -1))
        return 1;


    /* Read the GPT header */
    cnt = tsk_mm_read_block_nobuf
        (mm, (char *) &head, sizeof(head), GPT_PART_SOFFSET + 1);
    if (cnt != sizeof(head)) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_MM_READ;
        }
        snprintf(tsk_errstr2, TSK_ERRSTR_L,
            "GPT Header structure in Sector: %" PRIuDADDR, taddr + 1);
        return 1;
    }


    if (tsk_getu64(mm->endian, &head.signature) != GPT_HEAD_SIG) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "GPT Header: %" PRIx64, tsk_getu64(mm->endian,
                &head.signature));
        return 1;
    }

    if ((head_str = tsk_malloc(16)) == NULL)
        return 1;

    snprintf(head_str, 16, "GPT Header");
    if (NULL == tsk_mm_part_add(mm, (TSK_DADDR_T) 1,
            (TSK_DADDR_T) ((tsk_getu32(mm->endian,
                        &head.head_size_b) + 511) / 512),
            TSK_MM_PART_TYPE_DESC, head_str, -1, -1))
        return 1;

    /* Allocate a buffer for each table entry */
    ent_size = tsk_getu32(mm->endian, &head.tab_size_b);
    if (ent_size < sizeof(gpt_entry)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Header reports partition entry size of %" PRIu32
            " and not %zu", ent_size, sizeof(gpt_entry));
        return 1;
    }

    if ((tab_str = tsk_malloc(20)) == NULL)
        return 1;

    snprintf(tab_str, 20, "Partition Table");
    if (NULL == tsk_mm_part_add(mm, (TSK_DADDR_T) tsk_getu64(mm->endian,
                &head.tab_start_lba),
            (TSK_DADDR_T) ((ent_size * tsk_getu32(mm->endian,
                        &head.tab_num_ent) + 511) / 512),
            TSK_MM_PART_TYPE_DESC, tab_str, -1, -1))
        return 1;


    /* Process the partition table */
    if ((ent_buf = tsk_malloc(mm->block_size)) == NULL)
        return 1;

    i = 0;
    for (a = 0; i < tsk_getu32(mm->endian, &head.tab_num_ent); a++) {
        char *name;

        /* Read a sector */
        cnt = tsk_mm_read_block_nobuf(mm, ent_buf, mm->block_size,
            tsk_getu64(mm->endian, &head.tab_start_lba) + a);
        if (cnt != mm->block_size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_MM_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "Error reading GPT partition table sector : %"
                PRIuDADDR, tsk_getu64(mm->endian,
                    &head.tab_start_lba) + a);
            return 1;
        }

        /* Process the sector */
        ent = (gpt_entry *) ent_buf;
        for (; (uintptr_t) ent < (uintptr_t) ent_buf + mm->block_size && 
            i < tsk_getu32(mm->endian, &head.tab_num_ent); i++) {

            UTF16 *name16;
            UTF8 *name8;
            int retVal;

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "gpt_load: %d  Starting Sector: %" PRIu64
                    "  End: %" PRIu64 " Flag: %" PRIx64 "\n", i,
                    tsk_getu64(mm->endian, ent->start_lba),
                    tsk_getu64(mm->endian, ent->end_lba),
                    tsk_getu64(mm->endian, ent->flags));


            if (tsk_getu64(mm->endian, ent->start_lba) == 0) {
                ent++;
                continue;
            }

            if (tsk_getu64(mm->endian, ent->start_lba) > max_addr) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_MM_BLK_NUM;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "gpt_load_table: Starting sector too large for image");
                return 1;
            }


            if ((name = tsk_malloc(256)) == NULL)
                return 1;

            name16 = (UTF16 *) ((uintptr_t) ent->name);
            name8 = (UTF8 *) name;

            retVal =
                tsk_UTF16toUTF8(mm->endian, (const UTF16 **) &name16,
                (UTF16 *) ((uintptr_t) name16 + sizeof(ent->name)),
                &name8,
                (UTF8 *) ((uintptr_t) name8 + 256), TSKlenientConversion);

            if (retVal != TSKconversionOK) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "gpt_load_table: Error converting name to UTF8: %d\n",
                        retVal);
                *name = '\0';
            }

            if (NULL == tsk_mm_part_add(mm,
                    (TSK_DADDR_T) tsk_getu64(mm->endian, ent->start_lba),
                    (TSK_DADDR_T) (tsk_getu64(mm->endian,
                            ent->end_lba) - tsk_getu64(mm->endian,
                            ent->start_lba) + 1), TSK_MM_PART_TYPE_VOL,
                    name, -1, i))
                return 1;

            ent++;
        }
    }

    return 0;
}


/* 
 * Walk the partitions that have already been loaded during _open
 *
 * Return 1 on error and 0 on success
 */
uint8_t
gpt_part_walk(TSK_MM_INFO * mm, TSK_PNUM_T start, TSK_PNUM_T last, int flags,
    TSK_MM_PART_WALK_CB action, void *ptr)
{
    TSK_MM_PART *part;
    unsigned int cnt = 0;

    if (start < mm->first_part || start > mm->last_part) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Starting partition: %" PRIuPNUM "", start);
        return 1;
    }

    if (last < mm->first_part || last > mm->last_part) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "Ending partition: %" PRIuPNUM "", last);
        return 1;
    }

    part = mm->part_list;
    while ((part != NULL) && (cnt <= last)) {

        if (cnt >= start) {
            int retval;
            retval = action(mm, cnt, part, 0, ptr);
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
gpt_close(TSK_MM_INFO * mm)
{
    tsk_mm_part_free(mm);
    free(mm);
}

TSK_MM_INFO *
tsk_mm_gpt_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset)
{
    TSK_MM_INFO *mm;

    // clean up any errors that are lying around
    tsk_error_reset();

    mm = (TSK_MM_INFO *) tsk_malloc(sizeof(*mm));
    if (mm == NULL)
        return NULL;

    mm->img_info = img_info;
    mm->mmtype = TSK_MM_INFO_TYPE_GPT;
    mm->str_type = "GUID Partition Table";

    /* If an offset was given, then use that too */
    mm->offset = offset;

    /* inititialize settings */
    mm->part_list = NULL;
    mm->first_part = mm->last_part = 0;
    mm->endian = 0;
    mm->dev_bsize = 512;
    mm->block_size = 512;

    /* Assign functions */
    mm->part_walk = gpt_part_walk;
    mm->close = gpt_close;

    /* Load the partitions into the sorted list */
    if (gpt_load_table(mm)) {
        gpt_close(mm);
        return NULL;
    }

    /* fill in the sorted list with the 'unknown' values */
    if (tsk_mm_part_unused(mm)) {
        gpt_close(mm);
        return NULL;
    }

    return mm;
}
