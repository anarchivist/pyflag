/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/20 16:18:14 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2003-2007 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file mm_part.c
 * Contins the functions need to create and maintain the linked list of
 * partitions in a volume.
 */
#include "tsk_vs_i.h"


/* Add a partition to a sorted list 
 *
 * the structure is returned or NULL on error
 */
TSK_MM_PART *
tsk_mm_part_add(TSK_MM_INFO * mm, TSK_DADDR_T start, TSK_DADDR_T len,
    TSK_MM_PART_TYPE_ENUM type, char *desc, int8_t table, int8_t slot)
{
    TSK_MM_PART *part;
    TSK_MM_PART *cur_part = mm->part_list;

    if ((part = talloc(mm, TSK_MM_PART)) == NULL) {
        return NULL;
    }

    /* set the values */
    part->next = NULL;
    part->prev = NULL;
    part->start = start;
    part->len = len;
    part->desc = talloc_strdup(part, desc);
    part->table_num = table;
    part->slot_num = slot;
    part->type = type;

    /* is this the first entry in the list */
    if (mm->part_list == NULL) {
        mm->part_list = part;
        mm->first_part = 0;
        mm->last_part = 0;

        return part;
    }

    /* Cycle through to find the correct place to put it into */
    while (cur_part) {

        /* The one to add starts before this partition */
        if (cur_part->start > part->start) {
            part->next = cur_part;
            part->prev = cur_part->prev;
            if (part->prev)
                part->prev->next = part;
            cur_part->prev = part;

            /* If the current one was the head, set this to the head */
            if (cur_part == mm->part_list)
                mm->part_list = part;

            mm->last_part++;
            break;
        }

        /* the one to add is bigger then current and the list is done */
        else if (cur_part->next == NULL) {
            cur_part->next = part;
            part->prev = cur_part;

            mm->last_part++;
            break;
        }

        /* The one to add fits in between this and the next */
        else if (cur_part->next->start > part->start) {
            part->prev = cur_part;
            part->next = cur_part->next;
            cur_part->next->prev = part;
            cur_part->next = part;

            mm->last_part++;
            break;
        }

        cur_part = cur_part->next;
    }

    return part;
}

/* 
 * cycle through the sorted list and add unallocated entries
 * to the unallocated areas of disk
 *
 * Return 1 on error and 0 on success
 */
uint8_t
tsk_mm_part_unused(TSK_MM_INFO * mm)
{
    TSK_MM_PART *part = mm->part_list;
    TSK_DADDR_T prev_end = 0;

    /* prev_ent is set to where the previous entry stopped  plus 1 */
    while (part) {

        if (part->start > prev_end) {
            char *str;
            if ((str = talloc_size(NULL, 12)) == NULL)
                return 1;

            snprintf(str, 12, "Unallocated");
            if (NULL == tsk_mm_part_add(mm, prev_end,
                    part->start - prev_end, TSK_MM_PART_TYPE_DESC, str, -1,
                    -1)) {
                talloc_free(str);
                return 1;
            }
            talloc_free(str);
        }

        prev_end = part->start + part->len;
        part = part->next;
    }

    /* Is there unallocated space at the end? */
    if (prev_end < (TSK_DADDR_T)(mm->img_info->size / mm->block_size)) {
        char *str;
        if ((str = talloc_size(NULL, 12)) == NULL)
            return 1;

        snprintf(str, 12, "Unallocated");
        if (NULL == tsk_mm_part_add(mm, prev_end,
                mm->img_info->size / mm->block_size - prev_end,
                TSK_MM_PART_TYPE_DESC, str, -1, -1)) {
            talloc_free(str);
            return 1;
        }
        talloc_free(str);
    }

    return 0;
}

/* 
 * free the buffer with the description 
 */
void
tsk_mm_part_free(TSK_MM_INFO * mm)
{
    TSK_MM_PART *part = mm->part_list;
    TSK_MM_PART *part2;

    while (part) {
        if (part->desc)
            talloc_free(part->desc);

        part2 = part->next;
        talloc_free(part);
        part = part2;
    }
    mm->part_list = NULL;

    return;
}
