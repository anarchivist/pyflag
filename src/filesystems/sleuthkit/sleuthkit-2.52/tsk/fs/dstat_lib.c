/*
** dstat
** The Sleuth Kit 
**
** $Date: 2007/12/20 20:32:38 $
**
** Get the details about a data unit
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
*/

/**
 * \file dstat_lib.c
 * Contains the library API functions used by the dstat command
 * line tool.
 */
 
#include "tsk_fs_i.h"

#include "tsk_ffs.h"
#include "tsk_ext2fs.h"
#include "tsk_fatfs.h"


static TSK_WALK_RET_ENUM
dstat_act(TSK_FS_INFO * fs, TSK_DADDR_T addr, char *buf,
    TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    tsk_printf("%s: %" PRIuDADDR "\n", fs->duname, addr);
    tsk_printf("%sAllocated%s\n",
        (flags & TSK_FS_BLOCK_FLAG_ALLOC) ? "" : "Not ",
        (flags & TSK_FS_BLOCK_FLAG_META) ? " (Meta)" : "");

    if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_FFS_TYPE) {
        FFS_INFO *ffs = (FFS_INFO *) fs;
        tsk_printf("Group: %"PRI_FFSGRP"\n", ffs->grp_num);
    }
    else if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_EXT_TYPE) {
        EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
        if (addr >= ext2fs->first_data_block)
            tsk_printf("Group: %"PRI_EXT2GRP"\n", ext2fs->grp_num);
    }
    else if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_FAT_TYPE) {
        FATFS_INFO *fatfs = (FATFS_INFO *) fs;
        /* Does this have a cluster address? */
        if (addr >= fatfs->firstclustsect) {
            tsk_printf("Cluster: %"PRIuDADDR"\n",
                (2 +
                    (addr - fatfs->firstclustsect) / fatfs->csize));
        }
    }

    return TSK_WALK_STOP;
}



uint8_t
tsk_fs_dstat(TSK_FS_INFO * fs, uint8_t lclflags, TSK_DADDR_T addr,
    TSK_FS_BLOCK_FLAG_ENUM flags)
{
    return fs->block_walk(fs, addr, addr, flags, dstat_act, NULL);
}
