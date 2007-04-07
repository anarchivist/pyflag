/*
** dstat
** The Sleuth Kit 
**
** $Date: 2007/04/05 16:01:57 $
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
#include "fs_tools_i.h"

#include "ffs.h"
#include "ext2fs.h"
#include "fatfs.h"


static uint8_t
dstat_act(TSK_FS_INFO * fs, DADDR_T addr, char *buf,
    TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    tsk_printf("%s: %" PRIuDADDR "\n", fs->duname, addr);
    tsk_printf("%sAllocated%s\n",
        (flags & TSK_FS_BLOCK_FLAG_ALLOC) ? "" : "Not ",
        (flags & TSK_FS_BLOCK_FLAG_META) ? " (Meta)" : "");

    if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_FFS_TYPE) {
        FFS_INFO *ffs = (FFS_INFO *) fs;
        tsk_printf("Group: %lu\n", (ULONG) ffs->grp_num);
    }
    else if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_EXT_TYPE) {
        EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
        if (addr >= ext2fs->first_data_block)
            tsk_printf("Group: %lu\n", (ULONG) ext2fs->grp_num);
    }
    else if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_FAT_TYPE) {
        FATFS_INFO *fatfs = (FATFS_INFO *) fs;
        /* Does this have a cluster address? */
        if (addr >= fatfs->firstclustsect) {
            tsk_printf("Cluster: %lu\n",
                (ULONG) (2 +
                    (addr - fatfs->firstclustsect) / fatfs->csize));
        }
    }

    return TSK_WALK_STOP;
}



uint8_t
tsk_fs_dstat(TSK_FS_INFO * fs, uint8_t lclflags, DADDR_T addr,
    TSK_FS_BLOCK_FLAG_ENUM flags)
{
    return fs->block_walk(fs, addr, addr, flags, dstat_act, NULL);
}
