/*
** dstat
** The Sleuth Kit 
**
** $Date: 2006/11/29 22:02:08 $
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
dstat_act(FS_INFO * fs, DADDR_T addr, char *buf, int flags, void *ptr)
{
    switch (fs->ftype & FSMASK) {
    case EXTxFS_TYPE:
	tsk_printf("Block: %" PRIuDADDR "\n", addr);
	break;
    case FFS_TYPE:
	tsk_printf("Fragment: %" PRIuDADDR "\n", addr);
	break;
    case FATFS_TYPE:
	tsk_printf("Sector: %" PRIuDADDR "\n", addr);
	break;
    case NTFS_TYPE:
	tsk_printf("Cluster: %" PRIuDADDR "\n", addr);
	break;
    case ISO9660_TYPE:
	tsk_printf("Block: %" PRIuDADDR "\n", addr);
	break;
    default:
	tsk_error_reset();
	tsk_errno = TSK_ERR_FS_ARG;
	snprintf(tsk_errstr, TSK_ERRSTR_L,
	    "dstat_act: Unsupported File System\n");
	return WALK_ERROR;
    }

    tsk_printf("%sAllocated%s\n",
	(flags & FS_FLAG_DATA_ALLOC) ? "" : "Not ",
	(flags & FS_FLAG_DATA_META) ? " (Meta)" : "");

    if ((fs->ftype & FSMASK) == FFS_TYPE) {
	FFS_INFO *ffs = (FFS_INFO *) fs;
	tsk_printf("Group: %lu\n", (ULONG) ffs->grp_num);
    }
    else if ((fs->ftype & FSMASK) == EXTxFS_TYPE) {
	EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
	if (addr >= ext2fs->first_data_block)
	    tsk_printf("Group: %lu\n", (ULONG) ext2fs->grp_num);
    }
    else if ((fs->ftype & FSMASK) == FATFS_TYPE) {
	FATFS_INFO *fatfs = (FATFS_INFO *) fs;
	/* Does this have a cluster address? */
	if (addr >= fatfs->firstclustsect) {
	    tsk_printf("Cluster: %lu\n",
		(ULONG) (2 +
		    (addr - fatfs->firstclustsect) / fatfs->csize));
	}
    }

    return WALK_STOP;
}



uint8_t
fs_dstat(FS_INFO * fs, uint8_t lclflags, DADDR_T addr, int flags)
{
    return fs->block_walk(fs, addr, addr, flags, dstat_act,
	(void *) "dstat");
}
