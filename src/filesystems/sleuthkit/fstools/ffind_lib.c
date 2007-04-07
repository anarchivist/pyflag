/*
** ffind  (file find)
** The Sleuth Kit 
**
** $Date: 2007/04/05 16:01:56 $
**
** Find the file that uses the specified inode (including deleted files)
** 
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/
#include "fs_tools_i.h"

/* NTFS has an optimized version of this function */
extern uint8_t
ntfs_find_file(TSK_FS_INFO *, INUM_T, uint32_t,
    uint16_t, int, TSK_FS_DENT_TYPE_WALK_CB, void *ptr);


static INUM_T inode = 0;
static uint8_t localflags = 0;
static uint8_t found = 0;

static uint8_t
find_file_act(TSK_FS_INFO * fs, TSK_FS_DENT * fs_dent, void *ptr)
{
    /* We found it! */
    if (fs_dent->inode == inode) {
        found = 1;
        if (fs_dent->flags & TSK_FS_DENT_FLAG_UNALLOC)
            tsk_printf("* ");

        tsk_printf("/%s%s\n", fs_dent->path, fs_dent->name);

        if (!(localflags & TSK_FS_FFIND_ALL)) {
            return TSK_WALK_STOP;
        }
    }
    return TSK_WALK_CONT;
}


/* Return 0 on success and 1 on error */
uint8_t
tsk_fs_ffind(TSK_FS_INFO * fs, uint8_t lclflags, INUM_T inode_a,
    uint32_t type, uint16_t id, int flags)
{
    found = 0;
    localflags = lclflags;
    inode = inode_a;

    /* Since we start the walk on the root inode, then this will not show
     ** up in the above functions, so do it now
     */
    if (inode == fs->root_inum) {
        if (flags & TSK_FS_DENT_FLAG_ALLOC) {
            tsk_printf("/\n");
            found = 1;

            if (!(lclflags & TSK_FS_FFIND_ALL))
                return 0;
        }
    }

    if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
        TSK_FS_INFO_TYPE_NTFS_TYPE) {
        if (ntfs_find_file(fs, inode, type, id, flags, find_file_act,
                NULL))
            return 1;
    }
    else {
        if (fs->dent_walk(fs, fs->root_inum, flags, find_file_act, NULL))
            return 1;
    }

    if (found == 0) {

        /* With FAT, we can at least give the name of the file and call
         * it orphan 
         */
        if ((fs->ftype & TSK_FS_INFO_TYPE_FS_MASK) ==
            TSK_FS_INFO_TYPE_FAT_TYPE) {
            TSK_FS_INODE *fs_inode = fs->inode_lookup(fs, inode);
            if ((fs_inode != NULL) && (fs_inode->name != NULL)) {
                if (fs_inode->flags & TSK_FS_DENT_FLAG_UNALLOC)
                    tsk_printf("* ");
                tsk_printf("%s/%s\n", TSK_FS_ORPHAN_STR,
                    fs_inode->name->name);
            }
            if (fs_inode)
                tsk_fs_inode_free(fs_inode);
        }
        else {
            tsk_printf("File name not found for inode\n");
        }
    }
    return 0;
}
