#include "fs_tools_i.h"
#include "hfs.h"

uint8_t
hfs_jopen(TSK_FS_INFO * fs, INUM_T inum)
{
    tsk_fprintf(stderr, "jopen not implemented for HFS yet");

    return 0;
}

uint8_t
hfs_jentry_walk(TSK_FS_INFO * fs, int flags, TSK_FS_JENTRY_WALK_CB action,
    void *ptr)
{
    tsk_fprintf(stderr, "jentry_walk not implemented for HFS yet");

    return 0;
}

uint8_t
hfs_jblk_walk(TSK_FS_INFO * fs, DADDR_T start, DADDR_T end, int flags,
    TSK_FS_JBLK_WALK_CB action, void *ptr)
{

    tsk_fprintf(stderr, "jblk_walk not implemented for HFS yet");

    return 0;
}
