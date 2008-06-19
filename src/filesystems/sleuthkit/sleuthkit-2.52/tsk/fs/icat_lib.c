/*
** icat_lib 
** The Sleuth Kit 
**
** $Date: 2007/12/20 20:32:38 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
** 
** Copyright (c) 1997,1998,1999, International Business Machines          
** Corporation and others. All Rights Reserved.

 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/
 
/**
 * \file icat_lib.c
 * Contains the library API functions used by the icat command
 * line tool.
 */

#include "tsk_fs_i.h"



/* Call back action for file_walk
 */
static TSK_WALK_RET_ENUM
icat_action(TSK_FS_INFO * fs, TSK_DADDR_T addr, char *buf,
    size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    if (size == 0)
        return TSK_WALK_CONT;

    if (fwrite(buf, size, 1, stdout) != 1) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WRITE;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "icat_action: error writing to stdout: %s", strerror(errno));
        return TSK_WALK_ERROR;
    }

    return TSK_WALK_CONT;
}

/* Return 1 on error and 0 on success */
uint8_t
tsk_fs_icat(TSK_FS_INFO * fs, uint8_t lclflags, TSK_INUM_T inum, uint32_t type,
    uint16_t id, int flags)
{
    TSK_FS_INODE *inode;

#ifdef TSK_WIN32
    if (-1 == _setmode(_fileno(stdout), _O_BINARY)) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WRITE;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "icat_lib: error setting stdout to binary: %s",
            strerror(errno));
        return 1;
    }
#endif

    inode = fs->inode_lookup(fs, inum);
    if (!inode) {
        return 1;
    }

    if (fs->file_walk(fs, inode, type, id, flags, icat_action, NULL)) {
        tsk_fs_inode_free(inode);
        return 1;
    }

    tsk_fs_inode_free(inode);

    return 0;
}
