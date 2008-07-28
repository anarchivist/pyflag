/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/20 16:17:59 $
 *
 * Copyright (c) 2006 Brian Carrier, Basis Technology.  All Rights reserved
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
--*/

/**
 * \file fs_inode.c
 * Contains functions to allocate, free, and process the generic inode
 * structures
 */
#include "tsk_fs_i.h"

/**
 * Contains the short (1 character) name of the file type
 */
char tsk_fs_inode_mode_str[TSK_FS_INODE_MODE_TYPE_STR_MAX][2] =
    { "-", "p", "c", "", "d", "", "b", "", "-", "",
    "l", "", "s", "h", "w"
};

/**
 * Allocates a generic inode / metadata structure.
 *
 * @param direct_count Number of direct block address pointers to include in structure
 * @param indir_count Number of indirect block address pointers to include in structure
 * @returns NULL on error
 */
TSK_FS_INODE *
tsk_fs_inode_alloc(int direct_count, int indir_count)
{
    TSK_FS_INODE *fs_inode;

    fs_inode = talloc(NULL, TSK_FS_INODE);
    if (fs_inode == NULL)
        return NULL;
    memset(fs_inode, 0, sizeof(TSK_FS_INODE));
    fs_inode->attr_state = TSK_FS_INODE_ATTR_EMPTY;

    fs_inode->direct_count = direct_count;
    if (direct_count > 0) {
        fs_inode->direct_addr =
            (TSK_DADDR_T *) talloc_size(fs_inode, direct_count * sizeof(TSK_DADDR_T));
        if (fs_inode->direct_addr == NULL)
            return NULL;
        memset(fs_inode->direct_addr, 0, direct_count * sizeof(TSK_DADDR_T));
    }
    else {
        fs_inode->direct_addr = NULL;
    }

    fs_inode->indir_count = indir_count;
    if (indir_count > 0) {
        fs_inode->indir_addr =
            (TSK_DADDR_T *) talloc_size(fs_inode, indir_count * sizeof(TSK_DADDR_T));
        if (fs_inode->indir_addr == NULL)
            return NULL;
        memset(fs_inode->indir_addr, 0, indir_count * sizeof(TSK_DADDR_T));
    }
    else {
        fs_inode->indir_addr = NULL;
    }

    return (fs_inode);
}


/**
 * Resize an existing FS_INODE structure -- changes the number of
 * block pointers. 
 *
 * @param fs_inode Structure to resize
 * @param direct_count Number of direct block address pointers to include in structure
 * @param indir_count Number of indirect block address pointers to include in structure
 * @return NULL on error 
 */
TSK_FS_INODE *
tsk_fs_inode_realloc(TSK_FS_INODE * fs_inode, int direct_count,
    int indir_count)
{
    if (fs_inode->direct_count != direct_count) {
        fs_inode->direct_count = direct_count;
        fs_inode->direct_addr =
            (TSK_DADDR_T *) talloc_realloc_size(fs_inode, (char *) fs_inode->direct_addr,
            direct_count * sizeof(TSK_DADDR_T));
        if (fs_inode->direct_addr == NULL) {
            talloc_free(fs_inode);
            return NULL;
        }
    }
    if (fs_inode->indir_count != indir_count) {
        fs_inode->indir_count = indir_count;
        fs_inode->indir_addr =
            (TSK_DADDR_T *) talloc_realloc_size(fs_inode, (char *) fs_inode->indir_addr,
            indir_count * sizeof(TSK_DADDR_T));
        if (fs_inode->indir_addr == NULL) {
            talloc_free(fs_inode);
            return NULL;
        }
    }
    return (fs_inode);
}


/**
 * Free the memory allocated to the FS_INODE structure.
 *
 * @param fs_inode Structure to free
 */
void
tsk_fs_inode_free(TSK_FS_INODE * fs_inode)
{
	talloc_free(fs_inode);
	return;
}
