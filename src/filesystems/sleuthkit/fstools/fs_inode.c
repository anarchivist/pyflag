/*
 * The Sleuth Kit
 *
 * $Date: 2007/04/04 22:06:14 $
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
#include "fs_tools_i.h"

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

    fs_inode = (TSK_FS_INODE *) tsk_malloc(sizeof(*fs_inode));
    if (fs_inode == NULL)
        return NULL;

    fs_inode->direct_count = direct_count;
    fs_inode->direct_addr =
        (DADDR_T *) tsk_malloc(direct_count * sizeof(DADDR_T));
    if (fs_inode->direct_addr == NULL)
        return NULL;

    fs_inode->indir_count = indir_count;
    fs_inode->indir_addr =
        (DADDR_T *) tsk_malloc(indir_count * sizeof(DADDR_T));
    if (fs_inode->indir_addr == NULL)
        return NULL;

    fs_inode->attr = NULL;
    fs_inode->name = NULL;
    fs_inode->link = NULL;
    fs_inode->addr = 0;
    fs_inode->seq = 0;
    fs_inode->atime = fs_inode->mtime = fs_inode->ctime =
        fs_inode->crtime = fs_inode->dtime = 0;

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
            (DADDR_T *) tsk_realloc((char *) fs_inode->direct_addr,
            direct_count * sizeof(DADDR_T));
        if (fs_inode->direct_addr == NULL) {
            free(fs_inode->indir_addr);
            free(fs_inode);
            return NULL;
        }
    }
    if (fs_inode->indir_count != indir_count) {
        fs_inode->indir_count = indir_count;
        fs_inode->indir_addr =
            (DADDR_T *) tsk_realloc((char *) fs_inode->indir_addr,
            indir_count * sizeof(DADDR_T));
        if (fs_inode->indir_addr == NULL) {
            free(fs_inode->direct_addr);
            free(fs_inode);
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
    TSK_FS_INODE_NAME_LIST *fs_name, *fs_name2;

    if (!fs_inode)
        return;

    if (fs_inode->direct_addr)
        free((char *) fs_inode->direct_addr);
    fs_inode->direct_addr = NULL;

    if (fs_inode->indir_addr)
        free((char *) fs_inode->indir_addr);
    fs_inode->indir_addr = NULL;

    if (fs_inode->attr)
        tsk_fs_data_free(fs_inode->attr);
    fs_inode->attr = NULL;

    if (fs_inode->link)
        free(fs_inode->link);
    fs_inode->link = NULL;

    fs_name = fs_inode->name;
    while (fs_name) {
        fs_name2 = fs_name->next;
        fs_name->next = NULL;
        free(fs_name);
        fs_name = fs_name2;
    }

    free((char *) fs_inode);
}
