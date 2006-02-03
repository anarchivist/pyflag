/*
 * The Sleuth Kit
 *
 * $Date: 2005/06/15 15:58:03 $
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
--*/

#include "fs_tools.h"
#include "fs_data.h"

/* fs_inode_alloc - allocate generic inode structure */

FS_INODE *
fs_inode_alloc(int direct_count, int indir_count)
{
    FS_INODE *fs_inode;

    fs_inode = (FS_INODE *) mymalloc(sizeof(*fs_inode));

    fs_inode->direct_count = direct_count;
    fs_inode->direct_addr =
	(DADDR_T *) mymalloc(direct_count * sizeof(DADDR_T));

    fs_inode->indir_count = indir_count;
    fs_inode->indir_addr =
	(DADDR_T *) mymalloc(indir_count * sizeof(DADDR_T));

    fs_inode->attr = NULL;
    fs_inode->name = NULL;
    fs_inode->link = NULL;
    fs_inode->addr = 0;
    fs_inode->seq = 0;
    fs_inode->atime = fs_inode->mtime = fs_inode->ctime =
	fs_inode->crtime = fs_inode->dtime = 0;

    return (fs_inode);
}

/* fs_inode_realloc - resize generic inode structure */

FS_INODE *
fs_inode_realloc(FS_INODE * fs_inode, int direct_count, int indir_count)
{
    if (fs_inode->direct_count != direct_count) {
	fs_inode->direct_count = direct_count;
	fs_inode->direct_addr =
	    (DADDR_T *) myrealloc((char *) fs_inode->direct_addr,
				  direct_count * sizeof(DADDR_T));
    }
    if (fs_inode->indir_count != indir_count) {
	fs_inode->indir_count = indir_count;
	fs_inode->indir_addr =
	    (DADDR_T *) myrealloc((char *) fs_inode->indir_addr,
				  indir_count * sizeof(DADDR_T));
    }
    return (fs_inode);
}

/* fs_inode_free - destroy generic inode structure */

void
fs_inode_free(FS_INODE * fs_inode)
{
    FS_NAME *fs_name, *fs_name2;

    if (fs_inode->direct_addr)
	free((char *) fs_inode->direct_addr);
    fs_inode->direct_addr = NULL;

    if (fs_inode->indir_addr)
	free((char *) fs_inode->indir_addr);
    fs_inode->indir_addr = NULL;

    if (fs_inode->attr)
	fs_data_free(fs_inode->attr);
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
