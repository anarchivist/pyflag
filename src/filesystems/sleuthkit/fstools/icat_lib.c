/*
** icat_lib 
** The Sleuth Kit 
**
** $Date: 2005/06/13 19:27:17 $
**
** Brian Carrier [carrier@sleuthkit.org]
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

#include "fs_tools.h"



/* Call back action for file_walk
 */
static uint8_t
icat_action(FS_INFO * fs, DADDR_T addr, char *buf,
	    unsigned int size, int flags, void *ptr)
{
    if (size == 0)
	return WALK_CONT;

    if (fwrite(buf, size, 1, stdout) != 1)
	error("icat_action: write: %m");

    return WALK_CONT;
}

uint8_t
fs_icat(FS_INFO * fs, uint8_t lclflags, INUM_T inum, uint32_t type,
	uint16_t id, int flags)
{
    FS_INODE *inode;

    inode = fs->inode_lookup(fs, inum);
    if (!inode)
	error("error getting inode");

    fs->file_walk(fs, inode, type, id, flags, icat_action, NULL);

    fs_inode_free(inode);

    return 0;
}
