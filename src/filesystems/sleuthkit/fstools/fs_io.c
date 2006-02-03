/*
 * The Sleuth Kit
 *
 * $Date: 2005/08/13 05:27:45 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 * 
 * Copyright (c) 1997,1998,1999, International Business Machines          
 * Corporation and others. All Rights Reserved.
 *
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
--*/

#include <errno.h>
#include "fs_tools.h"


/* fs_read_block - read a block given the address - calls the read_random at the img layer */

OFF_T
fs_read_block(FS_INFO * fs, DATA_BUF * buf, OFF_T len, DADDR_T addr)
{
    OFF_T offs, cnt;

    if (len % fs->dev_bsize) {
	if (verbose)
	    fprintf(stderr,
		    "fs_read_block: Block read request with length (%"
		    PRIuOFF ") not a multiple of %d", len, fs->dev_bsize);
	errno = EIO;
	return 0;
    }


    if (len > buf->size) {
	if (verbose)
	    fprintf(stderr,
		    "fs_read_block: Buffer length is too short for read (%"
		    PRIuOFF " > %u)", len, (int) buf->size);

	errno = EIO;
	return 0;
    }

    if (addr > fs->last_block) {
	if (verbose)
	    fprintf(stderr,
		    "fs_read_block: File system block address is too large for image %"
		    PRIuDADDR ")", addr);
	errno = EFAULT;
	return 0;
    }

    buf->addr = addr;
    offs = (OFF_T) addr *fs->block_size;

    cnt = fs->img_info->read_random(fs->img_info, buf->data, len, offs);
    buf->used = cnt;
    return cnt;
}

OFF_T
fs_read_block_nobuf(FS_INFO * fs, char *buf, OFF_T len, DADDR_T addr)
{
    if (len % fs->dev_bsize) {
	if (verbose)
	    fprintf(stderr,
		    "fs_read_block_nobuf: Block read request with length (%"
		    PRIuOFF ") not a multiple of %d", len, fs->dev_bsize);
	errno = EIO;
	return 0;
    }

    if (addr > fs->last_block) {
	if (verbose)
	    fprintf(stderr,
		    "fs_read_block_nobuf: File system block address is too large for image %"
		    PRIuDADDR ")", addr);
	errno = EFAULT;
	return 0;
    }

    return fs->img_info->read_random(fs->img_info, buf, len,
				     (OFF_T) addr * fs->block_size);
}
