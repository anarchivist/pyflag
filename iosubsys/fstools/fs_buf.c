/*++
* NAME
*	fs_buf 3
* SUMMARY
*	file system buffer management routines
* SYNOPSIS
*	#include "fstools.h"
*
*	FS_BUF	*fs_buf_alloc(int size)
*
*	void	fs_buf_free(FS_BUF *buf)
* DESCRIPTION
*	This module implements file sysem buffer management.
*
*	fs_buf_alloc() allocates a buffer with the specified size.
*
*	fs_buf_free() destroys a buffer that was created by fs_buf_alloc().
* DIAGNOSTCS
*	Fatal errors: out of memory. Panic: block size is not a multiple
*	of the device block size.
* LICENSE
*	This software is distributed under the IBM Public License.
* AUTHOR(S)
*	Wietse Venema
*	IBM T.J. Watson Research
*	P.O. Box 704
*	Yorktown Heights, NY 10598, USA
*--*/

#include "fs_tools.h"
#include "mymalloc.h"
#include "error.h"

/* fs_buf_alloc - allocate file system I/O buffer */

FS_BUF *fs_buf_alloc(int size)
{
    //char   *myname = "fs_buf_alloc";
    FS_BUF *buf;

    //if (size % DEV_BSIZE)
	//panic("%s: size %d not multiple of %d", myname, size, DEV_BSIZE);
    buf = (FS_BUF *) mymalloc(sizeof(*buf));
    buf->data = mymalloc(size);
    buf->size = size;
    buf->used = 0;
    buf->addr = -1;
    return (buf);
}

/* fs_buf_free - destroy file system I/O buffer */

void    fs_buf_free(FS_BUF *buf)
{
    free(buf->data);
    free((char *) buf);
}
