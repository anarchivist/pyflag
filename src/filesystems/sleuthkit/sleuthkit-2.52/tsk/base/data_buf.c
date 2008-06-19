/*
 * The Sleuth Kit 
 *
 * $Date: 2007/12/19 19:57:56 $
 */
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

#include "tsk_base_i.h"

/**
 * \file data_buf.c
 * Contains functions to allocate and maintain the tsk_data_buf structures.
 * these structures store a buffer and an address from where they came. 
 */


/**
 * Allocate and initialize a tsk_data_buf structure.
 *
 * @param size Size in bytes to allocated for the buffer
 *
 * @return NULL on error
 */
TSK_DATA_BUF *
tsk_data_buf_alloc(size_t size)
{
    TSK_DATA_BUF *buf;

    if ((buf = (TSK_DATA_BUF *) tsk_malloc(sizeof(*buf))) == NULL)
        return NULL;

    if ((buf->data = tsk_malloc(size)) == NULL) {
        free(buf);
        return NULL;
    }
    buf->size = size;
    buf->used = 0;
    buf->addr = 0;
    return (buf);
}


/**
 * Free the tsk_data_buf and its buffers.
 *
 * @param  buf The structure to free.
 */
void
tsk_data_buf_free(TSK_DATA_BUF * buf)
{
    free(buf->data);
    free((char *) buf);
}
