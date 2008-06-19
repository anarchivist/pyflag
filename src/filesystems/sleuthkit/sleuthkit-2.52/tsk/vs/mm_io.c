/*
 * The Sleuth Kit
 *
 * $Date: 2007/12/20 16:18:13 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006 Brian Carrier, Basis Technology.  All rights reserved
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

/** \file mm_io.c
 * Contains the wrapper code that allows one to read sectors from a MM_INFO structure.
 * They call the underlying IMG_INFO read functions.
 */
#include <errno.h>
#include "tsk_vs_i.h"


/* mm_read_block - read a block given the address - 
 * calls the read_random at the img layer 
 * Returns the size read or -1 on error */

ssize_t
mm_read_block(TSK_MM_INFO * mm, TSK_DATA_BUF * buf, size_t len,
    TSK_DADDR_T addr)
{
    TSK_OFF_T ofmm;
    ssize_t cnt;

    if (len % mm->dev_bsize) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_READ;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "mm_read_block: length %zu not a multiple of %d",
            len, mm->dev_bsize);
        return -1;
    }


    if (len > buf->size) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_READ;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "mm_read_block: buffer too small - %zu > %Zd",
            len, buf->size);
        return -1;
    }

    buf->addr = addr;
    ofmm = (TSK_OFF_T) addr *mm->block_size;

    cnt =
        mm->img_info->read_random(mm->img_info, mm->offset, buf->data, len,
        ofmm);
    buf->used = cnt;
    return cnt;
}

/* Return number of bytes read or -1 on error */
ssize_t
tsk_mm_read_block_nobuf(TSK_MM_INFO * mm, char *buf, size_t len,
    TSK_DADDR_T addr)
{
    if (len % mm->dev_bsize) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_MM_READ;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "tsk_mm_read_block_nobuf: length %zu"
            " not a multiple of %d", len, mm->dev_bsize);
        return -1;
    }

    return mm->img_info->read_random(mm->img_info, mm->offset, buf, len,
        (TSK_OFF_T) addr * mm->block_size);
}
