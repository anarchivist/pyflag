/*
 * The Sleuth Kit 
 *
 * $Date: 2007/12/19 19:57:57 $
 *
 * Brian Carrier [carrier@sleuthkit.org]
 * Copyright (c) 2006-2007 Brian Carrier, Basis Technology.  All rights reserved.
 */
 
/** \file mymalloc.c
 * These functions allocate and realocate memory and set the error handling functions
 * when an error occurs.
 */ 
 
/*++
* NAME
*	tsk_malloc 3
* SUMMARY
*	memory management wrappers
* SYNOPSIS
*	#include <tsk_malloc.h>
*
*	char	*tsk_malloc(len)
*	int	len;
*
*	char	*tsk_realloc(ptr, len)
*	char	*ptr;
*	int	len;
*
*	char	*mystrdup(str)
*const char *str;
*DESCRIPTION
*	This module performs low-level memory management with error
*	handling. A call of these functions either succeeds or it does
*	not return at all.
*
*	tsk_malloc() allocates the requested amount of memory. The memory
*	is not set to zero.
*
*	tsk_realloc() resizes memory obtained from tsk_malloc() or tsk_realloc()
*	to the requested size. The result pointer value may differ from
*	that given via the \fBptr\fR argument.
*
*	mystrdup() returns a dynamic-memory copy of its null-terminated
*	argument. This routine uses tsk_malloc().
* SEE ALSO
*	error(3) error reporting module.
* DIAGNOSTICS
*	Fatal errors: the requested amount of memory is not available.
* LICENSE
* .ad
* .fi
*	The IBM Public Licence must be distributed with this software.
* AUTHOR(S)
*	Wietse Venema
*	IBM T.J. Watson Research
*	P.O. Box 704
*	Yorktown Heights, NY 10598, USA
*--*/

#include "tsk_base_i.h"
#include <errno.h>

#define SK_TALLOC_HACK 1

#ifdef SK_TALLOC_HACK
#include "talloc.h"
void *global_talloc_context=NULL;
#endif

/* tsk_malloc - allocate memory and set error values on error
 */
char *
tsk_malloc(size_t len)
{
    char *ptr;

#ifdef SK_TALLOC_HACK
    if ((ptr = (char *) talloc_zero_size(global_talloc_context, len)) == 0) {
#else
    if ((ptr = (char *) malloc(len)) == 0) {
#endif
        tsk_error_reset();
        tsk_errno = TSK_ERR_AUX_MALLOC;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "tsk_malloc: %s",
            strerror(errno));
    }
    return (ptr);
}

/* tsk_realloc - reallocate memory and set error values if needed */
char *
tsk_realloc(char *ptr, size_t len)
{
#ifdef SK_TALLOC_HACK
    if ((ptr = (char *) talloc_realloc_size(global_talloc_context, ptr, len)) == 0) {
#else
    if ((ptr = (char *) realloc(ptr, len)) == 0) {
#endif
        tsk_error_reset();
        tsk_errno = TSK_ERR_AUX_MALLOC;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "tsk_realloc: %s",
            strerror(errno));
    }
    return (ptr);
}
