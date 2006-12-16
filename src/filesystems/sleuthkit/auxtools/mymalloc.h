/*++
* NAME
*	mymalloc 3h
* SUMMARY
*	memory management wrappers
* SYNOPSIS
*	#include "mymalloc.h"
* DESCRIPTION
* .nf
*/

#ifndef _MYMALLOC_H
#define _MYMALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "talloc.h"

    /*
     * External interface.
     */
  void *global_talloc_context;
  #define free talloc_free

  // Force sk to use mymalloc everywhere instead of malloc
  #define malloc mymalloc

    extern char *mymalloc(size_t);
    extern char *myrealloc(char *, size_t);
    extern char *mystrdup(const char *);

#ifdef __cplusplus
}
#endif
#endif
/* LICENSE
* .ad
* .fi
*	The IBM Public License must be distributed with this software.
* AUTHOR(S)
*	Wietse Venema
*	IBM T.J. Watson Research
*	P.O. Box 704
*	Yorktown Heights, NY 10598, USA
--*/
