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

 /*
  * External interface.
  */
extern char *mymalloc(int);
extern char *myrealloc(char *, int);
extern char *mystrdup(const char *);

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
