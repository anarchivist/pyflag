/*++
 * NAME
 *	error 3h
 * SUMMARY
 *	diagnostics handlers
 * SYNOPSIS
 *	#include <error.h>
 * DESCRIPTION
 * .nf
 */

 /*
  * External interface.
  */
extern void remark(char *,...);
extern void error(char *,...);
extern void panic(char *,...);
extern char *progname;
extern int verbose;

#ifdef MISSING_STRERROR

extern const char *strerror(int);

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
*--*/
