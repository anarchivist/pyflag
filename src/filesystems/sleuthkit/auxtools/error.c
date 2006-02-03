/*++
* NAME
*	error 3
* SUMMARY
*	diagnostics handlers
* SYNOPSIS
*	#include <error.h>
*
*	void	error(format, ...)
*	char	*format;
*
*	void	remark(format, ...)
*	char	*format;
*
*	void	panic(format, ...)
*	char	*format;
*
*	char	*progname;
*	int	verbose;
* DESCRIPTION
*	This module reports diagnostics. Each routine produces a one-line
*	record with the program name and a caller-provided informative
*	message. In the format string, %m is replaced by the text that
*	corresponds to the present \fBerrno\fR value.
*
*	error() writes a message to the standard error stream and
*	terminates the process with a non-zero exit status.
*
*	remark() writes a message to the standard error stream.
*
*	panic() writes a message to the standard error stream and
*	forces a core dump.
*
*	progname is a global variable that the application should
*	assign the program name. The initial value is a pointer to
*	the string \fB"unknown"\fR.
*
*	verbose is a global variable (initially, zero), that exists
*	solely for the convenience of the application. Typical usage
*	is like:
*
* .ti +5
*	if (verbose) remark(...);
* SEE ALSO
*	errno(2) error numbers
* HISTORY
*	error() and remark() appear in "Software Tools" by B.W. Kernighan
*	and P.J. Plaugher.
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

/* System library. */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifdef __STDC__
#include <stdarg.h>
#define VARARGS(func,type,arg) func(type arg, ...)
#define VASTART(ap,type,name)  va_start(ap,name)
#define VAEND(ap)              va_end(ap)
#else
#include <varargs.h>
#define VARARGS(func,type,arg) func(va_alist) va_dcl
#define VASTART(ap,type,name)  {type name; va_start(ap); name = va_arg(ap, type)
#define VAEND(ap)              va_end(ap);}
#endif

/* Utility library. */

#include "error.h"

char *progname = "unknown";
int verbose = 0;

/* percentm - replace %m by error message associated with value in err */

char *
percentm(char *buf, char *str, int err)
{
    char *ip = str;
    char *op = buf;

    while (*ip) {
	switch (*ip) {
	case '%':
	    switch (ip[1]) {
	    case '\0':		/* don't fall off end */
		*op++ = *ip++;
		break;
	    case 'm':		/* replace %m */
		strcpy(op, strerror(err));
		op += strlen(op);
		ip += 2;
		break;
	    default:		/* leave %<any> alone */
		*op++ = *ip++, *op++ = *ip++;
		break;
	    }
	default:
	    *op++ = *ip++;
	}
    }
    *op = 0;
    return (buf);
}

/* error - print warning on stderr and terminate */

void
VARARGS(error, char *, fmt)
{
    va_list ap;
    int err = errno;
    char buf[BUFSIZ];

    VASTART(ap, char *, fmt);
    fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, percentm(buf, fmt, err), ap);
    fprintf(stderr, "\n");
    VAEND(ap);
    exit(1);
}

/* remark - print warning on stderr and continue */

void
VARARGS(remark, char *, fmt)
{
    va_list ap;
    int err = errno;
    char buf[BUFSIZ];

    VASTART(ap, char *, fmt);
    fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, percentm(buf, fmt, err), ap);
    fprintf(stderr, "\n");
    VAEND(ap);
}


#if 0
/* BC: Nothing uses this and it cases problems on the mac */
/* panic - print warning on stderr and dump core */

void
VARARGS(panic, char *, fmt)
{
    va_list ap;
    int err = errno;
    char buf[BUFSIZ];

    VASTART(ap, char *, fmt);
    fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, percentm(buf, fmt, err), ap);
    fprintf(stderr, "\n");
    VAEND(ap);
    abort();
}

#endif
