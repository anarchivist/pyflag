/*
** The Sleuth Kit 
**
** $Date: 2007/06/13 21:17:01 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved
*/

#ifndef _TSK_OS_H
#define _TSK_OS_H

    /*
     * Solaris 2.x. Build for large files when dealing with filesystems > 2GB.
     * With the 32-bit file model, needs pread() to access filesystems > 2GB.
     */
#if defined(SUNOS5)
#define SUPPORTED
#define USE_LIBAFF
#define	USE_LIBEWF
#define HAVE_UNISTD

#include <sys/sysmacros.h>

/* Sol 5.7 has inttypes, but sys/inttypes is needed for PRI.. macros */
#include <inttypes.h>
#include <sys/inttypes.h>
#endif


    /*
     * FreeBSD can handle filesystems > 2GB.
     */
#if defined(FREEBSD2) || defined(FREEBSD3) || defined(FREEBSD4) || defined(FREEBSD5)
#define SUPPORTED
#define USE_LIBAFF
#define	USE_LIBEWF
#define HAVE_UNISTD

/* FreeBSD 5 has inttypes and support for the printf macros */
#if defined(FREEBSD4) || defined(FREEBSD5)
#include <inttypes.h>
#endif

#endif                          /* FREEBSD */

    /*
     * BSD/OS can handle filesystems > 2GB.
     */
#if defined(BSDI2) || defined(BSDI3) || defined(BSDI4)
#define SUPPORTED
#define USE_LIBAFF
#define	USE_LIBEWF
#define HAVE_UNISTD

#include <inttypes.h>
#endif                          /* BSDI */


/*
 * NetBSD
 */
#if defined(NETBSD16)
#define SUPPORTED
#define USE_LIBAFF
#define	USE_LIBEWF
#define HAVE_UNISTD

#include <inttypes.h>
#endif                          /* NETBSD */


    /*
     * OpenBSD looks like BSD/OS 3.x.
     */
#if defined(OPENBSD2) || defined (OPENBSD3)
#define SUPPORTED
#define USE_LIBAFF
#define	USE_LIBEWF
#define HAVE_UNISTD

#include <inttypes.h>
#endif



#if defined(DARWIN)
#define SUPPORTED
#define USE_LIBAFF
#define	USE_LIBEWF
#define HAVE_UNISTD

#include <inttypes.h>
#endif                          /* DARWIN */


    /*
     * Linux 2.whatever. 
     */
#if defined(LINUX2)
#define SUPPORTED
//#define USE_LIBAFF
//#define	USE_LIBEWF
#define HAVE_UNISTD

#include <inttypes.h>
#endif                          /* LINUX */



#if defined(CYGWIN)
#define SUPPORTED
#define USE_LIBAFF
#define	USE_LIBEWF
#define HAVE_UNISTD

#include <inttypes.h>

#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )

#endif                          /* CYGWIN */


#if defined(__INTERNIX)
#define SUPPORTED
#include <inttypes.h>
#define HAVE_UNISTD

#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )

#endif                          /* INTERNIX */

#if defined(_WIN32) || defined (__WIN32__)
#define SUPPORTED
#define TSK_WIN32
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN     /* somewhat limit Win32 pollution */

#include <windows.h>
#include <tchar.h>
#include <io.h>

#define _CRT_SECURE_NO_DEPRECATE	1

#include "intrin.h"

typedef unsigned __int8 uint8_t;
typedef __int8 int8_t;
typedef unsigned __int16 uint16_t;
typedef __int16 int16_t;
typedef unsigned __int32 uint32_t;
typedef __int32 int32_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
typedef int mode_t;
typedef uint16_t gid_t;
typedef uint16_t uid_t;

#define strtoull	strtoul
#define snprintf   _snprintf
#define strcasecmp(string1, string2)	_strnicmp(string1, string2, strlen(string1))

#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )

#endif


/* When TSK deals with the outside world (printing / input), the data will 
 * be in either UTF-16 or UTF-8 (Windows or Unix).  TSK_TCHAR is defined 
 * as the data type needed and the following function map to the required 
 * function. 
 */

#ifdef TSK_WIN32

/* TSK_TCHAR is a wide 2-byte character */
typedef TCHAR TSK_TCHAR;
#define _TSK_T	_T

#define TSTAT _tstat
#define STAT_STR    _stat64i32
#define TSTRTOK	_tcstok
#define TSTRLEN	_tcslen
#define TSTRCMP	_tcscmp
#define TSTRNCPY _tcsncpy
#define TSTRNCAT _tcsncat
#define TSTRCHR	_tcschr
#define TSTRTOUL _tcstoul
#define TSTRTOULL _tcstoui64
#define TATOI	_tstoi
#define TFPRINTF fwprintf
#define TSNPRINTF _snwprintf
#define PUTENV	_wputenv
#define TZSET	_tzset

#define PRIcTSK _TSK_T("S")     ///< printf macro to print a char string to TSK_TCHAR
#define PRIwTSK _TSK_T("s")     ///< printf macro to print a wide char string to TSK_TCHAR

#define PRIttocTSK  "S"         ///< printf macro to print a TSK_TCHAR string to stderr or other char device

#define unlink _unlink
#define MAIN _tmain
#define fseeko _fseeki64

#define strtok_r(a,b,c) strtok(a,b)

#else

/* TSK_TCHAR is a 1-byte character */
typedef char TSK_TCHAR;
#define _TSK_T(x)	x

#define TSTAT	stat
#define STAT_STR    stat
#define TSTRTOK	strtok
#define TSTRLEN	strlen
#define TSTRCMP	strcmp
#define TSTRNCPY strncpy
#define TSTRNCAT strncat
#define TSTRCHR	strchr
#define TSTRTOUL strtoul
#define TSTRTOULL strtoull
#define TATOI	atoi
#define TFPRINTF fprintf
#define TSNPRINTF snprintf

#define PUTENV	putenv
#define TZSET	tzset

#define PRIcTSK _TSK_T("s")     ///< printf macro to print a char string to TSK_TCHAR
#define PRIwTSK _TSK_T("S")     ///< printf macro to print a wide char string to TSK_TCHAR

#define PRIttocTSK  "s"         ///< printf macro to print a TSK_TCHAR string to stderr or other char device

#define MAIN main

#endif

    /*
     * Catch-all.
     */
#ifndef SUPPORTED
#error "This operating system is not supported"
#endif

#endif
