/*
** The Sleuth Kit 
**
** $Date: 2008/01/29 22:52:29 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved
*/

/** \file tsk_os.h
 * Contains some OS-specific type settings.
 */

#ifndef _TSK_OS_H
#define _TSK_OS_H

    /*
     * Solaris 2.x. Build for large files when dealing with filesystems > 2GB.
     * With the 32-bit file model, needs pread() to access filesystems > 2GB.
     */
#if defined(sun)
#include <sys/sysmacros.h>
#endif

#ifdef __MINGW32__
#define roundup(x, y)   \
  ( ( ((x)+((y) - 1)) / (y)) * (y) )

#define HAVE_GETHOSTNAME
#include <windows.h>
int gethostname_mingw (char *, size_t);

#define gethostname gethostname_mingw
#define strtok_r(a,b,c) strtok(a,b)
#define fseeko fseek
#define daddr_t int

#endif

#if defined(__CYGWIN__)
#ifndef roundup
#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )
#endif
#endif

#if defined(__INTERNIX)
#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )
#endif


#if !defined(__MINGW32__) && (defined(_WIN32) || defined (__WIN32__))
#define TSK_WIN32

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN     /* somewhat limit Win32 pollution */
#define _CRT_SECURE_NO_DEPRECATE	1

#include <windows.h>
#include <tchar.h>
#include <io.h>
#include "intrin.h"

// define the sized int types
typedef unsigned __int8 uint8_t;
typedef __int8 int8_t;
typedef unsigned __int16 uint16_t;
typedef __int16 int16_t;
typedef unsigned __int32 uint32_t;
typedef __int32 int32_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;

// define the typical unix types
typedef int mode_t;
typedef int ssize_t;

// remap some of the POSIX functions
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


// Non-Win32
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


#endif
