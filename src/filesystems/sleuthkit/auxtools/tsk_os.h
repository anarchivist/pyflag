/*
** The Sleuth Kit 
**
** $Date: 2006/06/20 22:35:37 $
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved
*/

#ifndef _TSK_OS_H
#define _TSK_OS_H

#ifdef __cplusplus
extern "C" {
#endif

    /*
     * Solaris 2.x. Build for large files when dealing with filesystems > 2GB.
     * With the 32-bit file model, needs pread() to access filesystems > 2GB.
     */
#if defined(SUNOS5)
#define SUPPORTED
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
#define HAVE_UNISTD

/* FreeBSD 5 has inttypes and support for the printf macros */
#if defined(FREEBSD4) || defined(FREEBSD5)
#include <inttypes.h>
#endif

#endif				/* FREEBSD */

    /*
     * BSD/OS can handle filesystems > 2GB.
     */
#if defined(BSDI2) || defined(BSDI3) || defined(BSDI4)
#define SUPPORTED
#define HAVE_UNISTD

#include <inttypes.h>
#endif				/* BSDI */


/*
 * NetBSD
 */
#if defined(NETBSD16)
#define SUPPORTED
#define HAVE_UNISTD

#include <inttypes.h>
#endif				/* NETBSD */


    /*
     * OpenBSD looks like BSD/OS 3.x.
     */
#if defined(OPENBSD2) || defined (OPENBSD3)
#define SUPPORTED
#define HAVE_UNISTD

#include <inttypes.h>
#endif



#if defined(DARWIN)
#define SUPPORTED
#define HAVE_UNISTD

#include <inttypes.h>
#endif				/* DARWIN */


    /*
     * Linux 2.whatever. 
     */
#if defined(LINUX2)
#define SUPPORTED
#define HAVE_UNISTD

#include <inttypes.h>
#endif				/* LINUX */



#if defined(CYGWIN)
#define SUPPORTED
#define HAVE_UNISTD

#include <inttypes.h>

#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )

#endif				/* CYGWIN */


#if defined(__INTERNIX)
#define SUPPORTED
#include <inttypes.h>
#define HAVE_UNISTD

#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )

#endif				/* INTERNIX */

#if defined(_WIN32) || defined (__WIN32__)
#define SUPPORTED
#define TSK_WIN32
#define WIN32_LEAN_AND_MEAN	/* somewhat limit Win32 pollution */
#include <windows.h>
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
#define open(filename, oflag)	_open(filename, oflag|_O_BINARY, 0)
#define lseek	_lseek
#define read	_read
#define close	_close
#define snprintf   _snprintf
#define strcasecmp(string1, string2)	_strnicmp(string1, string2, sizeof(string1))

#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )

#if !defined(_SYS_INT_TYPES_H)
#if defined (_LP64) || defined (_I32LPx)
    typedef unsigned long uintptr_t;
#else
    typedef unsigned int uintptr_t;
#endif
#endif

#endif
    /*
     * Catch-all.
     */
#ifndef SUPPORTED
#error "This operating system is not supported"
#endif

#ifdef __cplusplus
}
#endif
#endif
