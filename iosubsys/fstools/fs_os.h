/*
** The Sleuth Kit 
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2004 Brian Carrier.  All rights reserved
*/



 /*
  * Solaris 2.x. Build for large files when dealing with filesystems > 2GB.
  * With the 32-bit file model, needs pread() to access filesystems > 2GB.
  */
#if defined(SUNOS5)
#define SUPPORTED

#include <sys/sysmacros.h>

/* Sol 5.7 has inttypes, but sys/inttypes is needed for PRI.. macros */
#include <inttypes.h>		
#include <sys/inttypes.h>

#define LSEEK		lseek
#define OFF_T		off_t
#define ROOTINO		UFSROOTINO
#define STRTOUL		strtoul
#define DADDR_T		daddr_t
#define INO_TO_CG	itog
#define DEF_FSTYPE	"solaris"

#define u_int8_t	uint8_t
#define u_int16_t	uint16_t
#define u_int32_t	uint32_t
#define u_int64_t	uint64_t

#endif

 /*
  * SunOS 4.x cannot handle filesystems > 2GB.
  */

/* @@@ Should this be removed? - and from makedefs?
#if defined(SUNOS4)
#define SUPPORTED
#define LSEEK		lseek
#define OFF_T		off_t
#define STRTOUL		strtol
#define DADDR_T		daddr_t
#define DEF_FSTYPE	"solaris"
#define INO_TO_CG	itog

extern char *optarg;
extern int optind;

#define u_int8_t	uint8_t
#define u_int16_t	uint16_t
#define u_int32_t	uint32_t
#define u_int64_t	uint64_t

#endif
*/

 /*
  * FreeBSD can handle filesystems > 2GB.
  */
#if defined(FREEBSD2) || defined(FREEBSD3) || defined(FREEBSD4) || defined(FREEBSD5)
#define SUPPORTED

/* FreeBSD 5 has inttypes and support for the printf macros */
#if defined(FREEBSD4) || defined(FREEBSD5)
#include <inttypes.h>
#endif

#define LSEEK		lseek
#define OFF_T		off_t
#define STRTOUL		strtoul
#define DADDR_T		daddr_t
#define DEF_FSTYPE	"freebsd"
#define INO_TO_CG	ino_to_cg
#endif /* FREEBSD */

 /*
  * BSD/OS can handle filesystems > 2GB.
  */
#if defined(BSDI2) || defined(BSDI3) || defined(BSDI4)
#define SUPPORTED

#include <inttypes.h>

#define LSEEK		lseek
#define OFF_T		off_t
#define STRTOUL		strtoul
#define DADDR_T		daddr_t
#define DEF_FSTYPE	"bsdi"
#define INO_TO_CG	ino_to_cg
#endif /* BSDI */

/*
 * NetBSD
 */
#if defined(NETBSD16)
#define SUPPORTED

#include <inttypes.h>

#define LSEEK		lseek
#define OFF_T		off_t
#define STRTOUL		strtoul
#define DADDR_T		daddr_t
#define DEF_FSTYPE	"netbsd"
#define INO_TO_CG	ino_to_cg
#endif /* NETBSD */


 /*
  * OpenBSD looks like BSD/OS 3.x.
  */
#if defined(OPENBSD2) || defined (OPENBSD3)
#define SUPPORTED

#include <inttypes.h>

#define LSEEK		lseek
#define OFF_T		off_t
#define STRTOUL		strtoul
#define DADDR_T		daddr_t
#define DEF_FSTYPE	"openbsd"
#define INO_TO_CG	ino_to_cg
#endif

#if defined(DARWIN)
#define SUPPORTED

#include <inttypes.h>

#define LSEEK		lseek
#define OFF_T		off_t
#define STRTOUL		strtoul
#define DADDR_T		daddr_t
#define DEF_FSTYPE	"darwin-hfs"
#define INO_TO_CG	ino_to_cg
#endif /* DARWIN */


 /*
  * Linux 2.whatever. We'll see how stable the interfaces are.
  */
#if defined(LINUX2) 
#define SUPPORTED

#include <linux/types.h>
#include <inttypes.h>

#define USE_MYLSEEK
#define HAVE_LLSEEK
#define LSEEK		mylseek
#define OFF_T		off_t
#define STRTOUL		strtoul
#define DADDR_T		daddr_t
#define DEF_FSTYPE		"linux-ext2"
#endif /* LINUX */

#if defined(CYGWIN)
#define SUPPORTED

#include <inttypes.h>

#define LSEEK		lseek
#define OFF_T		off_t
#define STRTOUL		strtoul
#define DADDR_T		daddr_t
#define DEF_FSTYPE	"freebsd"
#define INO_TO_CG	ino_to_cg

#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )

#endif /* CYGWIN */

#if defined(__INTERNIX)
#define SUPPORTED

#include <inttypes.h>

#define LSEEK		lseek
#define OFF_T		off_t
#define STRTOUL		strtoul
#define DADDR_T		long 
#define DEF_FSTYPE	"freebsd"
#define INO_TO_CG	ino_to_cg

#define roundup(x, y)	\
	( ( ((x)+((y) - 1)) / (y)) * (y) )

#endif /* INTERNIX*/





/* printf macros - if the OS doesnot have inttypes.h yet */


#ifndef PRIx64
#define PRIx64 "llx"
#endif

#ifndef PRIX64
#define PRIX64 "llX"
#endif

#ifndef PRIu64
#define PRIu64 "llu"
#endif



#ifndef PRIx32
#define PRIx32 "x"
#endif

#ifndef PRIX32
#define PRIX32 "X"
#endif

#ifndef PRIu32
#define PRIu32 "u"
#endif



#ifndef PRIx16
#define PRIx16 "hx"
#endif

#ifndef PRIX16
#define PRIX16 "hX"
#endif

#ifndef PRIu16
#define PRIu16 "hu"
#endif



 /*
  * Catch-all.
  */
#ifndef SUPPORTED
#error "This operating system is not supported"
#endif

