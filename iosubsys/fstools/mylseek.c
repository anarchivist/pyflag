/*++
* NAME
*	mylseek 3
* SUMMARY
*	seek beyond the 32-bit barrier
* SYNOPSIS
*	#include "fs_tools.h"
*
*	OFF_T mylseek(int fd, OFF_T offset, int whence)
* DESCRIPTION
*	mylseek() jumps whatever hoops are needed to seek files
*	with larger than 32-bit offsets.
* LICENSE
	This software is distributed under the IBM Public License.
* AUTHOR(S)
*Wietse Venema
*IBM T.J. Watson Research
*	P.O. Box 704
*	Yorktown Heights, NY 10598, USA
--*/

#include "fs_tools.h"
#ifdef USE_MYLSEEK
#ifdef HAVE_LLSEEK
#include <errno.h>
#include <syscall.h>

/* Needed for some Linux distros - Fedora Core 2 */
#if defined(LINUX2)
#include <linux/unistd.h>
#endif

 /*
  * This is LINUX, live on the bleeding edge and watch your software break
  * with the next release...
  */

static  _syscall5(int, _llseek, unsigned int, fd, unsigned long, offset_high,
		          unsigned long, offset_low, OFF_T *, result,
		          unsigned int, origin)
/* mylseek - seek beyond the 32-bit barrier */

OFF_T   mylseek(int fd, OFF_T offset, int whence)
{
    OFF_T   result;
    int     ret;

    ret = _llseek(fd, (unsigned long) (offset >> 32),
		  (unsigned long) (offset & 0xffffffff),
		  &result, whence);
    return (ret < 0 ? -1 : result);
}

#endif
#endif
