/******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Version: 0.85 Date: Fri Dec 28 16:12:30 EST 2007$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************/
#ifndef __MISC_H
#define __MISC_H

#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
//#include <unistd.h>
#include "enum.h"

#define O_BINARY 0

/** This is used for debugging. */
#ifndef __DEBUG__
#define DEBUG(x, ...)
#else
#define DEBUG(x, ...) do {				\
    printf("%s:%u ",__FUNCTION__,__LINE__);		\
    printf(x, ## __VA_ARGS__);				\
  } while(0)

#endif

/** Modules may register initialisation functions using this macro.

    The build system will ensure that these functions are called at
    boot time.

    Note that function_name is global with all modules, and should be
    in the format modulename_functionname to prevent clashes.
**/
#define MODULE_INIT(function_name)		\
void __MODULE_INIT_ ## function_name()

#define False 0
#define True 1

/** This is used when we need to copy the NULL as well */
#define ZSTRING_CMP(a, str) memcmp(a, str, strlen(str)+1)
#define ZSTRING_NO_NULL_CMP(a, str) memcmp(a, str, strlen(str))
#define ZSTRING_CPY(a, str) memcpy(a, str, strlen(str)+1)
#define ZSTRING_NO_NULL_CPY(a, str) memcpy(a, str, strlen(str))

/** Dont use these with memcpy and memcmp because they break under
    FEDORA (see bug00032). Use the above instead.
*/
#define ZSTRING(str) str , (strlen(str)+1)

#define ZSTRING_NO_NULL(str) str , (strlen(str))

char *format_alloc(int x, ...);
#define q(...) format_alloc(1, __VA_ARGS__, 0)

#undef min
#define min(X, Y)  ((X) < (Y) ? (X) : (Y))
#undef max
#define max(X, Y)  ((X) > (Y) ? (X) : (Y))

// A size for various buffers around the place.
#define BUFF_SIZE 10240

#define LE 1

/** This is used to remind callers that a parameter is an out
    variable 
*/
#define OUT

#endif
