#ifndef __MISC_H
#define __MISC_H

#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

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

char *format_alloc(int x, ...);

#define q(...) format_alloc(1, __VA_ARGS__, 0)

#undef min
#define min(X, Y)  ((X) < (Y) ? (X) : (Y))

#define BUFF_SIZE 1024

#define LE 1

/** This is used to remind callers that a parameter is an out
    variable 
*/
#define OUT

#endif
