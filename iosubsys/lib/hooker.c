#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include "iosubsys.h"
#include <stdarg.h>
#include "except.h"
#include <string.h>

//We call hard exit when hooking exit()
extern void _exit(int);

#define DEBUG_LEVEL 5

/* Used for Debugging messages*/
void debug(int level, const char *message, ...)
{
	va_list ap;
	
	if(DEBUG_LEVEL>level) {
	  va_start(ap, message);
	  vfprintf(stderr,message, ap);
	  fflush(stderr);
	  va_end(ap);
	};
};

struct dispatcher_t {
  //Handle for libc
  void *handle;
  //original hooked functions:
  int (*open)(const char *pathname, int flags,int mode);
  int (*open64)(const char *pathname, int flags,int mode);
  off_t (*lseek)(int fildes, off_t offset, int whence);
  off_t (*lseek64)(int fildes, off_t offset, int whence);
  ssize_t (*read)(int fd, void *buf, size_t count);
  void (*exit)(int status);
  int (*dup2)(int oldfd, int newfd);
  int (*close)(int fd);
} *dispatch=NULL;

#define HOOK(x)   dispatch->x = dlsym(dispatch->handle,#x); check_errors();


// This static variable is used to decide when we should hook calls
// through the library. The library itself will be using the same
// calls we are trying to hook (i.e. open,read seek etc). When running
// within the context of the library, we do not want to hook those
// calls, just use the original so functions. Hence we set the context
// to UNHOOKED just before we service the call, and return it to
// HOOKED just after. Note that this is _not_ thread safe - so we will
// have problems running programs with threads!!!!
enum context_t {
  HOOKED, UNHOOKED
};

static char *iosubsys=NULL;

static enum context_t context=HOOKED;

//These store the different IO sources which will be opened.
static IO_INFO *iosources[255];
static int iosource_count=10;

void check_errors() {
  char *error;
  if((error=dlerror())!=NULL) {
    fprintf(stderr,"%s\n",error);
    exit(EXIT_FAILURE);
  };
};

// Load the library and initialise the static dispatcher
void load_library(void) {
  debug(1,"Loading library now for hooking\n");

  //Zero out our iosource array:
  memset(iosources,0,sizeof(iosources));

  dispatch=(struct dispatcher_t *)malloc(sizeof(*dispatch));
  dispatch->handle=dlopen("libc.so.6",RTLD_NOW);
  if(!dispatch->handle) {
    fputs(dlerror(),stderr);
    exit(EXIT_FAILURE);
  };

  //Actually hook all our functions
  HOOK(open);
  HOOK(open64);
  HOOK(lseek);
  HOOK(lseek64);
  HOOK(read);
  HOOK(exit);
  HOOK(dup2);
  HOOK(close);
};

//This function initialises the hooker
void init_hooker() {
  char *io_name;
  char *options=getenv("IO_OPTS");

  //First load the libraries:
  load_library();

  //Now intialise the IO Subsystem from environment variables:
  io_name = getenv("IO_SUBSYS");
  iosubsys = io_name;

  if(io_name) {
    iosource_count++;
    //    sleep(10);

    context=UNHOOKED;
    iosources[iosource_count] = io_open(io_name);
    //Parse options for this io subsystem:
    if(options)
      io_parse_options(iosources[iosource_count],options);
    context=HOOKED;
  };

};

/* These are wrappers for all the functions we will be hooking.
 */
int open64(const char *pathname, int flags,int mode) {
  //We only hook files which start with this prefix. If the system
  //wants to open other files, thats ok.
  char *file_prefix = getenv("IO_FILENAME");

  //If we were not initialised yet, we do so now...
  debug(1,"asked to open %s",pathname);  

  //If we were not initialised yet, we do so now...
  if(!dispatch) {
    init_hooker();
  };

  debug(1,"opening64 %s",file_prefix);

  if(context == UNHOOKED || !iosubsys || 
     (file_prefix && memcmp(pathname,file_prefix,strlen(file_prefix)))) {
    debug(1, "Opened %s without hooking",pathname);
    return (dispatch->open64(pathname,flags,mode));
  } else {
    // Turn off hooking. NOTE: This makes us non-reentrant!!!
    context = UNHOOKED;
    debug(1,"Will hook open64\n");
    iosources[iosource_count]->open(iosources[iosource_count]);
    //Turn hooking back on:
    context = HOOKED;
    //Return the iosource number as a file handle (we will hopefully
    //get that back on subsequent read calls):
    return(iosource_count);
  }
};

int open(const char *pathname, int flags, ...) {
  va_list ap;
  int mode;
  va_start(ap,flags);
  mode = (int)*ap;
  va_end(ap);

  return open64(pathname,flags,mode);
};


int llseek(unsigned int fd,  unsigned  long  offset_high,  unsigned  long  offset_low, loff_t *result, unsigned int whence) {
  debug(1,"Called llseek\n");
  return 0;
};

off_t lseek(int fildes, unsigned long int offset, int whence) {
  debug(1,"Called lseek with %lu\n",offset);
  //If we were not initialised yet, we do so now...
  if(!dispatch) {
    init_hooker();
  };

  if(context==UNHOOKED || !iosubsys || !iosources[fildes]) {
    return dispatch->lseek(fildes,offset ,whence);
  } else {
    iosources[fildes]->fpos = offset;
    return offset;
  };
};

off_t lseek64(int fildes,  off_t  offset, int whence) {
  debug(1,"Called lseek64 with %llu, %u\n",offset,whence);
  //If we were not initialised yet, we do so now...
  if(!dispatch) {
    init_hooker();
  };

  if(context==UNHOOKED || !iosubsys || !iosources[fildes]) {
    return dispatch->lseek64(fildes,offset ,whence);
  } else {
    iosources[fildes]->fpos = offset;
    return offset;
  };
};

ssize_t read(int fd, void *buf, size_t count) {
    //If we were not initialised yet, we do so now...
  if(!dispatch) {
    init_hooker();
  };

  if(context == UNHOOKED || !iosubsys || !iosources[fd]) {
    debug(1, "reading without hooking");
    return dispatch->read(fd,buf,count);
  } else {
    int read_len;

    debug(1,"read %lu from %lu at %llu\n",count,fd,iosources[fd]);

    context = UNHOOKED;
    read_len = iosources[fd]->read_random
      (iosources[fd], buf, count, iosources[fd]->fpos, "nothing");

    if(read_len>0) iosources[fd]->fpos+=read_len;
    context = HOOKED;

    return(read_len);
  };
};

ssize_t write(int fd, const void *buf, size_t count) {
  debug(1,"not writing %s",buf);
  //Pretend to have written...
  return (count);
};

//Hook exit to prevent stupid programs from exiting suddenly when an
//error occurs. This is mostly used for dbtool which is written using
//sk. When sk has an abnormal condition, it just dies which stops
//dbtool. This way we raise an exception allowing dbtool to catch it
//and keep going.
void exit(int status) {
  if(context == HOOKED && status!=0) {
    context = UNHOOKED;
    RAISE(E_GENERIC,NULL,"exit() called with status %d",status);
    context = HOOKED;
  };

  _exit(status);
};

int dup2(int oldfd, int newfd)
{
  //If the oldfd is an iosource, we make the new one an io source:
  if(iosources[oldfd]) {
    //Is the new one already assigned?
    if(iosources[newfd]) return -1;
    iosources[newfd]=iosources[oldfd];
    return 0;
  };
  
  return(dispatch->dup2(oldfd,newfd));
};

int close(int fd) {

  if(iosources[fd]) {
    iosources[fd]=NULL;
    return 0;
  } else {
    debug(1,"Closing fd %u\n",fd);
    return(dispatch->close(fd));
  }
};
