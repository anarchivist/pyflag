#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include "iosubsys.h"
#include <stdarg.h>
#include "except.h"
#include <string.h>
#include "hooker.h"
//#include <fcntl.h>

#define O_RDONLY 0

static char *iosubsys=NULL;
enum context_t context=HOOKED;

#define IOSNUM 256

//These store the different IO sources which will be opened.
static IO_INFO *iosources[IOSNUM];
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
    RAISE(E_GENERIC,NULL,dlerror());
  };

  //Actually hook all our functions
  HOOK(open);
  HOOK(open64);
  HOOK(lseek);
  HOOK(lseek64);
  HOOK(read);
  HOOK(write);
  HOOK(exit);
  HOOK(dup2);
  HOOK(close);
  HOOK(fopen);
  HOOK(fclose);
  HOOK(fread);

  //Remove the LD_PRELOAD now that we are already hooked. This is needed if something else needs to fork later:
    unsetenv("LD_PRELOAD");
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
  CHECK_INIT;

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
  int mode=0;
  va_start(ap,flags);
  mode = (int)*ap;
  va_end(ap);

  return open64(pathname,flags,mode);
};


int llseek(unsigned int fd,  unsigned  long  offset_high,  unsigned  long  offset_low, 
	   loff_t *result, unsigned int whence) {
  debug(1,"Called llseek\n");
  return 0;
};

off_t lseek(int fildes, unsigned long int offset, int whence) {
  debug(1,"Called lseek with %lu\n",offset);
  CHECK_INIT;

  if(context==UNHOOKED || !iosubsys || !iosources[fildes]) {
    return dispatch->lseek(fildes,offset ,whence);
  } else {
    iosources[fildes]->fpos = offset;
    return offset;
  };
};

off_t lseek64(int fildes,  off_t  offset, int whence) {
  debug(1,"Called lseek64 with %llu, %u\n",offset,whence);
  CHECK_INIT;

  if(context==UNHOOKED || !iosubsys || !iosources[fildes]) {
    return dispatch->lseek64(fildes,offset ,whence);
  } else {
    iosources[fildes]->fpos = offset;
    return offset;
  };
};

ssize_t read(int fd, void *buf, size_t count) {
  //If we were not initialised yet, we do so now...
  CHECK_INIT;

  if(context == UNHOOKED || !iosubsys || !iosources[fd]) {
    debug(1, "reading without hooking");
    return dispatch->read(fd,buf,count);
  } else {
    int read_len;

    debug(1,"read %lu from %lu at %p\n",count,fd,iosources[fd]);

    context = UNHOOKED;
    read_len = iosources[fd]->read_random
      (iosources[fd], buf, count, iosources[fd]->fpos, "nothing");

    if(read_len>0) iosources[fd]->fpos+=read_len;
    context = HOOKED;
    
    debug(1,"Returned %lu bytes of data\n",read_len);
    return(read_len);
  };
};

ssize_t write(int fd, const void *buf, size_t count) {
  CHECK_INIT;
  
  //If the fd is actually an iosource, we pretend to write to it, but do not.
  if(iosources[fd] && context==HOOKED) {
    debug(1,"not writing %s",buf);
    //Pretend to have written...
    return (count);
  };
  
  //Otherwise, this is a read fd, and we do write to it:
  return dispatch->write(fd,buf,count);
};

//Hook exit to prevent stupid programs from exiting suddenly when an
//error occurs. This is mostly used for dbtool which is written using
//sk. When sk has an abnormal condition, it just dies which stops
//dbtool. This way we raise an exception allowing dbtool to catch it
//and keep going.

void exit(int status) {
  CHECK_INIT;

  if(context == HOOKED && status!=0) {
    context = UNHOOKED;
    RAISE(E_GENERIC,NULL,"exit() called with status %d",status);
    context = HOOKED;
  };
  dispatch->exit(status);
  _exit(0);
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
  CHECK_INIT;

  debug(1,"Called close with %u\n",fd);
  if(iosources[fd] && context==HOOKED) {
    iosources[fd]=NULL;
    return 0;
  } else if(context==HOOKED) {
    debug(1,"Closing fd %u\n",fd);
    return(dispatch->close(fd));
  } else return 0;
};

FILE *fopen(const char *path, const char *mode) {
  char *file_prefix = getenv("IO_FILENAME");

  CHECK_INIT;

  if( context == HOOKED && !memcmp(path,file_prefix,strlen(file_prefix))) {
    if(mode[0]=='r') {
      return ((FILE *)open(path,O_RDONLY));
    };
    RAISE(E_GENERIC,NULL,"Writing is not supported to %s",path);
  };

  return(dispatch->fopen(path,mode));
};

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
  //Stream is actually a hooked io subsys
  if((unsigned int)stream<256) {
    return read((int)stream,ptr,size*nmemb);
  };
  return dispatch->fread(ptr,size,nmemb,stream);
};

int getc(FILE *stream) {
  unsigned char temp;
  int len;

  CHECK_INIT;

  len=fread(&temp,1,1,stream);
  if(len>0)
    return((int)temp);
  else
    return(EOF);
};

int fgetc(FILE *stream) {
  return getc(stream);
};

int fclose(FILE *stream) {
  CHECK_INIT;

  //Thats an iosource:
  if((unsigned int)stream<256) {
    iosources[(unsigned int)stream]=NULL;
    return 0;
  };
  return dispatch->fclose(stream);
};

int stat(const char *file_name, struct stat *buf) {
  CHECK_INIT;
  buf->st_size=-1;
  return(0);
};

int lstat64(const char *file_name, struct stat *buf) {
  CHECK_INIT;
  buf->st_size=-1;
  return(0);
};

int __xstat64 (int __ver, __const char *__filename, struct stat *buf) {
  CHECK_INIT;
  buf->st_size=-1;
  return(0);
};

int fileno(FILE *stream) {
  CHECK_INIT;
	return((int)stream);
};
