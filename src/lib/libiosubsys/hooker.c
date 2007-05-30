/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
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
# ******************************************************
*/
#include "config.h"
#include "hooker.h"
#include "libiosubsys.h"
#include "except.h"

#undef O_RDONLY
#define O_RDONLY 0

static char *iosubsys=NULL;
enum context_t context=HOOKED;

#define IOSNUM 256

//These store the different IO sources which will be opened.
static IOSource iosources[IOSNUM];
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

  //This is used for debugging with gdb - attach during this sleep
  //sleep(10);

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
  HOOK(fopen64);
  HOOK(fseek);
  HOOK(fdopen);
  HOOK(fclose);
  HOOK(fread);
  HOOK(ftell);
  HOOK(ftello);
  HOOK(fgets);
  HOOK(__fxstat64);
  HOOK(ferror);
  HOOK(feof);

  //Remove the LD_PRELOAD now that we are already hooked. This is needed if something else needs to fork later:
  unsetenv("LD_PRELOAD");
};

//This function initialises the hooker
void init_hooker() {
  char *io_name;
  IOOptions opts = iosubsys_parse_options((char *)getenv("IO_OPTS"));

  //First load the libraries:
  load_library();

  //Now intialise the IO Subsystem from environment variables:
  io_name = getenv("IO_SUBSYS");
  iosubsys = io_name;

  if(io_name) {
    iosource_count++;

    context=UNHOOKED;
    iosources[iosource_count] = iosubsys_Open(io_name, opts);
    context=HOOKED;
  };
};

/* These are wrappers for all the functions we will be hooking.
 */
int open64(const char *pathname, int flags,int mode) {
  //We only hook files which start with this prefix. If the system
  //wants to open other files, thats ok.
  char *file_prefix = getenv("IO_FILENAME");
  int new_fd;

  //If we were not initialised yet, we do so now...
  debug(1,"asked to open %s",pathname);  

  //If we were not initialised yet, we do so now...
  CHECK_INIT;

  debug(1,"opening64 %s",file_prefix);

  if(context == UNHOOKED || !iosubsys || 
     (file_prefix && memcmp(pathname,file_prefix,strlen(file_prefix)))) {
    debug(1, "Opened %s without hooking",pathname);
    /* This is a strage bug reported by gmjones:

       Glibc's open may return an fd which is already occupied by an
       io source fd. IO Sources use the range of fds larger than
       iosource_count, but it is still possible for an iosource fd to
       be dup2ed into the low range. Since iosource fds are not real,
       and the kernel does not know about them, the kernel may issue
       the same fd as an iosource. We need to prevent that by checking
       to see that there is no iosource already assigned to that
       psuedo fd, and if it is, we repeat the open operation to force
       a new fd to be issued by the kernel.

    */
    do {
      debug(1,"Calling the dispatcher for open64");

      /** This routes open to open64 on 32 bit patforms, and to open
	  of 64 bit platforms. 
      */
#if _FILE_OFFSET_BITS==64
      new_fd = dispatch->open64(pathname,flags,mode);
#else
      new_fd = dispatch->open(pathname,flags,mode);
#endif
      debug(1,"Returned from dispatcher");
    } while(iosources[new_fd]);

    debug(1,"returned unhooked fd=%u",new_fd);
    return new_fd;
  } else {
    // Turn off hooking. NOTE: This makes us non-reentrant!!!
    context = UNHOOKED;
    debug(1,"Will hook open64\n");
    //    iosources[iosource_count]->Open(iosources[iosource_count]);
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

  debug(1,"called open");
  
  CHECK_INIT;

  va_start(ap,flags);
  mode = va_arg(ap, int);
  va_end(ap);

  return open64(pathname,flags,mode);
};


int llseek(unsigned int fildes,  unsigned  long  offset_high,  unsigned  long  offset_low, 
	   loff_t *result, unsigned int whence) {
  unsigned long long int offset=offset_high;

  offset=(offset>>32)+offset_low;

  debug(1,"Called llseek\n");
  CHECK_INIT;
  
  if(context==UNHOOKED || !iosubsys || !iosources[fildes]) {
    return dispatch->lseek(fildes,offset ,whence);
  } else {
    if(whence==SEEK_SET) {
      iosources[fildes]->fpos = offset;
    } else if(whence==SEEK_CUR) {
      iosources[fildes]->fpos += offset;
    };
    printf("Someone called SEEK_END");
  };
  return offset;
};

off_t lseek(int fildes, off_t offset, int whence) {
  debug(1,"Called lseek with %lu\n",offset);
  CHECK_INIT;

  if(context==UNHOOKED || !iosubsys || !iosources[fildes]) {
    return dispatch->lseek(fildes,offset ,whence);
  } else {
    if(whence == SEEK_SET) {
      iosources[fildes]->fpos = offset;
    } else if(whence==SEEK_CUR) {
      iosources[fildes]->fpos += offset;
    };

    if(offset<0) iosources[fildes]->fpos=0;
    return iosources[fildes]->fpos;
  };
};

off_t lseek64(int fildes,  off_t  offset, int whence) {
  debug(1,"Called lseek64 with %llu, %u\n",offset,whence);
  CHECK_INIT;

  if(context==UNHOOKED || !iosubsys || !iosources[fildes]) {
    return dispatch->lseek64(fildes,offset ,whence);
  } else {
    iosources[fildes]->fpos = offset;
    return iosources[fildes]->fpos;
  };
};

int fseek(FILE *stream, long offset, int whence) {
  int fd=(int)stream;

  CHECK_INIT;

  lseek(fd, offset,whence);
  return 0;
};

off_t ftello(FILE *stream) {
  int fd=(int)stream;

  return lseek(fd, 0, SEEK_CUR);
};

long ftell(FILE *stream) {
  int fd=(int)stream;

  return lseek(fd, 0, SEEK_CUR);
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
      (iosources[fd], buf, count, iosources[fd]->fpos);

    if(read_len>0) iosources[fd]->fpos+=read_len;
    context = HOOKED;
    
    debug(1,"Returned %lu bytes of data\n",read_len);
    return(read_len);
  };
};

char *fgets(char *s, int size, FILE *stream) {
  int fd;
  
  fd=(long int)stream;

  CHECK_INIT;
  read(fd, s, size);
  return s;
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
  CHECK_INIT;

  //If the oldfd is an iosource, we make the new one an io source:
  if(iosources[oldfd]) {
    //Is the new one already assigned?
    if(iosources[newfd]) return -1;
    iosources[newfd]=iosources[oldfd];
    return newfd;
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

#ifndef _FILE_OFFSET_BITS
FILE *fopen64(const char *path, const char *mode) {
  FILE *fd;
  CHECK_INIT;

  printf("opening file %s",path);

  fd=fopen(path,mode);
  return fd;
};
#endif

FILE *fopen(const char *path, const char *mode) {
  char *file_prefix = getenv("IO_FILENAME");

  CHECK_INIT;

  if( context == HOOKED && iosubsys) {
    if(mode[0]=='r') {
      return ((FILE *)open64(path,O_RDONLY, 0));
    };
    RAISE(E_GENERIC,NULL,"Writing is not supported to %s",path);
  };

  return(dispatch->fopen(path,mode));
};

FILE *fdopen(int fd, const char *mode) {
  CHECK_INIT;

  //Check if fd is one of ours:
  if( context == HOOKED && iosources[fd]) {
    if(mode[0]=='r') {
      return ((FILE *)fd);
    };
    RAISE(E_GENERIC,NULL,"Writing is not supported to file descriptor %u",fd);
  };

  return(dispatch->fdopen(fd,mode));
};

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
  CHECK_INIT;

  if( context == UNHOOKED || !iosubsys)
    return dispatch->fread(ptr,size,nmemb,stream);

  //Stream is actually a hooked io subsys
  if((unsigned int)stream<256) {
    return read((long int)stream,ptr,size*nmemb)/size;
  };
  return dispatch->fread(ptr,size,nmemb,stream);
};

int getc(FILE *stream) {
  unsigned char temp;
  int len;

  CHECK_INIT;

  len=fread(&temp,1,1,stream);
  if(len>0)
    return((long int)temp);
  else
    return(EOF);
};

int fgetc(FILE *stream) {
  CHECK_INIT;

  return getc(stream);
};

int fclose(FILE *stream) {
  CHECK_INIT;

  //Thats an iosource:
  if((uint32_t)stream<256) {
    iosources[(uint32_t)stream]=NULL;
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


int __fxstat64(int ver, int filedes, struct stat *buf) {
  CHECK_INIT;

  if(iosources[filedes]){
    buf->st_size=-1;
    return(0);
  } else {
    dispatch->__fxstat64(ver, filedes,buf);
    return 0;
  };
};

int fileno(FILE *stream) {
  CHECK_INIT;
	return((long int)stream);
};

int fcntl(int fd, int cmd, ... ) {
  CHECK_INIT;

  return( 0);
};

int ferror(FILE *stream) {
  CHECK_INIT;

  return 0;
};       

/** 
    There currently is no way for us to tell if we are at the end of
    the file, so we just return - no error.
 */
int feof(FILE *stream) {
  return 0;
};

void check_init(struct dispatcher_t * dispatch) {
  if(!dispatch) { init_hooker(); };
}

