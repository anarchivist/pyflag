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
#  Version: FLAG  $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "stringio.h"
#include "talloc.h"
#include "misc.h"

StringIO StringIO_constructor(StringIO self) {
  //Create a valid buffer to hold the data:
  self->data = talloc(self,char);
  self->size = 0;
  self->readptr=0;
  
  return self;
};

int StringIO_write(StringIO self,char *data, int len) {
  if(self->readptr+len > self->size) {
    self->size = self->readptr + len;
    
    self->data = talloc_realloc_size(self,self->data,self->size+1);
  };
  
  memcpy(self->data+self->readptr,data,len);
  self->readptr+=len;
  
  return len;
};

int StringIO_sprintf(StringIO self, char *fmt, ...) {
  va_list ap;
  char *data;
  int len;
  
  va_start(ap, fmt);
  data = talloc_vasprintf(self, fmt, ap);
  va_end(ap);
  len = strlen(data);
  
  if(self->readptr+len > self->size) {
    self->size = self->readptr + len;    
    self->data = talloc_realloc_size(self,self->data,self->size+1);
  };
  
  memcpy(self->data+self->readptr,data,len);
  self->readptr+=len;
  talloc_free(data);
  return len;
};

int StringIO_read(StringIO self,char *data,int len) {
  if(self->readptr+len > self->size) {
    len = self->size-self->readptr;
  };

  memcpy(data,self->data+self->readptr,len);
  self->readptr+=len;
  return(len);
};

/** Writes into ourselves from a stream */
int StringIO_read_stream(StringIO self, StringIO stream, int length) {
  int len;
  char buff[BUFF_SIZE];

  while(length > 0) {
    len = CALL(stream, read, buff, min(length, BUFF_SIZE));
    if(len==0) break;

    CALL(self, write, buff, len);
    length -= len;
  };

  return length;

  // This is too error prone if we have complex stringio classes.
#if 0  
  stream->get_buffer(stream,&data,&len);

  //Only write whats available:
  if(length>len) length=len;

  self->write(self,data,length);

  //Move the input stream by that many bytes:
  stream->seek(stream,length,SEEK_CUR);

  return length;
#endif
};

/** Write into a stream from ourself */
int StringIO_write_stream(StringIO self, StringIO stream, int length) {
  return stream->read_stream(stream,self,length);
};

uint64_t StringIO_seek(StringIO self, int64_t offset,int whence) {
  switch(whence) {
    // Set the readptr:
  case SEEK_SET:
    self->readptr = offset;
    break;
  case SEEK_CUR:
    self->readptr += offset;
    break;
  case SEEK_END:
    self->readptr = self->size+offset;
    break;
  default:
    DEBUG("unknown whence");
    //    RAISE(E_GENERIC,NULL,"Unknown whence");
  };

  if(self->readptr>self->size) {
    self->data=talloc_realloc_size(self->data,self->data,self->readptr);
    self->size=self->readptr;
  };

  return self->readptr;
};

int StringIO_eof(StringIO self) {
  return (self->readptr==self->size);
};

void StringIO_get_buffer(StringIO self,char **data, int *len) {
  *data = self->data+self->readptr;
  *len = self->size - self->readptr;
};

void StringIO_truncate(StringIO self,int len) {
  if(self->readptr>len) self->readptr=len;
  self->size=len;
  if(self->readptr > self->size) 
    self->readptr=self->size;
};

void StringIO_skip(StringIO self, int len) {
  if(len > self->size) 
    len=self->size;

  memmove(self->data, self->data+len, self->size-len);
  self->size -= len;
  self->readptr=0;
};

/* locate a substring. This returns a pointer inside the data
   buffer... */
char *StringIO_find(StringIO self, char *needle) {
  char *i;
  int needle_size = strlen(needle);

  if(self->size < needle_size)
    return NULL;

  for(i=self->data; i<=self->data + self->size - needle_size; i++) {
    if(memcmp(i, needle, needle_size)==0) {
      return i;
    };
  };

  return NULL;
};

/* case insensitive version of find */
char *StringIO_ifind(StringIO self, char *needle) {
  int i;
  if(self->size < strlen(needle))
    return NULL;
  for(i=0; i<=self->size-strlen(needle); i++) {
    if(strncasecmp(self->data+i, needle, strlen(needle)) == 0)
      return self->data+i;
  }
  return NULL;
};

void StringIO_destroy(StringIO self) {
  //First free our buffer:
  talloc_free(self->data);
  
  //Now free ourselves:
  talloc_free(self);
};

VIRTUAL(StringIO,Object)
  VMETHOD(Con) = StringIO_constructor;
  VMETHOD(write) = StringIO_write;
  VMETHOD(sprintf) = StringIO_sprintf;
  VMETHOD(read) = StringIO_read;
  VMETHOD(read_stream) = StringIO_read_stream;
  VMETHOD(write_stream) = StringIO_write_stream;
  VMETHOD(seek) = StringIO_seek;
  VMETHOD(get_buffer) = StringIO_get_buffer;
  VMETHOD(eof) = StringIO_eof;
  VMETHOD(truncate) = StringIO_truncate;
  VMETHOD(skip) = StringIO_skip;
  VMETHOD(find) = StringIO_find;
  VMETHOD(ifind) = StringIO_ifind;
  VMETHOD(destroy) = StringIO_destroy;

//These are class attributes - all instantiated objects will have
//these set
  VATTR(size) = 0;
  VATTR(readptr) = 0;
END_VIRTUAL


/** This is an implementation of a DiskStringIO class */
DiskStringIO DiskStringIO_OpenFile(DiskStringIO self, char *filename, int mode) {
  self->fd = open(filename, mode);
  
  if(self->fd<0) {
    talloc_free(self);
    return NULL;
  };

  return self;
};

/** Reading always reads from the disk */
int DiskStringIO_read(StringIO self, char *data, int len) {
  DiskStringIO this = (DiskStringIO)self;
  int length_read;

  // If we have stuff in the write buffer we flush it to disk
  if(self->size > 0 ) {
    CALL(this, flush);
  };

  // Where should we be?
  lseek(this->fd, self->readptr, SEEK_SET);

  length_read = read(this->fd, data, len);
  self->readptr += length_read;

  return length_read;
};

uint64_t DiskStringIO_seek(StringIO self, long long int offset, int whence) {
  // This is just a passthrough to the file itself:
  DiskStringIO this = (DiskStringIO)self;

  self->readptr = lseek(this->fd, offset, whence);

  return self->readptr;
};

VIRTUAL(DiskStringIO, StringIO)
     VMETHOD(OpenFile) = DiskStringIO_OpenFile;
     VMETHOD(super.read) = DiskStringIO_read;
     VMETHOD(super.seek) = DiskStringIO_seek;
END_VIRTUAL

/** Create a new file, or if it already exists, open the file for writing.
    Note - caller must close fd when done to ensure no fds are leaked.
*/
static int get_working_fd(CachedWriter this) {
  int fd;

  // Should we just use our old fd?
  if(this->fd>0) return this->fd;

  if(!this->created) {
    /** Check to see if we can create the required file: */
    fd=creat(this->filename, 0777);
    this->created = 1;
  } else {
    fd=open(this->filename, O_APPEND | O_WRONLY);
  };

  return fd;
};

/** An automatic destructor to be called to flush out the stream. */
static int CachedWriter_flush(void *self) {
  CachedWriter this=(CachedWriter)self;
  int fd;

  if(this->super.size==0) return 0;

  fd=get_working_fd(this);
  if(fd>=0) {
    write(fd, this->super.data, this->super.size);
    
    // If we were given an fd - we dont close it:
    if(this->fd < 0)
      close(fd);
  };

  return 0;
};

CachedWriter CachedWriter_Con(CachedWriter self, char *filename) {
  /** Call our base classes constructor */
  self->__super__->Con((StringIO)self);

  if(filename)
    self->filename = talloc_strdup(self, filename);

  /** Ensure that we get flushed out when we get destroyed */
  talloc_set_destructor((void *)self, CachedWriter_flush);

  return self;
};

int CachedWriter_write(StringIO self, char *data, int len) {
  CachedWriter this=(CachedWriter)self;
  int written;

  /** Write the data to our base class */
  written=this->__super__->write(self, data, len);

  /** If we are too large, we flush to disk: */
  if(self->size > MAX_DISK_STREAM_SIZE) {
    int fd=get_working_fd(this);
    
    if(fd==-1) return fd;

    write(fd, self->data, self->size);

    this->written+=self->size;

    if(this->fd<0)
      close(fd);

    self->truncate(self, 0);
  };

  return written; 
};

/** Returns the current offset in the file where the current file
    pointer is. */
int CachedWriter_get_offset(CachedWriter self) {
  return self->super.size + self->written;
};

VIRTUAL(CachedWriter, StringIO)
     VATTR(fd) = -1;

     VMETHOD(Con) = CachedWriter_Con;
     VMETHOD(get_offset) = CachedWriter_get_offset;
     VMETHOD(super.write) = CachedWriter_write;
END_VIRTUAL
