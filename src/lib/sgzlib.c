/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Tue Jun 10 13:18:41 EST 2008$
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
/*************************************************
         sgzlib - A seekable Gzip file format

   Author:         Michael Cohen (scudette@users.sourceforge.net)
   Version: 0.1   
   Copyright (2004).

   This library provides a unified interface for access and creation
   of sgzip files. sgzip files are files based on the gzip compression
   library which are also quickly seekable and therefore may be used
   for applications where seeking is important. See the .h file for a
   full description of this library.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
                                                                                          
   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.
                                                                                          
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA
                                                                                          
************************************************/

#include "sgzlib.h"
#include "except.h"

#define DEFAULT_BLOCKSIZE 1024*32

int sgz_verbose=1;

// Constant messages:
static char Malloc[]="Cant Malloc\n";
static char Write[]="Write Error - Could not write %s\n";
static char Read[]="Read Error - Could not read %s\n";

/* A nonfatal error occured */
static void warn(const char *message, ...)
{
	va_list ap;
	va_start(ap, message);
	vprintf(message, ap);
	va_end(ap);
};

/* Used for Debugging messages*/
void sgzip_debug(int level, const char *message, ...)
{
	va_list ap;
	if(sgz_verbose < level) return;
	va_start(ap, message);
	vfprintf(stderr,message, ap);
	va_end(ap);
};

/*
This function reads from the fd, until the buffer is full. If a read
does not return enough bytes to fill the buffer (as would happen if we
read from a socket or pipe), we retry again.

If however, the read returns no bytes (and its blocking) then we
assume that the file is finished, and return a short buffer.

If we fail to read, we return the error code back.
*/
static int read_from_stream(int fd,void *buf,int length) {
  int result;
  char *current_p = (char *)buf;

  while(length>0) {
    if(length==0)
      break;

    result=read(fd,current_p,length);
    if(result<0) { //Error occured
      return(result);
    } else if(result==0) { //EOF reached
      break;
    };
    length-=result;
    current_p+=result;
  };
  return(current_p-(char *)buf);
};

/*
 Produces a default sgzip header. Mallocs its own memory, caller must
 free it.
*/
struct sgzip_header *sgzip_default_header(void) {
  struct sgzip_header *header;
  char magic[]="sgz";
  char compression[]="gzip";

  header=(struct sgzip_header *)malloc(sizeof(*header));
  if(!header) RAISE(E_IOERROR,NULL,Malloc);
  memcpy(header->magic,magic,sizeof(magic));
  memcpy(header->x.compression,compression,sizeof(compression));
  header->blocksize=DEFAULT_BLOCKSIZE;
  return header;
};

/* Reads the header from the file. 
Returns NULL if the file can not be identified as a sgzip file 
*/
struct sgzip_header *sgzip_read_header(int fd) {
  struct sgzip_header *result;

  result=(struct sgzip_header *)malloc(sizeof(*result));
  if(!result)
    RAISE(E_NOMEMORY,NULL,Malloc);
  lseek(fd,0,SEEK_SET);

  if(read_from_stream(fd,result,sizeof(*result))<sizeof(*result)) {
    RAISE(E_IOERROR,NULL,Read,"header");
  };
  
  if(strncmp(result->magic,"sgz",3)) {
    RAISE(E_IOERROR,NULL,"File does not look like a sgz file (bad magic)\n");
    return(NULL);
  };

  return(result);
};

/* Write a correct file header on the file descriptor.

   The user can pass in a prefilled in struct sgzip_header *, in which
   case a new struct will not be malloced. If the user passes in NULL,
   a new struct will be malloced and returned.
 */
struct sgzip_header *sgzip_write_header(int fd,struct sgzip_header *header) {
  if(!header){
    header=sgzip_default_header();
  }
  
  if(write(fd,header,sizeof(*header))<sizeof(*header)) 
    RAISE(E_IOERROR,NULL,Write,"header");

  return(header); 
};


struct sgzip_index_list *add_item(struct sgzip_index_list *index,int block_length) {
  struct sgzip_index_list *i;

  //i is the last item in the list:
  for(i=index;i && i->next;i=i->next);

  if(!index) {
    index=(struct sgzip_index_list *)malloc(sizeof(*index));
    if(!index) RAISE(E_NOMEMORY,NULL,Malloc);

    i=index;
    i->offset=block_length;
    i->next=NULL;
  } else {
    i->next=(struct sgzip_index_list *)malloc(sizeof(*i->next));
    if(!i->next) RAISE(E_NOMEMORY,NULL,Malloc);
    
    /* 
       We store a cumulative absolute offset in our linked lists and
       file, but we only really need to store a relative
       offset. Relative offsets can save 2 bytes per block, but lose
       the ability to recover from a corrupted file (although it
       could be difficult to resync anyway if the file is corrupted
       - so it may not be practical to recover from a corrupted
       sgzip file).
    */
    i->next->offset=i->offset+block_length;
    i=i->next;
    i->next=NULL;
  };

  return(index);
};

//Size of write chunks
#define BUFFER_SIZE 1024*1024

/* This function is used to streamline write operations in order to
   reduce total number of system calls required.

   We expect to get a pre-malloced buffer to work with which the
   caller must provide and then free afterwards.

   Fill stores the current size of the buffer, it should not be
   modified by the caller.
   
   If data is NULL, or length =0, we flush the buffer.
 */
static int stream_write(int outfd,void *data,int length, 
			char *buffer,uint32_t *fill, int size, char *comment) {
  //Can we fit the new data in the buffer? Or do we need to flush the
  //data?
  if(!data || length==0 || *fill+length>size) { //No: write the buffer out
    if(write(outfd,buffer,*fill)<*fill) warn(Write,comment);
    *fill=0;
  };

  //If the data is too big to fit in the buffer, we just flush it all out
  if(length>size) {
    if(write(outfd,buffer,length)<length) warn(Write,comment);
    return(length);
  };

  //Otherwise we copy the data into the buffer for next time
  if(data && length>0) {
    memcpy(buffer+*fill,data,length);
    *fill+=length;
  };
  return(length);
};

void sgzip_write_index(int outfd,uint64_t *index) {
  int j,count=0;
  char *buffer;
  uint32_t fill=0;

  buffer=(char *)malloc(BUFFER_SIZE);
  if(!buffer) RAISE(E_NOMEMORY,NULL,Malloc);

  for(j=0;index[j];j++) {
    stream_write(outfd,index+j,sizeof(*index),buffer,&fill,BUFFER_SIZE,"Index");
    count++;
  }

  //Flush the stream:
  stream_write(outfd,NULL,0,buffer,&fill,BUFFER_SIZE,"Flush");
  free(buffer);
  
  //Write the size of the index
  write(outfd,&count,sizeof(count));

  //Write the index magic to indicate this file has an index:
  if(write(outfd,"sgzidx",sizeof(char)*6)<6) 
    warn("Could not write index magic\n");
};

/* Copy stream in to stream out */
void sgzip_compress_fds(int infd,int outfd,const struct sgzip_obj *sgzip) {
  unsigned char *datain;
  uint32_t lengthin;
  unsigned char *dataout;
  char *buffer;
  unsigned long lengthout;
  uint32_t fill=0;
  int result;
  struct sgzip_index_list *index_list=NULL;
  struct sgzip_index_list *i;
  uint64_t count=0;
  uint64_t *index;

  datain=(unsigned char *) malloc(sgzip->header->blocksize);
  dataout=(unsigned char*)malloc(sgzip->header->blocksize+1024);
  buffer = (unsigned char *)malloc(BUFFER_SIZE);
  if(!datain || !dataout || !buffer)
    RAISE(E_NOMEMORY,NULL,Malloc);

  do {
    //Read a block from the input
    lengthin=read_from_stream(infd,datain,sizeof(*datain)*sgzip->header->blocksize);
    if(lengthin<0) {
      warn("Error reading from file descriptor\n");
      return;
    };

    //Compress this block
    lengthout=sgzip->header->blocksize+1024;
    if(!sgzip->level) {
      if(lengthin>lengthout) RAISE(E_GENERIC,NULL,"Unable to copy %u bytes into %u bytes\n",lengthin,lengthout);
      memcpy(dataout,datain,lengthin);
    } else {
      result = compress2(dataout,(unsigned long *)&lengthout,datain,(unsigned long)lengthin,sgzip->level);
      if(result!=Z_OK) {
	warn("Cant compress block of size %lu into size %lu...\n" , lengthin, lengthout);
      };
    };
    //Now we write the size of the compressed buffer as a pointer to
    //the next buffer. This is done to force only 32bits to be written
    //into the file.
    {
      uint32_t temp = (uint32_t)lengthout;

      stream_write(outfd,&temp,sizeof(temp),
		   buffer,&fill,BUFFER_SIZE,"Compressed Pointer");
    };

    if(!(count % 100)) {
      sgzip_debug(1,"Wrote %llu blocks of %lu bytes = %llu Mb total\r",count,sgzip->header->blocksize,(count*sgzip->header->blocksize/1024/1024));
    };

    //Add this to the index list:
    index_list=add_item(index_list,lengthout);

    //And the compressed data:    
    result=stream_write(outfd,dataout,sizeof(*dataout)*lengthout,
			buffer,&fill,BUFFER_SIZE,"Data write");

    count++;
  } while(lengthin>0);

  //Write a single int of zero offset to indicate the blocks have
  //finished:
  lengthout=0;
  result=stream_write(outfd,&lengthout,sizeof(lengthout),
		      buffer,&fill,BUFFER_SIZE,"Index");

  //Flush the write stream:
  stream_write(outfd,NULL,0,buffer,&fill,BUFFER_SIZE,"Flush");

  //Now write the index to the file:
  index=(uint64_t *)calloc(sizeof(*index),count+1);
  if(!index) RAISE(E_NOMEMORY,NULL,Malloc);
  
  for(count=0,i=index_list;i;i=i->next,count++) {
    index[count]=i->offset;
  };  
  index[count]=0;

  sgzip_write_index(outfd,index);

  free(index);
  free(datain);
  free(buffer);
  free(dataout);
};

/* We implement a simple cache here to avoid having to decompress the
   same block if it is read in little chunks. This seems to make a
   huge difference for programs like ils etc, particularly when
   operating on a fat filesystem.

   data is a malloced block which gets read every time. We never free
   data since it must remain valid between calls.
*/
static unsigned char *data=NULL;
static unsigned char *cdata=NULL;
uint64_t cached_block_offs=-1;
static int cached_length=-1;

/* read a random buffer from the sgziped file */
int sgzip_read_random(char *buf, int len, uint64_t offs,
		      int fd, uint64_t *index,const struct sgzip_obj *sgzip) {
  unsigned long int length,clength;
  uint64_t block_offs,copied=0,buffer_offset,available;
  int result;

  //Only malloc data the first time we run.
  if(!data)
    data=(char *)malloc(sizeof(*data)*(sgzip->header->blocksize+1024));
  if(!cdata)
    cdata=(char *)malloc(sizeof(*cdata)*(sgzip->header->blocksize+1024));

  if(!data || !cdata) RAISE(E_NOMEMORY,NULL,Malloc);

  block_offs=(int)(offs/sgzip->header->blocksize);
  if(block_offs > sgzip->header->x.max_chunks) {
    return(0);
    //This should not raise... just return 0 bytes.
    //    RAISE(E_IOERROR,NULL,"Attempt to seek past the end of the file (block %lu requested from a %u blocks file)",block_offs,(header->x.max_chunks));
  };
  
  //The offset where we need to start from in the individual block.
  buffer_offset=offs % sgzip->header->blocksize;

  while(len>0) {
    //If we no longer have any more blocks (we reached the end of the file)
    if(block_offs >= (sgzip->header->x.max_chunks-1)) break;

    //Here we decide if we have a cache miss:
    if(cached_block_offs != block_offs) {
      //Length of this block
      clength=index[block_offs+1]-index[block_offs];

      if(clength>=(sgzip->header->blocksize+1024)) {
	RAISE(E_IOERROR,NULL,"Clength (%u) is too large (blocksize is %u)",clength,sgzip->header->blocksize);
      };

      if(clength<0) break;

      //Read the compressed block from the file:
      if(lseek(fd,sizeof(struct sgzip_header)+sizeof(unsigned int)*(block_offs+1)+
	       index[block_offs],SEEK_SET)<0 || read(fd,cdata,clength)<0) {
	RAISE(E_IOERROR,NULL,"Compressed file reading problem (seeked to %llu - read %llu bytes)",sizeof(struct sgzip_header)+sizeof(unsigned int)*(block_offs+1)+ index[block_offs],clength);
      };
  
      length=sgzip->header->blocksize;
      result=uncompress(data,(unsigned long *)&length,cdata,clength);
    
      //Inability to decompress the data is non-recoverable:
      if(!result==Z_OK) {
	RAISE(E_IOERROR,NULL,"Cant decompress block %lu \n" , block_offs);
      };

      //Note which block we decompressed
      cached_block_offs = block_offs;
      cached_length =length;
    } else {
      //Cache hit - data is valid
      length=cached_length;
    };

    //The available amount of data to read:
    available=length-buffer_offset;
    if(available>len) {
      available=len;
    };

    //Copy the right data into the buffer
    memcpy(buf+copied,data+buffer_offset,available);
    len-=available;
    copied+=available;
    block_offs++;
    buffer_offset=0;
  }

  return(copied);
};

/* This function reads the index from the file and returns an array of
   long ints representing the offsets into the compressed image where
   the blocks can be found. Each entry in the array is blocksize big,
   so to seek to an arbitrary location, we just divide the location by
   the blocksize and use that as the reference to the correct block in
   the file. 

   If the index is not there we flag an error by returning null.
*/
uint64_t *sgzip_read_index(int fd, struct sgzip_obj *sgzip) {
  char magic[6];
  unsigned int count;
  uint64_t *index;
  uint64_t end;

  //Find the end of file:
  end=lseek(fd,0,SEEK_END);
  if(end<0) return(NULL);

  //First we detect if there is an index at the end by reading the magic
  if(lseek(fd,(uint64_t)(end-6-sizeof(count)),SEEK_SET)<0) {
    /* This file may not be seekable, in this case we cant read its
       index.  We can rebuild the index from the file itself, but a
       non-seekable file cannot be used for read_random, and simply
       decompressing it in a stream does not need an index.
    */
    return(NULL);
  };
  
  if(read(fd,&count,sizeof(count))<sizeof(count))
    RAISE(E_IOERROR,NULL,Read,"index");

  if(read(fd,magic,sizeof(char)*6)<6)
    RAISE(E_IOERROR,NULL,Read,"index");

  if(strncmp(magic,"sgzidx",6)) {
    warn("It appears that there is no index on this file, you may regenerate the index\n");
    return(NULL);
  };

  sgzip->header->x.max_chunks = count;

  //Allocate enough memory for the array:
  index=(uint64_t *)calloc(count+1,sizeof(*index));
  if(!index) 
    RAISE(E_NOMEMORY,NULL,Malloc);

  //Now find the start of the index
  if(lseek(fd,end-6-sizeof(count)-count*sizeof(*index),SEEK_SET)<0) {
    warn("seek error\n");
    return(NULL);
  };

  //Read the array in:
  if(read(fd,index+1,sizeof(*index)*count)<sizeof(*index)*count) {
    warn("Unable to read the index\n");
    return(NULL);
  };

  //Null terminate the end of the array
  index[count]=0;
  return(index);
};

/* 
   reads the stream and calculates the index map.

   This is done by following all the blocks throughout the file and
   rebuilding the index. None of the blocks are decoded so this should
   be quick.  We return an index array of uint64_t.
 */
uint64_t *sgzip_calculate_index_from_stream(int fd,
			      const struct sgzip_obj *sgzip) {
  int length=0;
  int zoffset=0;
  int offset=0,count=0;
  char *datain;
  int datalength=sgzip->header->blocksize+1024;
  struct sgzip_index_list *result=NULL,*i;
  uint64_t *index=NULL;

  /* We use read, rather than seek so this will work on non-seekable
     streams. */
  datain=(char *) malloc(datalength);
  if(!datain) 
    RAISE(E_NOMEMORY,NULL,Malloc);
  
  TRY {
    while((read_from_stream(fd,&length,sizeof(length))>0) && length>0){
      count++;
      /* If we need to read more data than we expected we bail because
	 the blocksize specified in the header is incorrect */
      if(length>(datalength+1024)) {
	RAISE(E_IOERROR,NULL,"blocksize %lu is bigger than that specified in the header, invalid sgzip file\n",length);
      };
      
      zoffset+=length;
      
      // Add to linked list
      result=add_item(result,length);
      
      //Seek length bytes from here for the next value
      if(read_from_stream(fd,datain,sizeof(*datain)*length)<length) {
	RAISE(E_IOERROR,NULL,Read,"file1");
      };
      
      offset+=sgzip->header->blocksize;
    };
  } EXCEPT(E_IOERROR) {
    /* When we hit the end of the file, we should get an io_error,
       which is a sign for us to write the index on the file */
  };
  //Create an index table:
  index=(uint64_t *)malloc(count*sizeof(*index));
  if(!index) RAISE(E_NOMEMORY,NULL,Malloc);

  count=1;
  for(i=result;i;i=i->next) {
    index[count]=i->offset;
    count++;
  };

  index[count]=0;
  return(index);
};

/* 
   Decompress the stream, writing it into the outfd.
 */
void sgzip_decompress_fds(int fd,int outfd,struct sgzip_obj *sgzip) {
  int length=0;
  unsigned long lengthout=0;
  int read_len;
  int result;
  int zoffset=0;
  unsigned char *datain,*dataout;
  char *buffer;
  int datalength=sgzip->header->blocksize+1024;
  uint32_t count=0;
  uint32_t fill=0;

  /* We use read, rather than seek so this will work on non-seekable
     streams. */
  datain=(unsigned char *) malloc(datalength);
  dataout=(unsigned char *) malloc(datalength);
  buffer = (unsigned char *)malloc(BUFFER_SIZE);
  if(!datain || !dataout || !buffer) 
    RAISE(E_NOMEMORY,NULL,Malloc);
  
  while((read_from_stream(fd,&length,sizeof(length))>0) && length>0){
    count++;
    /* If we need to read more data than we expected we bail because
       the blocksize specified in the header is incorrect */
    if(length>datalength) {
      free(datain);
      free(dataout);

      RAISE(E_IOERROR,NULL,"blocksize %lu is bigger than that specified in the header, invalid sgzip file\n",length);
    };

    zoffset+=length;
    read_len=read_from_stream(fd,datain,sizeof(*datain)*length);
    if(read_len<length) {
      free(datain);
      free(dataout);

      RAISE(E_IOERROR,NULL,"Only read %u bytes from stream, wanted %u",read_len,length);
    };
    
    //Now uncompress this block:
    lengthout=datalength;

    result=uncompress(dataout,(unsigned long *)&lengthout,datain,length);
    if(result!=Z_OK) {
      warn("Cant uncompress block of size %lu into size %lu..., filling with zeros\n" , length, datalength);
      memset(dataout,0,datalength);
    };
    
    //Write the output:
    stream_write(outfd,dataout,sizeof(*dataout)*lengthout,buffer,&fill,BUFFER_SIZE,"Data write");

    if(!(count % 100)) {
      sgzip_debug(1,"Wrote %lu blocks of %lu bytes = %lu Mb total\r",count,sgzip->header->blocksize,count*sgzip->header->blocksize/1024/1024);
    };
  };

  free(datain);
  free(dataout);
};
