/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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
/*****************************************************
 * Eye Witness Compression Format Support
 * Version 0.1
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Michael Cohen <scudette@users.sourceforge.net> (C) 2004
 *
 *  This software normally lives on http://sourceforge.net/projects/pyflag/
 *  Check there for the latest updates.
 *
 *  Comments:
 *     Seems like a really strange format:
 *
 *           - The CRC does not cover the sector offsets in the table
 *           section, so having a second copy is pointless. You cant
 *           detect errors in the offsets so its impossible to know
 *           which table section is correct (table or table2).
 *
 *           - The sectors offset does not have a checksum on it, so
 *           its impossible to detect errors in the compressed data,
 *           other than when the decompressor fails. Most bit errors
 *           in compressors produce valid huffman values and therefore
 *           would decode to something. Its therefore impossible to
 *           know if the data that was extracted from each sector is
 *           correct. I actually expeienced exactly this phenomenon
 *           while using encase. Text only files, appeared to be
 *           binary mixed with segments of text - a classic indication
 *           of a corrupt compressed sector. I would assume that
 *           encase does an MD5 hash comparison to let you know if the
 *           whole file has been corrupted, but its impossible to know
 *           which sectors are corrupted.
 *
 *           - This format is not suitable for writing to streams,
 *           because we need to go back and seek into the file in
 *           order to write stuff into it. (for example we have no
 *           idea how big the section is going to be until we finished
 *           writing it... then we need to seek back to the section
 *           header to modify it. This limits this format's
 *           usefulness, and increases the likelyhood for errors. (Use
 *           sgzip for stream compression). 
 *
 *           - In general sgzip is a better format (its much more
 *           simple and robust), try to not use this file format
 *           unless there is a very good reason to do so (e.g. you
 *           need to exchange files with encase users etc).
 *
 ****************************************************/
#include "libevf.h"
#include "except.h"
#include "global.h"
#include "md5.h"

// Constant messages:
static char Malloc[]="Cant Malloc\n";
static char Write[]="Write Error - Could not write %s\n";
static char Read[]="Read Error - Could not read %s\n";
static char Seek[]="Cant Seek";
static char evf_magic[]={0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00};
//Standard block size is 32K:
static int blocksize=32*1024;

/* A nonfatal error occured */
void evf_warn(const char *message, ...)
{
	va_list ap;
	va_start(ap, message);
	vfprintf(stderr,message, ap);
	va_end(ap);
};

int evf_listonly=0;

int evf_verbose=0;
/* Used for Debugging messages*/
void evf_debug(int threshold,const char *message, ...)
{
  va_list ap;
  if(evf_verbose<threshold) return;
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
int read_from_stream(int fd,void *buf,int length) {
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

int advance_stream(int fd, int length) {
  int result;
  int count = 0;
  char current_p;

  evf_warn("  hrmm...asked to advance: %i\n", length);

  while(length>0) {
    if(length==0) 
      break;

    result=read(fd,&current_p,1);
    if(result<0) { //Error occured
      return(result);
    } else if(result==0) { //EOF reached
      break;
    };
    length-=result;
    count += result;
  };
  return(count);
};

struct evf_file_header *evf_read_header(int fd) {
  struct evf_file_header *file;

  file=(struct evf_file_header *)malloc(sizeof(*file));
  if(!file) RAISE(E_NOMEMORY,NULL,Malloc);

  if(read_from_stream(fd,file,sizeof(*file))<sizeof(*file))   {
    free(file);
    
    RAISE(E_IOERROR,NULL,Read,"File Header");
  };
  
  if(strcmp(evf_magic,file->magic)) {
    free(file);

    RAISE(E_IOERROR,NULL,"File format not recognised as EWF");
  };

  evf_debug(2,"Opened EVF file\n");
  evf_debug(2,"Segment %u\n",file->segment);
  return(file);
};

/* This is taken from the ASR data web site */
unsigned int evf_crc(void *buffer,int buffersize,unsigned int prevkey) {
  unsigned char *cbuffer=(unsigned char *)buffer;
  unsigned int b=prevkey & 0xffff;
  unsigned int d=(prevkey>>16)&0xffff;
  int i;

  for(i=0; i<buffersize; i++) {
    b+=cbuffer[i];
    d+=b;
    
    if(i!=0 && ((i %0x15b0 ==0) || (i==buffersize-1))) {
      b=b%0xfff1;
      d=d%0xfff1;
    };
  };

  return((d<<16) | b);
};

struct evf_section_header *evf_read_section(int fd) {
  struct evf_section_header *section;
  
  section=(struct evf_section_header *)malloc(sizeof(*section));
  if(!section) RAISE(E_NOMEMORY,NULL,Malloc);

  if(read_from_stream(fd,section,sizeof(*section))<sizeof(*section)) 
    RAISE(E_IOERROR,NULL,Read,"Section Header");


  if(!memcmp(section->type,"header",strlen("header"))) {
#ifdef CYGWIN
    //Windows does not have llu formatter...
    evf_debug(1,"section %s: next header: %lu, Section size: %lu crc %u(%u)\n",
	      section->type,(unsigned int)section->next,(unsigned int)section->size,section->crc,evf_crc(section,sizeof(*section)-4,1));
#else
    evf_debug(1,"section %s: next header: %llu, Section size: %llu crc %u(%u)\n",
	      section->type,section->next,section->size,section->crc,evf_crc(section,sizeof(*section)-4,1));
#endif

  } else {
#ifdef CYGWIN
    //Windows does not have llu formatter...
    evf_debug(2,"section %s: next header: %lu, Section size: %lu crc %u(%u)\n",
	      section->type,(unsigned int)section->next,(unsigned int)section->size,section->crc,evf_crc(section,sizeof(*section)-4,1));
#else
    evf_debug(2,"section %s: next header: %llu, Section size: %llu crc %u(%u)\n",
	      section->type,section->next,section->size,section->crc,evf_crc(section,sizeof(*section)-4,1));
#endif
  }
    


  return section;
};

/* Prints the MD5 sum as a string */
void evf_printable_md5(char *md5,char *data) {
  int i;

  for(i=0;i<16;i++) {
    unsigned char c=*(md5+i);
    snprintf(data+i*2,3,"%02x",c);
  };
};

void process_section(struct evf_section_header *header,int image_number,struct offset_table *offsets) {
  char *data,*cdata;
  struct section *this_section,*tmp;
  int fd=offsets->files[image_number];
  long long int offset;

  //Create a new section entry:
  this_section=(struct section *)malloc(sizeof(*this_section));
  if(!this_section) RAISE(E_NOMEMORY,NULL,Malloc);

  this_section->fd=fd;

  //Work out where the section started.
  offset=lseek(fd,0,SEEK_CUR);
  if(offset<0){
    free(this_section);

    RAISE(E_IOERROR,NULL,"seek error");
  };

  this_section->start_offset=offset-sizeof(struct evf_section_header);
  this_section->end_offset=header->size+this_section->start_offset;
  this_section->next=NULL;

  //Add this section to the section list:
  if(offsets->section_list) {
    for(tmp=offsets->section_list;tmp->next;tmp=tmp->next);
    tmp->next=this_section;
  } else {
    offsets->section_list=this_section;
  }

  if(!memcmp(header->type,"header",strlen("header"))) {
    long int length=blocksize,result;

    cdata=(char *)malloc(blocksize);
    data=(char *)malloc(blocksize);
    if(!data || !cdata) RAISE(E_NOMEMORY,NULL,Malloc);

    //Read until the end of the block.
    if(read_from_stream(fd,cdata,header->size)<header->size) {
      free(data);
      free(cdata);
      free(this_section);

      RAISE(E_IOERROR,NULL,Read,"section: header");
    };

    result=uncompress(data,(long int *)&length,cdata,header->size);
    if(result != Z_OK) {
      free(data);
      free(cdata);
      free(this_section);

      RAISE(E_IOERROR,NULL,"Cant Decompress section header %u",result);
    };
    
    //Null terminate the data just in case
    data[length]=0;
    evf_debug(1,"Header data: %s\n",data);
    free(data);
    free(cdata);
    return;

    /* Handle Volumes */
  } else if(!memcmp(header->type,"volume",strlen("volume")) || !memcmp(header->type,"disk",strlen("disk")) ) {
    struct evf_volume_header *volume;

    volume=(struct evf_volume_header *)malloc(sizeof(*volume));
    if(!volume) RAISE(E_NOMEMORY,NULL,Malloc);

    if(read_from_stream(fd,volume,sizeof(*volume))<sizeof(*volume)) 
      RAISE(E_IOERROR,NULL,Read,"Volume header");

    evf_debug(3,"This volume has %u chunks of %u bytes each. crc %u(%u)\n",volume->chunk_count,volume->sectors_per_chunk*volume->bytes_per_sector,volume->crc,evf_crc(volume,sizeof(*volume)-4,1));

    //Malloc enough memory for the index:
    offsets->chunk_size=volume->sectors_per_chunk*volume->bytes_per_sector;
    offsets->max_chunk=0;
    if(volume->chunk_count==0) volume->chunk_count=1;
    offsets->fd=(int *)malloc(volume->chunk_count*sizeof(int));
    offsets->offset=(unsigned int *)malloc(volume->chunk_count*sizeof(*offsets->offset));
    offsets->size=(unsigned short int *)malloc(volume->chunk_count*sizeof(*offsets->size));
    if(!offsets->fd || !offsets->offset || !offsets->size) RAISE(E_NOMEMORY,NULL,Malloc);

    free(volume);

    /* Handle Table sections */
  } else if(!strcmp(header->type,"table")) {
    struct evf_table_header *table;
    unsigned int offset,old_offset=0;
    struct section *tmp_section;
    int i;

    table=(struct evf_table_header *)malloc(sizeof(*table));
    if(!table) RAISE(E_NOMEMORY,NULL,Malloc);

    if(read_from_stream(fd,table,sizeof(*table))<sizeof(*table)) {
      free(table);

      RAISE(E_IOERROR,NULL,Read,"Table header");
    };

    evf_debug(3,"Table is of size %u chunks crc %u(%u)\n",table->count,table->crc,evf_crc(table,sizeof(*table)-4,1));
    
    if(read_from_stream(fd,&old_offset,sizeof(old_offset))<sizeof(old_offset)) {
      free(table);

      RAISE(E_IOERROR,NULL,Read,"Table header");
    };

    old_offset=old_offset  & 0x7fffffff;

    //Make sure we have enough memory to store the table data):
    offsets->fd=(int *)realloc(offsets->fd,(offsets->max_chunk+2+table->count)*sizeof(int));
    offsets->offset=(unsigned int *)realloc(offsets->offset,(offsets->max_chunk+2+table->count)*sizeof(*offsets->offset));
    offsets->size=(unsigned short int *)realloc(offsets->size,(offsets->max_chunk+2+table->count)*sizeof(*offsets->offset));
    if(!offsets->fd || !offsets->offset || !offsets->size) RAISE(E_NOMEMORY,NULL,Malloc);

    //Now read the table data from the file into memory:
    if(read_from_stream(fd, offsets->offset + offsets->max_chunk+1
			,table->count * sizeof(offset))
       < table->count * sizeof(offset)) {
      free(table);
      
      RAISE(E_IOERROR,NULL,Read,"Table header");
    };

    for(i=0;i<table->count-1;i++) {
      offset = offsets->offset[offsets->max_chunk+1] & 0x7fffffff;

      offsets->fd[offsets->max_chunk]=fd;
      offsets->offset[offsets->max_chunk]=old_offset;
      offsets->size[offsets->max_chunk]=(unsigned short int)(offset-old_offset);
      evf_debug(3,"offset %u in file %u has size %u\n",offsets->max_chunk,old_offset,offset-old_offset);
      offsets->max_chunk++;
      old_offset=offset;
    };

    /*
      Now we need to work out the offset for the last entry. This is
      complex because we dont know how large the last compressed chunk
      is, all we know is where it starts in the file. We need to find
      the sectors section in the file, work out how large it is, and
      then we assume that the last sector fills the sectors section
      out
    */
    for(tmp_section=offsets->section_list;tmp_section->next;tmp_section=tmp_section->next) {
      if(tmp_section->fd==fd && tmp_section->start_offset<offset && offset<tmp_section->end_offset) {
	offsets->fd[offsets->max_chunk]=fd;
	offsets->offset[offsets->max_chunk]=offset & 0x7fffffff;
	offsets->size[offsets->max_chunk]=tmp_section->end_offset-offset;
	offsets->max_chunk++;
	evf_debug(3,"Last chunk is %u big on fd %u\n",tmp_section->end_offset-offset,fd);
	break;
      };
    };

    free(table);

    /* Handle Sector sections */
  } else if(!strcmp(header->type,"sectors")) {
    /* The sectors section holds the actual compressed data so we need
       to just skip it */

    /* Handle table2 sections */
  } else if(!strcmp(header->type,"table2")) {
    /* The table2 section is another copy of the table section???? why
       have 2 copies when there is no way of knowing if one was
       damaged because the crc does not cover it? */
  } else if(!strcmp(header->type,"hash")) {
    if(read_from_stream(fd,offsets->md5,16)<16) RAISE(E_IOERROR,NULL,Read,"hash");
  } else {
    //    printf("I dont know how to handle this section %s\n",header->type);
  };
};

/* decompress all blocks and spit it out to outfd */
void evf_decompress_fds(struct offset_table *offsets,int outfd) {
  int i;
  char *data,*cdata;
  long int length,clength,result;
  MD5_CTX md5;

  data=(char *)malloc(offsets->chunk_size);
  //Compressed block may be larger than chunksize:
  cdata=(char *)malloc(offsets->chunk_size+1024);
  if(!data || !cdata) RAISE(E_NOMEMORY,NULL,Malloc);
  
  MD5Init(&md5);

  for(i=0;i<offsets->max_chunk;i++) {
    int chunk_size;
    //Seek to the right place in the right image:
    if(lseek(offsets->fd[i],offsets->offset[i],SEEK_SET)<0) {
      free(data);
      free(cdata);

      RAISE(E_IOERROR,NULL,"Cant Seek");
    };

    chunk_size=offsets->size[i];

    clength=read_from_stream(offsets->fd[i],cdata,chunk_size);
    if(clength<chunk_size) {
      free(data);
      free(cdata);

      RAISE(E_IOERROR,NULL,"Could not read %u bytes from %u while decompressing file\n",chunk_size,offsets->offset[i]);
    };

    length=offsets->chunk_size;

    if(chunk_size<offsets->chunk_size) {
      result=uncompress(data,(long int *)&length,cdata,clength);
      if(result!=Z_OK) {
	evf_warn("Cant uncompress block (%u with offset %u in fd %u) of size %lu into size %lu..., filling with zeros\n" ,i, offsets->offset[i], offsets->fd[i],clength, offsets->chunk_size);
	memset(data,0,offsets->chunk_size);
      };
    } else {
      if(chunk_size - length == 4) {
	// In encase v4, there seems to be a CRC after each block
	// we dont bother checking it for compressed blocks because
	// zlib does its own checking and any errors should be reported there
	if(evf_crc(cdata, length, 1) != *((unsigned int *)(cdata+length))) {
	  evf_warn("WARNING: CRC error in block %i\n", i);
	}
      }
      evf_debug(1,"Block %i of %i is UNCOMPRESSED (%%%i)\r",i,offsets->max_chunk, offsets->max_chunk > 0 ? (i*100)/offsets->max_chunk : 1);
      memcpy(data,cdata,length);
    };

    /* Calculate the MD5 sum for the buffer */
    MD5Update(&md5,data,length);

    if(write(outfd,data,length)<length) {
      free(data);
      free(cdata);
      
      RAISE(E_IOERROR,NULL,Write,"to decompress file");
    };
  };

  MD5Final(cdata,&md5);

  evf_printable_md5(offsets->md5,data);
  evf_debug(0,"Stored MD5 Sum is: %s,  ",data);

  evf_printable_md5(cdata,data);
  evf_debug(0,"Computed MD5 Sum is: %s.  ",data);


  if(!memcmp(cdata,offsets->md5,16)) {
    evf_debug(0,"Correct.\n");
  }else {
    evf_debug(0,"INCORRECT HASH !!!\n");
    exit(1);
  };

  free(data);
  free(cdata);
};

/* We implement a simple cache here to avoid having to decompress the
   same block if it is read in little chunks. This seems to make a
   huge difference for programs like ils etc, particularly when
   operating on a fat filesystem.

   data is a malloced block which gets read every time. We never free
   data since it must remain valid between calls.
*/
static char *data=NULL;
static char *cdata=NULL;
static long long int cached_chunk=-1;
static int cached_length=-1;

/* Read a random buffer from the evf file */
int evf_read_random(char *buf, int len, unsigned long long int offs,
		    const struct offset_table *offsets) {
  long int length,clength,available;
  int result;
  unsigned long long int chunk,buffer_offset,chunk_size,copied=0;

  if(!data)
    data=(char *)malloc(offsets->chunk_size);

  if(!cdata)
    cdata=(char *)malloc(offsets->chunk_size+1024);  

  if(!data || !cdata) RAISE(E_NOMEMORY,NULL,Malloc);
  
  //Current chunk we are after:
  chunk = (int)(offs/offsets->chunk_size);
  if(chunk>offsets->max_chunk) {
    RAISE(E_IOERROR,NULL,"Attempting to seek past the end of the file!");
  };

  //Offset within the decompressed buffer
  buffer_offset=offs % offsets->chunk_size;

  while(len>0) {
    //If we no longer have any more blocks (we reached the end of the file)
    if(chunk >= offsets->max_chunk) break;

    //Work out if this is a cache miss:
    if(cached_chunk != chunk) {

      //Seek to the right place in the right image:
      if(lseek(offsets->fd[chunk],offsets->offset[chunk],SEEK_SET)<0) {
	RAISE(E_IOERROR,NULL,"Cant Seek");
      };

      //The size of the compressed chunk
      chunk_size=offsets->size[chunk];
      clength=read_from_stream(offsets->fd[chunk],cdata,chunk_size);
      if(clength<chunk_size) {
	RAISE(E_IOERROR,NULL,Read,"decompressing file");  
      };
    
      //Decompress the chunk:
      length=offsets->chunk_size;  
      if(chunk_size<offsets->chunk_size) {
	result=uncompress(data,(long int *)&length,cdata,clength);
	if(result!=Z_OK) {
	  evf_warn("Cant uncompress block of size %lu into size %lu..., filling with zeros\n" , clength, offsets->chunk_size);
	  memset(data,0,offsets->chunk_size);
	};
      } else {
	memcpy(data,cdata,length);
      };
      cached_chunk = chunk;
    };

    //The available amount of data to read:
    available=offsets->chunk_size-buffer_offset;
    if(available>len) {
      available=len;
    };

    //Copy the relevant data to buf:
    memcpy(buf+copied,data+buffer_offset,available);
    len-=available;
    copied+=available;
    chunk++;
    buffer_offset=0;
  };

  return(copied);
};


/***************************************************
 * Compression support
 ***************************************************/
void evf_write_file_header(unsigned short int segment, int fd) {
  write(fd,evf_magic,sizeof(evf_magic));
  write(fd,"\1",1);
  write(fd,&segment,sizeof(segment));
  segment=0;
  write(fd,&segment,sizeof(segment));
};

struct evf_section_header *evf_new_section_header(char *type) {
  struct evf_section_header *temp;
  
  temp=(struct evf_section_header *)calloc(sizeof(struct evf_section_header),1);
  if(strlen(type)>15) RAISE(E_NOMEMORY,NULL,"Section name is too big\n");
  strcpy(temp->type,type);
  return (temp);
};

/* Write the section into the file. This function should be called
   after writing the section data, because it will get the current
   file position, and adjust the section's size and next pointers from
   that. This function will return the next section's position. 
*/
int evf_write_section(int section_position,struct evf_section_header *section,int outfd) {
  section->next=lseek(outfd,0,SEEK_CUR);
  if(section->next<0) 
    RAISE(E_IOERROR,NULL,Seek);

  section->size=section->next-section_position;
  section->crc=evf_crc(section,sizeof(*section)-4,1);

  //Go back to the section and re-write it:
  if(lseek(outfd,section_position,SEEK_SET)<0) 
    RAISE(E_IOERROR,NULL,Seek);

  if(write(outfd,section,sizeof(*section))<0) 
    RAISE(E_IOERROR,NULL,Write,"section");
  
  //Return filepointer to current place:
  if(lseek(outfd,section->next,SEEK_SET)<0) 
    RAISE(E_IOERROR,NULL,Seek);

  return(section->next);
};

/* This is the constructor for evf_volume_header. Most of these fields
   are not known when we first start writing the file, so you must go
   back to them at the end. (This is a braindead compression format.)
 */
struct evf_volume_header *evf_new_volume(int chunk_size) {
  struct evf_volume_header *temp = (struct evf_volume_header *)calloc(sizeof(struct evf_volume_header),1);
  if(!temp) RAISE(E_NOMEMORY,NULL,Malloc);
  temp->sectors_per_chunk=64;
  temp->bytes_per_sector=512;
  temp->reserved=1;
  
  return(temp);
};

/* This function reads data from a stream infd, and creates possibly a
   number of files based on filename (with extensions of .Exx, where
   xx is a number). Note the the output files can not be streams
   because we need to seek in them all over the place... This is the
   problem with this file format.

This function is very complex - reflective of the over complex nature
of the ewf compression format.
*/
void evf_compress_fds(int chunk_size,int infd, char *filename,int size) {
  char *data,*cdata;
  long int length,clength,result,i;
  int outfd;
  int segment_number=1;
  struct evf_section_header *section;
  unsigned int section_position;
  struct offset_table *offsets;
  int volume_offset;
  struct evf_volume_header *volume=NULL;
  int sectors_in_section=0;
  //Here we store the sector size temporarily
  int sector_size[16376];
  int volfd;
  int finished=0;
  int current_file_length=0;
  const char *header="1\r\nmain\r\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\tr\r\n1\t1\t1\t1\t1\t3.18b\tWindows 2000\t2004 2 16 17 32 15\t2004 2 16 17 32 7\t0\tf\r\n\r\n";
  MD5_CTX md5;
  struct evf_table_header *table;

  filename=strdup(filename);
  data=(char *)malloc(chunk_size);
  //Compressed block may be larger than chunksize:
  cdata=(char *)malloc(chunk_size+1024);
  offsets=(struct offset_table*)calloc(sizeof(struct offset_table),1);

  //Initialise offsets to some sensible defaults
  offsets->chunk_size=32*1024;

  if(!data || !cdata || !offsets) RAISE(E_NOMEMORY,NULL,Malloc);

  MD5Init(&md5);
  //Create the first file
  outfd=creat(filename,S_IRWXU);
  if(outfd<0) RAISE(E_IOERROR,NULL,"Cant create file %s",filename);

  evf_write_file_header(segment_number,outfd);

  //Do the file header section
  section_position = lseek(outfd,0,SEEK_CUR);
  if(section_position<0) RAISE(E_IOERROR,NULL,Seek);
  
  //We need to write two headers?????? what for????
  for(i=0;i<2; i++) {
    section = evf_new_section_header("header");
    write(outfd,section,sizeof(*section));

    // Write the header data - in future this could be user supplied.
    length=strlen(header);
    memcpy(data,header,length);

    clength=chunk_size;
    result = compress(cdata,(long int *)&clength,data,(long int)length);
    if(result!=Z_OK) {
      evf_warn("Cant compress block of size %lu into size %lu...\n" , length, clength);
    };

    write(outfd,cdata,clength);
    
    //Complete the header:
    section_position = evf_write_section(section_position,section,outfd);
    free(section);
  };
  
  //Now write the volume section if needed:
  volfd=outfd;
  section = evf_new_section_header("volume");
  write(outfd,section,sizeof(*section));
  
  volume=evf_new_volume(chunk_size);
  volume_offset=lseek(outfd,0,SEEK_CUR);
  if(volume_offset<0) RAISE(E_IOERROR,NULL,Seek);
  
  write(outfd,volume,sizeof(*volume));
  section_position = evf_write_section(section_position,section,outfd);
  free(section);
  
  while(1) {
    //Do a sectors section:
    section=evf_new_section_header("sectors");
    write(outfd,section,sizeof(*section));
    volume->chunk_count+=sectors_in_section;
    sectors_in_section=0;
    current_file_length=0;

    while(sectors_in_section<16375 && current_file_length<size) {
      if(read_from_stream(infd,data,chunk_size) < chunk_size) {
	//Finish up the section
	finished=1;
	break;
      };

      //Calculate the md5:
      MD5Update(&md5,data,chunk_size);

      length=chunk_size;
      clength=chunk_size+1024;
      result = compress(cdata,(long int *)&clength,data,(long int)length);
      if(result!=Z_OK) {
	evf_warn("Cant compress block of size %lu into size %lu...\n" , length, clength);
      };
      
      if(clength<chunk_size) {
	sector_size[sectors_in_section]=clength;
	write(outfd,cdata,clength);
      } else {
	sector_size[sectors_in_section]=length;
	write(outfd,data,length);
      };
      
      current_file_length+=clength;
      sectors_in_section++;
    };

    //Remember the position where we started writing the sectors data
    result=section_position+sizeof(*section);
    
    //Finish the sectors section
    section_position = evf_write_section(section_position,section,outfd);
    free(section);
    
    //Write the table section:
    section = evf_new_section_header("table");
    write(outfd,section,sizeof(*section));

    table=(struct evf_table_header *)calloc(sizeof(struct evf_table_header),1);
    if(!table) RAISE(E_NOMEMORY,NULL,Malloc);
    
    table->count=sectors_in_section;
    table->crc=evf_crc(table,sizeof(*table)-4,1);
    write(outfd,table,sizeof(*table));
    free(table);

    //We recall the initial offset in the file where we started writing the sectors before
    for(i=0;i<sectors_in_section;i++) {
      write(outfd,&result,sizeof(result));
      result+=sector_size[i];
    };
    
    //End the table section:
    section_position = evf_write_section(section_position,section,outfd);
    free(section);
    
    if(finished) {
      struct evf_hash hash;

      //Write the hash section:
      section=evf_new_section_header("hash");
      section_position=lseek(outfd,0,SEEK_CUR);
      write(outfd,section,sizeof(*section));
      
      MD5Final(&hash.md5,&md5);
      hash.zero=0;
      hash.zero2=0;

      //FIXME: What do these mean?
      hash.unknown=0x010ef7Ec;
      hash.unknown2=0x77f516b3;

      write(outfd,&hash,sizeof(hash));

      i=evf_crc(&hash,sizeof(hash),1);
      write(outfd,&i,sizeof(i));

      section_position = evf_write_section(section_position,section,outfd);
      free(section);

      //End this file because we ran out of input
      section = evf_new_section_header("done");
      section->size=0;
      section->next=section_position;
      section->crc=evf_crc(section,sizeof(*section)-4,1);
      write(outfd,section,sizeof(*section));
      break;
    } else if(current_file_length>size) {
      //We need to create a new file for more data
      section = evf_new_section_header("next");
      section->size=0;
      section->next=section_position;
      section->crc=evf_crc(section,sizeof(*section)-4,1);
      write(outfd,section,sizeof(*section));

      if(segment_number>1) {
	//Do not close the fd for the first file because we need to write the volume there.
	close(outfd);
      };
      segment_number++;
      sprintf(filename+strlen(filename)-2,"%02u",segment_number);
      printf("Setting filename to %s\n",filename);
      outfd=creat(filename,S_IRWXU);

      evf_write_file_header(segment_number,outfd);
      section_position=lseek(outfd,0,SEEK_CUR);
      if(section_position<0) RAISE(E_IOERROR,NULL,Seek);
    };
  };

  //Finish the volume:
  volume->chunk_count+=sectors_in_section;
  volume->sector_count=volume->chunk_count * volume->sectors_per_chunk;
  volume->crc=evf_crc(volume,sizeof(*volume)-4,1);
  if(lseek(volfd,volume_offset,SEEK_SET)<0) RAISE(E_IOERROR,NULL,Seek);

  write(volfd,volume,sizeof(*volume));
  free(data);
  free(cdata);
  return;
};
  
