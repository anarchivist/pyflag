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
/* This file implements file system IO calls. 
 
We overload the open,close, seek and read system calls to be
initialised through the correct IO subsystem.

*/
#include "iosubsys.h"
#include "sgzlib.h"
#include "libevf.h"
#include "remote.h"
#include "except.h"

inline int min(int x, int y) {
  if(x<y) return(x);
  return(y);
};

static int verbose=0;

/* Used for Debugging messages*/
static void debug(int level, const char *message, ...)
{
	va_list ap;
	if(verbose < level) return;
	va_start(ap, message);
	vfprintf(stderr,message, ap);
	va_end(ap);
};

/*******************************************
 *          Standard IO Subsystem.
 *          Defaults.
 *******************************************/
struct IO_INFO_STD {
  IO_INFO io;
  char *name;
  int fd;
};

typedef struct IO_INFO_STD IO_INFO_STD;

/* This is a generic constructor that can be called from all other
   objects */
IO_INFO *io_constructor(IO_INFO *class) {
  IO_INFO *io=(IO_INFO *)calloc(1,class->size);

  if(!io) RAISE(E_IOERROR,NULL,"Could not malloc\n");
  
  //Instantiate the class in the new object:
  memcpy(io,class,sizeof(*class));
  return(io);
};

/* fs_read_random - random-access read */
int    std_read_random(IO_INFO *self, char *buf, int len, off_t offs,
		               const char *comment)
{
    char   *myname = "fs_read_random";
    int     count;
    IO_INFO_STD *io=(IO_INFO_STD *)self;

    if(!self->ready && self->open(self)<0) return(-1);

    debug(2, "%s: read offs %.0f len %d (%s)\n",
	  myname, (double) offs, len, comment);

    if (lseek(io->fd, offs, SEEK_SET) != offs)
      RAISE(E_IOERROR,NULL,"read random seek error: offset %llu: %m (%s)", 
	    (off_t) offs, comment);
    
    if ((count = read(io->fd, buf, len)) != len)
      RAISE(E_IOERROR,NULL,"read random read error (%d@%llu): %m (%s)", 
	    len, (off_t) offs, comment);

    return(count);
}

void std_help(void) {
  printf("No parameters required");
};

int std_initialiser(IO_INFO *io,IO_OPT *args) {
  IO_INFO_STD *self=(IO_INFO_STD *)io;

  // If we only get an option with no value, then we assume its the
  // filename we need to open:
  for(;args;args=args->next) { 
    if(!args->value || strlen(args->value)==0) {
      self->name=strdup(args->option);
    } else if(CHECK_OPTION(args,filename)) {
      self->name=strdup(args->value);
    };
  };
  return(0);
};

int std_open(IO_INFO *self) {
  IO_INFO_STD *io=(IO_INFO_STD *)self;
  if(!io->name) {
    RAISE(E_IOERROR,NULL,"No filename set!!!");
  };
  io->fd=open(io->name,O_RDONLY);
  if(io->fd<0) {
    RAISE(E_IOERROR,NULL,"Unable to open file %s",io->name);
  };
  self->ready=1;
  return(io->fd);
};

int std_close(IO_INFO *io) {
  IO_INFO_STD *self=(IO_INFO_STD *)io;
  return (close(self->fd));
};

/***************************************
 *     Advanced IO Subsystem 
 *
 *   This subsystem can handle the dd image being split across
 *   multiple files, as well as having the partition image located
 *   within a larger file (for example the disk dd image)
 ***************************************/
struct adv_split_file {
  const char *name;
  int fd;
  // These correspond to the offsets for this file
  long long int start_offset;
  long long int end_offset;
  struct adv_split_file *next;
};

struct IO_INFO_ADV {
  IO_INFO io;
  //Stores the files belonging to this dd image set
  struct adv_split_file *file_list;
  unsigned long long offset;
};

typedef struct IO_INFO_ADV IO_INFO_ADV;

/* fs_read_random - random-access read */
int    adv_read_random(IO_INFO *self, char *buf, int len, off_t offs,
		               const char *comment)
{
    IO_INFO_ADV *io=(IO_INFO_ADV *)self;
    unsigned long long int count=0,available;
    struct adv_split_file *file;

    if(!self->ready)
      self->open(self);

    // Correct the offset as per the user preference:
    offs+=io->offset;

    //Find the file in the split list where the seek will end up in.
    for(file=io->file_list; file; file=file->next) {
      if((file->start_offset<=offs) && (offs<file->end_offset))
	break;
    };

    while(len>0) {
      if(!file)
	//If we dont have any more data, we break and return what we have.
	break;
      
      // Now find out how much we can read from this file:
      available= file->end_offset - offs;
      
      //Seek to the right spot:
      if (lseek(file->fd, offs - file->start_offset, SEEK_SET) != offs - file->start_offset)
	RAISE(E_IOERROR,NULL,"read block lseek error (%llu):", 
	      (off_t) offs);
      
      // If we only want to read a smaller number than whatever is
      // available:
      if(len<available) available=len;
      
      // Read that much into buf:
      count = read(file->fd, buf, available);
      if (count<0) RAISE(E_IOERROR,NULL,"read random read error (%d@%llu): ", 
	      len, (off_t) offs);
      
      //Advance to the next file in the sequence:
      len-=count;
      offs+=count;
      buf+=count;
      file=file->next;
    }
    //Return the total count of bytes read
    return(count);
}

void adv_help(void) {
  printf("Advanced io subsystem options\n\n");
  printf("\toffset=bytes\t\tNumber of bytes to seek to in the image file. Useful if there is some extra data at the start of the dd image (e.g. partition table/other partitions)\n");
  printf("\tfile=filename\t\tFilename to use for split files. If your dd image is split across many files, specify this parameter in the order required as many times as needed for seamless integration\n");
  printf("\tA single word without an = sign represents a filename to use\n");
};

int adv_add_file_to_split_list(IO_INFO_ADV *io,const char *name) {
  /* Add file to our split files list: */
  struct adv_split_file *file,*tmp;
  long long int max_offset=0;
  long long int file_size=0;
  
  file=NEW(struct adv_split_file);
  if(!file) RAISE(E_NOMEMORY,NULL,"Cant Malloc");

  file->next=NULL;  
  file->name=name;
  file->fd = open(name,O_RDONLY);
  if(file->fd<0) {
    free(file);

    RAISE(E_IOERROR,NULL,"Could not open file %s",name);
  };
  
  /* Find out the maximum offset already stored in the file list, as
     well as the end of the list */
  if(io->file_list) {
    for(tmp=io->file_list;tmp->next;tmp=tmp->next);
    tmp->next=file;
    max_offset=tmp->end_offset;
  } else {
    io->file_list=file;
  };
  
  /* Find out the size of the file: */
  file_size=lseek(file->fd,0,SEEK_END);
  if(file_size<0){
    free(file);

    RAISE(E_IOERROR,NULL,"Unable to seek on file %s",file->name);
  };
  
      /* Set the bounds of this file */
  file->start_offset=max_offset;
  file->end_offset=file->start_offset+file_size;
  
  return(file->fd);
};

int adv_initialiser(IO_INFO *self,IO_OPT *args) {
  IO_OPT *i;
  IO_INFO_ADV *io=(IO_INFO_ADV *)self;

  for(i=args;i;i=i->next) {
    //If we are not given an option=value pair, we interpret the whole
    //thing as a filename:
    if(i->option && (!i->value || strlen(i->value)==0)) {
      adv_add_file_to_split_list(io,i->option);
      continue;
    }else if(CHECK_OPTION(i,file)) {
      adv_add_file_to_split_list(io,i->value);
      fprintf(stderr, "Set file to read from as %s\n",i->value);
      continue;
    } else if(CHECK_OPTION(i,offset)) {
      io->offset=parse_offsets(i->value);
      //      printf("Set offset to %llu bytes\n",io->offset);
      continue;
    };

    // If we get here we did not recognise this option, lets give the
    // user a helpful message:
    RAISE(E_GENERIC,NULL,"option %s not recognised",i->option);
  };
  return(0);
};

int adv_open(IO_INFO *self) {
  //We dont do any openning here, since we open the files when we add
  //the options in...
  self->ready=1;
  return(1);
};

int adv_close(IO_INFO *self) {
  IO_INFO_ADV *io=(IO_INFO_ADV *)self;
  struct adv_split_file *file;
  
  for(file=io->file_list;file;file=file->next) 
    close(file->fd);
  return (1);
};

/************************************************
 *                       sgzip subsystem
 *
 *   This subsystem allows sleuthkit to read compressed sgzip image
 *   files. sgzip is a seekable compressed file format that can be
 *   generated by the use of the sgzip utility. See sgzlib.h for a
 *   full explanatation of the format.
 ************************************************/
struct IO_INFO_SGZ {
  IO_INFO io;
  struct sgzip_obj *sgzip;
  int fd;
  char *name;
  unsigned long long int *index;
  unsigned long long int offset;
};

typedef struct IO_INFO_SGZ IO_INFO_SGZ;

int sgz_read_random(IO_INFO *self, char *buf, int len, off_t offs,
		               const char *comment)
{
  IO_INFO_SGZ *io=(IO_INFO_SGZ *)self;

  if(!self->ready && self->open(self)<0) return(-1);

  len=sgzip_read_random(buf,len,offs+io->offset,io->fd,io->index,io->sgzip);
  return(len);
}

void sgz_help(void) {
  printf("sgzip subsystem options\n\n");
  printf("\tfile=filename\t\tFilename to open\n");
  printf("\toffset=bytes\t\tNumber of bytes to seek to in the (uncompressed) image file. Useful if there is some extra data at the start of the dd image (e.g. partition table/other partitions)\n");
};

int sgz_open(IO_INFO *self) {
  IO_INFO_SGZ *io=(IO_INFO_SGZ *)self;
  
  io->sgzip=NEW(struct sgzip_obj);

  if(!io->name) {
    RAISE(E_IOERROR,NULL,"No filename set!");
  };

  io->fd=open(io->name,O_RDONLY);
  if(io->fd<0) {
    RAISE(E_IOERROR,NULL,"Could not open file %s",io->name);
  };

  io->sgzip->header=sgzip_read_header(io->fd);
  if(!io->sgzip->header) {
    RAISE(E_IOERROR,NULL,"%s is not a sgz file",io->name);
  };

  io->index=sgzip_read_index(io->fd,io->sgzip);
  if(!io->index) {
    io->sgzip->header=sgzip_read_header(io->fd);
    fprintf(stderr, "You may consider rebuilding the index on this file to speed things up, falling back to non-indexed method\n");
    io->index=sgzip_calculate_index_from_stream(io->fd,io->sgzip);
  };
  self->ready=1;
  return(io->fd);
};

int sgz_initialiser(IO_INFO *self,IO_OPT *args) {
  IO_OPT *i;
  IO_INFO_SGZ *io=(IO_INFO_SGZ *)self;

  for(i=args;i;i=i->next) {
    //If we are not given an option=value pair, we interpret the whole
    //thing as a filename:
    if(i->option && (!i->value || strlen(i->value)==0)) {
      io->name=strdup(i->option);
      continue;
    }else if(CHECK_OPTION(i,file)) {
      io->name=strdup(i->value);
      fprintf(stderr, "Set file to read from as %s\n",i->value);
      continue;
    } else if(CHECK_OPTION(i,offset)) {
      io->offset=parse_offsets(i->value);
      continue;
    };

    // If we get here we did not recognise this option, raise an
    // error:
    RAISE(E_GENERIC,NULL,"option %s not recognised",i->option);
  };
  return(0);
};

int sgz_close(IO_INFO *self) {
  IO_INFO_SGZ *io=(IO_INFO_SGZ *)self;
  free(io->index);
  free(io->sgzip->header);
  free(io->sgzip);
  return (close(io->fd));
};

/************************************************
 *  Expert Witness Compression Format (EWF) subsystem
 *
 *   This subsystem allows processing of image files taken with the
 *   EWF format. EWF is a forensic compression format which is a
 *   "quasi-proprietary format", primarily used by Encase (tm)
 *   (http://www.guidancesoftware.com/) but also used by other leading
 *   commercial products.
 *
 *   This implementation is a clean room implementation based on the
 *   specifications on http://www.asrdata.com/SMART/whitepaper.html.
 *   This implementation is available under the GPL.
 *
 *   This subsystem allows interoperability with image files acquired
 *   using Encase, FTK and SMART.
 *
 *************************************************/
struct IO_INFO_EWF {
  IO_INFO io;
  struct evf_file_header *file_header;
  struct offset_table offsets;
  //This is the offset into the image. Its usually zero unless the
  //entire HDD was acquired.
  unsigned long long int offs;
  //Should we ignore errors?
  int force;
};

typedef struct IO_INFO_EWF IO_INFO_EWF;

void ewf_help(void) {
  printf("An Expert Witness IO subsystem\n\n"); 
  printf("\toffset=bytes\t\tNumber of bytes to seek to in the (uncompressed) image file. Useful if there is some extra data at the start of the dd image (e.g. partition table/other partitions\n");
  printf("\tfilename=file.e0?\t\tFilename to use for split files. If your dd image is split across many files, specify this parameter in the order required as many times as needed for seamless integration\n");
  printf("\tA single word without an = sign represents a filename to use\n");
};

int ewf_read_random(IO_INFO *self, char *buf,int len, off_t offs,
		    const char *comment) {
  IO_INFO_EWF *io=(IO_INFO_EWF *)self;
  
  //If we are not ready, we open the files
  if(!self->ready) self->open(self);
  
  //Read the data - Note we dont need to handle exceptions here, just
  //let them bubble upwards...
  len=evf_read_random(buf,len,offs+io->offs,&(io->offsets));
  
  return(len);
};

/* Opens and Adds additional files */
int ewf_add_file(IO_INFO_EWF *self,char *filename) {
  int fd;
  struct evf_file_header *file_header;

  /*  printf("will add %s as a filename\n",filename);*/
  fd=open(filename,O_RDONLY);
  if(fd<0) {
    RAISE(E_IOERROR,NULL,"Could not open %s",filename);
  };

  file_header=evf_read_header(fd);
  
  //Grow the files array so we can fit the segment in it:
  if(self->offsets.max_segment < file_header->segment) {
    //Amount of additional memory we will need
    int additional_memory=file_header->segment +1;
    
    self->offsets.files=realloc(self->offsets.files,additional_memory*sizeof(*self->offsets.files));
    if(!self->offsets.files) RAISE(E_NOMEMORY,NULL,"Malloc");
    
    //Clear off the newly initialised memory
    memset(self->offsets.files + self->offsets.max_segment + 1, -1 , (additional_memory - self->offsets.max_segment - 1)*sizeof(*self->offsets.files));
    
    //Adjust the maximum size of the array
    self->offsets.max_segment = file_header->segment;
  };
  
  //Store the fd in the correct spot within the files array. So we end
  //up with all the segments ordered regardless of which order we
  //opened them in.
  if(self->offsets.files[file_header->segment]>0) RAISE(E_GENERIC,NULL,"A segment (%s) is specified more than once",filename);
  
  self->offsets.files[file_header->segment]=fd;
  return(0);
};

int ewf_initialiser(IO_INFO *self,IO_OPT *args) {
  IO_OPT *i;
  IO_INFO_EWF *io=(IO_INFO_EWF *)self;

  //Initialise the offsets table the first time we use it:
  if(!io->offsets.files) {
    io->offsets.max_chunk=0;
    io->offsets.max_segment=0;
    //Allocate one array entry and realloc the rest when we need it
    io->offsets.files=(unsigned int *)malloc(sizeof(io->offsets.files)*2);
    io->offsets.fd=NULL;
    io->offsets.offset=NULL;
    io->offsets.section_list=NULL;
    *(io->offsets.files)=-1;
  };
  
  for(i=args;i;i=i->next) {
    if(CHECK_OPTION(i,help)) {
      self->help();
      continue;

    //If we are not given an option=value pair, we interpret the whole
    //thing as a filename:
    } else if(i->option && (!i->value || strlen(i->value)==0)) {
      ewf_add_file(io,strdup(i->option));
      continue;

    }else if(CHECK_OPTION(i,file)) {
      ewf_add_file(io,strdup(i->value));
      continue;

    } else if(CHECK_OPTION(i,offset)) {
      io->offs=parse_offsets(i->value);
      continue;
    };

    // If we get here we did not recognise this option, raise an error:
    RAISE(E_GENERIC,NULL,"option %s not recognised",i->option);
  };
  return(0);
};

int ewf_open(IO_INFO *self) {
  struct evf_section_header *section=NULL;
  IO_INFO_EWF *io=(IO_INFO_EWF *)self;
  int i;
  char tmp[255];

  //When we get here we should have all the files opened, and ready to
  //go. So we just check for consistency that we do not have any files
  //that were not specified:
  
  if(!io->offsets.files || io->offsets.max_segment<1) {
    RAISE(E_IOERROR,NULL,"No Files given");
  };

  /*  printf("max segments = %u\n",io->offsets.max_segment); */
  for(i=1;i<=io->offsets.max_segment;i++) {
    int old_section_offset=0;

    if(io->offsets.files[i]<=0) {
      RAISE(E_IOERROR,NULL,"Missing a segment file for segment %u",i);
    };

    //Now process each file in order until we build the whole index
    while(1) {
      section=evf_read_section(io->offsets.files[i]);

      //This will update offsets.fds and offsets.offset
      process_section(section,i,&(io->offsets));

      /* This ensures that the next section occurs _after_ the
	 current section.  There are some sections in the EVF file
	 which point back at themself, like done or next. When we
	 hit these, we give up reading the file and move to the next
	 file because its impossible to find the next section in the
	 chain. */
      if(old_section_offset >= section->next) break;

      //Go to the next section - If the next section is not found in
      //this file, there is something very wrong!
      if(lseek(io->offsets.files[i],section->next,SEEK_SET)!=section->next) {
	RAISE(E_IOERROR,NULL,"Could not seek");
      };

      strncpy(tmp,section->type,16);
      free(section);
      old_section_offset=section->next;
    };
  };
   
  //Check to see if we are done?
  if(strcasecmp(tmp,"done") && io->force) 
    RAISE(E_IOERROR,NULL,"No ending section, Cant find the last segment file");

  self->ready=1;  
  return(1);
}

int ewf_close(IO_INFO *self) {
  IO_INFO_EWF *io=(IO_INFO_EWF *)self;
  
  free(io->offsets.files);
  free(io->offsets.fd);
  free(io->offsets.offset);
  free(io->offsets.size);
  free(io);
  return(1);
};


/************************************************
 *                     RAID subsystem
 *
 *    This subsystem allows the sleuthkit to read files off a raid set
 *    given a raid reconstruction map.
 *
 ************************************************/
/* How the raid reassembly works:

  Definitions:
  ------------

  A physical block is a block present on a disk in the array. Physical
  blocks are counted from the begining of the disk itself.

  A logical block is a block within the logical reconstructed array
  and is counted from the begining of the complete image. Sequential
  Logical blocks will be physically located on different disks.

  A raid Map is a mapping between logical blocks and physical blocks
  present on a number of disks. Using this map we can locate a
  specific logical block as a physical block on a specific disk.

  The Map pattern repeats for a given number of physical block on a
  disk. We call the number of blocks between repetitions, the Period.

  Within a period we define the physical blocks on each disk as a "Slot".

  For example, if the period is 7, slot 1 will correspond to physical
  block 1,8,15... etc.  

  The total number of logical blocks in a period is found by
  multiplying the number of slots in the period by the total number of
  disk less the number of parity blocks in the period. The total
  number of parity blocks is in turn the total number of
  slots. Another way of thinking of it is that one disk is always
  sacrificed for parity, so total number of logical blocks = (number
  of disks - 1) * number of slots in period.

  The raid map is provided by the user as a sequence of logical blocks
  numbers located within the period.
*/
struct raid_element {
  int fd;
  char *name;
  int number;
  char *data;
  struct raid_element *next;
};

struct raid_element *new_raid_element() {
  struct raid_element *tmp = NEW(struct raid_element );

  if(!tmp) RAISE(E_NOMEMORY,NULL,"Malloc failed");
  tmp->next = 0;
  tmp->fd = 0;
  tmp->data=NULL;
  return (tmp);
};

struct coordinate {
  struct raid_element *disk;
  int disk_number;
  int slot;
};

struct IO_INFO_RAID {
  IO_INFO io;
  //Stores an array of raid elements:
  struct raid_element *disks;
  int number_of_elements;
  int number_of_slots;
  int logical_blocks_per_period;
  int block_size;
  int header_size;
  unsigned long long int offset;
  //An array of map information
  char *map_string;
  struct coordinate *map;
};

typedef struct IO_INFO_RAID IO_INFO_RAID;

void raid_help(void) {
  printf("Raid io subsystem options:\n\
\n\
blocksize=number - The total size of the block in bytes. A block is the largest contiguous run of data.\n\
slots=number - total number of slots in each period (if not specified this is assumed to be the same as the total number of disks\n\
map=1,2,P,3,4,P... A comma delimited map of the raid reconstruction. This map must be syntactically correct.\n\
offset=number - The offset to use into the disk (can use prefixed like k,m,s - sectors=512).\n\n");
  printf("This is an example of a raid reassembly map. This example uses 7 disks and spreads the parity among them in a rotating fashion:\n\
\n\
Disks:  0  1  2  3  4  5  6\n\
---------------------------\n\
S 0     0  1  2  3  4  5  P\n\
  1     P  6  7  8  9 10 11\n\
  2    17  P 12 13 14 15 16\n\
  3    22 23  P 18 19 20 21\n\
  4    27 28 29  P 24 25 26\n\
  5    32 33 34 35  P 30 31\n\
  6    37 38 39 40 41  P 36\n\
\n\
 In this case the following parameters must be specified:\n\
 blocksize=64k,slots=7,map=0.1.2.3.4.5.P.P.6.7.8.9.10.11.17.P.12.13.14.15.16.22.23.P.18.19.20.21.27.28.29.P.24.25.26.32.33.34.35.P.30.31.37.38.39.40.41.P.36,filename=d1,filename=d2,filename=d3,filename=d4,filename=d5,filename=d6,filename=d7\n\
\n\
 Note that if one of the disks can not be opened, we try to reconstruct it from the parity.\n");
};

void add_raid_element(IO_INFO_RAID *io,char *filename) {
  struct raid_element *tmp_element=new_raid_element();
  
  //Add name to the end of the list of raid elements, and open each
  //file for reading.
  if(!io->disks) {
    io->disks=tmp_element;
  } else {
    struct raid_element *tmp=io->disks;
    while(tmp->next) tmp=tmp->next;
    tmp->next=tmp_element;
  };
  
  tmp_element->name=strdup(filename);
  tmp_element->number=io->number_of_elements;

  fprintf(stderr, "Set file number %u as %s\n",
	  tmp_element->number,tmp_element->name);

  io->number_of_elements++;
};

int next_element(char **map_string) {
  unsigned int result;
  
  //This will be 1 when we reached the end of the string...
  if(!*map_string) return(-1);

  //Search map_string for the next occurance of the delimiter
  if(sscanf(*map_string,"%u",&result)==0) 
    result=-1;

  *map_string=index(*map_string,'.');
  if(*map_string)
    (*map_string)++;

  return(result);
};

/* This function parses the map given in parse string into elemets.
 See comment above for explaination of terminology.
 */
void parse_map(IO_INFO_RAID *io) {
  int slot=0;
  int disk=0;
  //The total number of blocks per period is total number of disks
  //less parity * total number of slots.
  int blocks=io->logical_blocks_per_period;
  char *x=io->map_string;
  int j;

  //  printf("Got Map %s to process\n",io->map_string);

  //Allocate enough memory to hold the map initialised with -1:
  io->map = (struct coordinate *)calloc(blocks , sizeof(*io->map));

  while(1) {
    int block=next_element(&x);

    if(block>=0) {
      struct raid_element *i=io->disks;
      //      printf("Read logical block %d at disk %u, slot %u\n",block,disk,slot);
      //Find the correct raid_element in the list:

      while(i && i->number!=disk) i=i->next;

      io->map[block].disk=i;
      io->map[block].disk_number=disk;
      io->map[block].slot=slot;
    } else {
      //  printf("parity at %u %u\n",disk,slot);
    };
    disk++;
    if(disk>=io->number_of_elements) {
      disk=0;
      slot++;
    };

    if(slot>=io->number_of_slots) break;
  };

  //Now we check to see if all the blocks have been covered.
  for(j=0;j<blocks;j++) {
    if(!io->map[j].disk) 
      RAISE(E_IOERROR,NULL,"Raid map did not account for logical block %u",j);
  };
};

int raid_initialiser(IO_INFO *self,IO_OPT *args) {
  IO_OPT *i;
  IO_INFO_RAID *io=(IO_INFO_RAID *)self;
  
  for(i=args;i;i=i->next) {
    //If we are not given an option=value pair, we interpret the whole
    //thing as a filename:
    if(i->option && (!i->value || strlen(i->value)==0)) {
      add_raid_element(io,i->option);
      continue;
    } else if(CHECK_OPTION(i,file)) {
      add_raid_element(io,i->value);
      continue;
    } else if(!strcasecmp(i->option,"blocksize")) {
      io->block_size=parse_offsets(i->value);
      continue;
    } else if(!strcasecmp(i->option,"header")) {
      io->header_size=parse_offsets(i->value);
      continue;
    } else if(!strcasecmp(i->option,"disks")) {
      io->number_of_elements = atoi(i->value);
      if(!io->number_of_slots) io->number_of_slots=io->number_of_elements;
      fprintf(stderr, "Set number of disks to %u\n", io->number_of_elements);
      continue;
    } else if(!strcasecmp(i->option,"slots")) {
      io->number_of_slots=atoi(i->value);
      fprintf(stderr, "Set number of slots to %u\n", io->number_of_slots);
      continue;
    } else if(!strcasecmp(i->option,"map")) {
      io->map_string=strdup(i->value);
      continue;
    } else if(!strcasecmp(i->option,"offset")) {
      io->offset=parse_offsets(i->value);
      continue;
    };

    // If we get here we did not recognise this option, raise an
    // error:
    RAISE(E_GENERIC,NULL,"option %s not recognised",i->option);
  };
  return(0);
};

int raid_open(IO_INFO *self) {
  IO_INFO_RAID *io=(IO_INFO_RAID *)self;
  struct raid_element *tmp_element=io->disks;
  int parity=0;

  io->logical_blocks_per_period = (io->number_of_elements-1) * (io->number_of_slots);

  if(!io->block_size) RAISE(E_IOERROR,NULL,"Block size is not set");

  if(!tmp_element || io->number_of_slots==0 || io->number_of_elements==0) RAISE(E_IOERROR,NULL,"No disks or no slots specified");

  //Parse the map from the provided map string
  if(!io->map_string) RAISE(E_IOERROR,NULL,"No Raid Map specified");
  if(!io->map) parse_map(io);

  while(tmp_element) {
    tmp_element->fd=open(tmp_element->name,O_RDONLY);
    if(tmp_element->fd<0) {
	    //RAISE(E_IOERROR,NULL,"Could not open file %s",tmp_element->name);
	    fprintf(stderr,"Could not open file %s, marking as missing\n",tmp_element->name);
	    parity++;
	    if(parity>1) RAISE(E_IOERROR,NULL,"More than one disk is missing, currently only RAID 5 with 1 parity disk supported.\n");
    }
    tmp_element=tmp_element->next;
  };

  self->ready=1;
  return(1);
};

int raid_close(IO_INFO *self) {
  IO_INFO_RAID *io=(IO_INFO_RAID *)self;
  struct raid_element *tmp_element=io->disks;

  while(tmp_element) {
    if(tmp_element->fd != -1)
	close(tmp_element->fd);
    tmp_element=tmp_element->next;
  };
  return(1);
};

// reads len bytes from the raid set IO source starting from offset
// offs. This function will not read accross block boundary, so if the
// required read straddles a block, we simply return the number of
// chars read. We then expect to be called again to do the next part
// of the read.
int raid_slack_read(IO_INFO_RAID *io, char *buf, int len, off_t offs) {
  off_t logical_block,relative_offs,physical_block,period_number,relative_logical_block;
  int slot,len_to_read,fd;

  //Correct offs to the array defaults:
  offs+=io->offset;

  logical_block = (unsigned long long int)(offs/io->block_size);
  relative_offs = (offs - logical_block*io->block_size);
  period_number = (unsigned long long int)(logical_block/io->logical_blocks_per_period);
  //The relative logical block within the period:
  relative_logical_block=(unsigned long long int)(logical_block-period_number*io->logical_blocks_per_period);
  
  //The correct slot to find the block in (looked up from the map).
  slot=io->map[relative_logical_block].slot;
  physical_block=slot+period_number*io->number_of_slots;

  //  printf("slot=%u(%llu) disk= %u relative_logical_block=%u relative_offs %llu\n",slot,physical_block, io->map[relative_logical_block].disk->number, relative_logical_block,relative_offs);

  len_to_read = min (len, io->block_size-relative_offs);
  fd=io->map[relative_logical_block].disk->fd;

  //Handle the case where we need to reconstruct a disk:
  if(fd==-1) {
	  char temp_buf[len_to_read+10];
	  struct raid_element *i;
	  int j;

	  memset(buf,0,len);

	  for(i=io->disks;i;i=i->next) {
		if(i->fd != -1) {
  			//grab the other blocks and generate the missing one
			  if(lseek(i->fd,io->header_size+physical_block * io->block_size+relative_offs,SEEK_SET)<0) {
			    RAISE(E_IOERROR,NULL,"Could not seek\n");
		  	};

			  if(read(i->fd,temp_buf, len_to_read) != len_to_read) {
			    RAISE(E_IOERROR,NULL,"Unable to read %u from file %s at offset %llu\n",len_to_read,io->map[slot].disk->name,physical_block * io->block_size+relative_offs);
			  };
			  for(j=0;j<len_to_read;j++) buf[j]^=temp_buf[j];
		};
	  };
  } else {
 //this is the normal case

  if(lseek(fd,io->header_size + physical_block * io->block_size+relative_offs,SEEK_SET)<0) {
    RAISE(E_IOERROR,NULL,"Could not seek\n");
  };

  if(read(fd,buf, len_to_read) != len_to_read) {
    RAISE(E_IOERROR,NULL,"Unable to read %u from file %s at offset %llu\n",len_to_read,io->map[slot].disk->name,physical_block * io->block_size+relative_offs);
  };
  }

  return(len_to_read);
};

int raid_read_random(IO_INFO *self, char *buf, int len, off_t offs,
		     const char *comment)
{
    IO_INFO_RAID *io=(IO_INFO_RAID *)self;
    int result,read_len=0;

    if(!self->ready && self->open(self)<0) return(-1);

    while(len>0) {
      TRY {
	result=raid_slack_read(io,buf,len,offs);
      } EXCEPT (E_IOERROR) {
	return(read_len);
      };
      
      read_len+=result;
      len-=result;
      buf+=result;
      offs+=result;
    };

    return(read_len);
}

/********************************************
 *      Remote Access subsystem 

 *    This subsystem is used to access a machine over the network to
 *    do remote analysis of its hard disk. There are two ways of using this:

1. The remote machine must have an ssh server installed, and the remote server program somewhere on the path. This method encrypts and authenticates access. The subsystem will call ssh to create a tunnel between the analysis machine and the remote server.

2. The remote server will be listening over TCP in a certain port. Note that this provides *NO* Encryption or authentication.

*****************************************/
struct IO_INFO_REMOTE {
  IO_INFO io;
  long long unsigned int offset;
  char *remote_server_path;
  char *remote_raw_device;
  char *username;
  struct remote_handle *hndl;
};

typedef struct IO_INFO_REMOTE IO_INFO_REMOTE;

void remote_help(void) {
  printf("A remote access subsystem\n");
  printf("This is used to access a remote device on a remote system. It may be invoked using ssh (in which case we have authentication and encryption), or over a TCP/IP link to a remote server.\n\n");
  printf("\toffset=bytes\t\tOffset from the start of the device\n");
  printf("\thost=hostname\t\tHostname of target\n");
  printf("\tuser=name\t\t Username at the remote target to use with ssh. This defaults to root\n");
  printf("\tserver_path=path\t\tPath on the server where we can find the remote server program.\n");
  printf("\tdevice=path\t\tRaw device to make available on the remote system.\n");
};

int remote_read_random(IO_INFO *self, char *buf,int len, off_t offs,
		    const char *comment) {
  IO_INFO_REMOTE *io=(IO_INFO_REMOTE *)self;
  char *data=NULL;

  offs+=io->offset;

  remote_read_data(io->hndl,offs,&data,&len);
  memcpy(buf,data,len);
  free(data);
  return(len);
};

int remote_initialiser(IO_INFO *self,IO_OPT *args) {
  IO_OPT *i;
  IO_INFO_REMOTE *io=(IO_INFO_REMOTE *)self;

  //Set some defaults
  io->username="root";
  io->remote_server_path="remote_server";
  io->remote_raw_device="/dev/hdc";
  io->hndl = NEW(struct remote_handle);
  io->hndl->host="localhost";

  for(i=args;i;i=i->next) {
    if(CHECK_OPTION(i,offset)) {
      io->offset=parse_offsets(i->value);
      continue;
    } else if(CHECK_OPTION(i,host)) {
      io->hndl->host = strdup(i->value);
      continue;
    } else if(CHECK_OPTION(i,port)) {
      io->hndl->port = atoi(i->value);
      continue;
    } else if(CHECK_OPTION(i,server_path)) {
      io->remote_server_path = strdup(i->value);
      continue;
    } else if(CHECK_OPTION(i,device)) {
      io->remote_raw_device=strdup(i->value);
      continue;
    } else if(CHECK_OPTION(i,user)) {
      io->username=strdup(i->value);
      continue;
    };

    // If we get here we did not recognise this option, raise an
    // error:
    RAISE(E_GENERIC,NULL,"option %s not recognised",i->option);
  };
  return(0);
};

int remote_open(IO_INFO *self) {
  IO_INFO_REMOTE *io=(IO_INFO_REMOTE *)self;
  char *argv[8];

  //We formulate the argvs we need for invoking the server:
  argv[0]="ssh";
  argv[1]="-l";
  argv[2]=io->username;
  argv[3]=io->hndl->host;
  argv[4]=io->remote_server_path;
  argv[5]=io->remote_raw_device;
  argv[6]=0;

  remote_open_server(io->hndl, argv);
  return(0);
};

int remote_close(IO_INFO *self) {
  IO_INFO_REMOTE *io=(IO_INFO_REMOTE *)self;

  printf("Trying to kill process %u\n",io->hndl->pid);
  kill(io->hndl->pid,SIGTERM);
  return(0);
};

/* These serve as classes (i.e. templates which each object
   instantiates). */
static IO_INFO subsystems[] ={
  { "standard","Standard Sleuthkit IO Subsystem",sizeof(IO_INFO_STD),&io_constructor,&free, 
    &std_help, &std_initialiser,  &std_read_random,  &std_open,  &std_close,0},

  { "advanced","Advanced Sleuthkit IO Subsystem",sizeof(IO_INFO_ADV),&io_constructor,&free,
    &adv_help, &adv_initialiser, &adv_read_random, &adv_open, &adv_close,0},

  { "sgzip","Seekable Gzip format",sizeof(IO_INFO_SGZ),&io_constructor,&free,  
    &sgz_help, &sgz_initialiser, &sgz_read_random, &sgz_open, &sgz_close,0},
  
  { "ewf","Expert Witness Compression format",sizeof(IO_INFO_EWF),&io_constructor,&free,  
    &ewf_help, &ewf_initialiser, &ewf_read_random, &ewf_open, &ewf_close,0},

  { "raid","Raid 5 implementation",sizeof(IO_INFO_RAID),&io_constructor,&free,  
    &raid_help, &raid_initialiser, &raid_read_random, &raid_open, &raid_close,0},

  { "remote","Remote Access Manipulation",sizeof(IO_INFO_REMOTE),&io_constructor,
    &free,&remote_help,&remote_initialiser, &remote_read_random,&remote_open, &remote_close,0},

  //Sentinel
  { NULL, NULL, 0, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL }
  };

// Constructor for io_opts
IO_OPT *new_io_opt() {
  IO_OPT *result;

  result=NEW(IO_OPT);
  if(!result) RAISE(E_NOMEMORY,NULL,"Malloc");
  result->option=NULL;
  result->value=NULL;
  result->next=NULL;
  return(result);
};

void io_parse_options(IO_INFO *io_obj,char *opts) {
  char *x,*y,*z;
  char *temp=strdup(opts);
  IO_OPT *io=NULL;
  IO_OPT *options=NULL;

  if(!strcasecmp(opts,"help")) {
    io_obj->help();
    return;
  };

  z=temp;
  while(1) {
    // Find the next comma:
    y=index(z,',');
    if (y) *y='\0';
    
    //Now find the = sign
    x=index(z,'=');
    
    if(x) {
      *x='\0';
      x++;
    };
    
    //Go to the end of the opts list
    if(options) {
      for(io=options;io->next;io=io->next);
      io->next=new_io_opt();
      io=io->next;
    } else {
      options=new_io_opt();
      io=options;
    };
    io->option=z;
    io->value=x;
    if(!y) break;
    z=y+1;
  };
  //Call the initialiser with those args:
  io_obj->initialise(io_obj,options);
};

int io_close(IO_INFO *self) {
  return(self->close(self));
};

void io_help(char *name) {
  int i;

  for(i=0;subsystems[i].name;i++) {
    if(!strncasecmp(subsystems[i].name,name,strlen(subsystems[i].name))) {
      subsystems[i].help();
      return;
    };
  };

  printf("Available Subsystems:\n\n");
  /* Print a list of subsystems to let the user know which ones are
     available: */
  for(i=0;subsystems[i].name;i++) {
    printf("\t%s - %s\n",subsystems[i].name,subsystems[i].description);
  };
};

/* Selects the requested subsystem.

Returns 0 for success, -1 for failure
*/
IO_INFO *io_open(char *name) {
  IO_INFO *io=NULL;
  int i=0;

  for(i=0;subsystems[i].name;i++) {
    if(!strncasecmp(subsystems[i].name,name,strlen(subsystems[i].name))) {
      io=&(subsystems[i]);
    };
  };

  if(io) {
    //Create a new instance
    io=io->constructor(io);
    return(io);
  };

  if(!strcmp(name,"help")) {
    io_help(name);
  };

  RAISE(E_IOERROR,NULL,"No such IO subsystem: %s",name);
  return(NULL);
};

/* Parses the string for a number. Can interpret the following suffixed:

  k - means 1024 bytes
  M - Means 1024*1024 bytes
  S - Menas 512 bytes (sector size)
*/
long long unsigned int parse_offsets(char *string) 
{
  long long unsigned int result=0;
  int multiplier=1;
  int offs=0;
  
  result=atoll(string);
  offs = strcspn(string,"KkMmSs");

  if(offs) {
    switch(string[offs]) {
    case 'K':
    case 'k':
      multiplier=1024;
      break;
    case 'm':
    case 'M':
      multiplier=1024*1024;
      break;
    case 'S':
    case 's':
      multiplier=512;
      break;
    };
  };

  return(multiplier*result);
};
