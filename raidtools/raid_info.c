#include <stdio.h>
#include <ctype.h>
#include "except.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

static char* version="0.1";
static char* tbl_name=" table ";

struct raid_element {
  FILE *fd;
  char *name;
  long long int offset;
  struct raid_element *next;
} raid;

struct raid_element *new_raid_element() {
  struct raid_element *tmp = (struct raid_element *)malloc(sizeof(struct raid_element));
  tmp->next = 0;
  tmp->fd = 0;
  tmp->offset = 0;
  return (tmp);
};

static int end=600000000;
static int blocksize=1024;
static int max_dev=1024;
static int start=193904640;

//We use this as the largest unit we can xor on this CPU in one instruction.
typedef unsigned int xor_unit;

//Check to see if the current offset set represented in the raid linked list verifies through the raid checksum. Returns 0 if it does not verify, and 1 if it does.
int checksum(char *cs_buffer) {
  struct raid_element *i = &raid;
  int j=1;
  xor_unit initial_cs=0;

  //Note that we are casting to xor_unit sizes to perform 32 bit comparisons at once.
  xor_unit itmp_buf;

  //Seek all filedescriptors to the right place, and do the checksum for the very first position.
  for(i=&raid; i->next; i=i->next) {
    fseek(i->fd , i->offset, SEEK_SET);
    fread(&itmp_buf,1,sizeof(xor_unit),i->fd);
    initial_cs ^= itmp_buf;
  };

  //Iterate over all the bytes in the block...
  for(j=0; j<blocksize/sizeof(xor_unit);j++) {
    xor_unit checksum = 0;
    //Calculate the checksum for each byte
    for(i=&raid; i->next; i=i->next) {
      fread(&itmp_buf,1,sizeof(xor_unit),i->fd);
      checksum ^= itmp_buf;
    };

    if(checksum != initial_cs) return(0);
  };

  return(1);
};

//We return 0 if we cant advance the element, 1 if operation was successful
int advance_raid_element(struct raid_element *element) {
  element->offset += blocksize;
  if (element->offset > start+blocksize*max_dev) {
    element->offset = start-blocksize*max_dev;
    if(!element->next) return(0);
    advance_raid_element(element->next);
    printf("Advancing %llu %llu %llu\n ", raid.offset,raid.next->offset,raid.next->next->offset);
  };
  return(1);
};

/* 
   Given an offset and a filehandle, seeks to it and determines if the block is text.

   Offset is specified in block size */
int text_block(long long int offset, FILE *file) {
  char buf[blocksize];
  int i;

  fseek(file,offset*blocksize,SEEK_SET);
  fread(buf,blocksize,1,file);
  for(i=0; i<blocksize; i++) {
    if(!isprint(buf[i])) {
      return(0);
    };
  };

  return(1);
};

/* Checks if the pointed to block contains a uniform byte array (i.e. all the same byte).
   offset is specified in block size, and refers to the block offset into the file.

   return 1 if its uniform, 0 if its not */
int uniform(long long int offset, FILE *file) {
  xor_unit initial,temp;
  int i;

  fseek(file,offset*blocksize,SEEK_SET);
  fread(&initial,1,sizeof(xor_unit),file);
  for(i=0; i<blocksize/sizeof(xor_unit)-1;i++) {
    fread(&temp,1,sizeof(xor_unit),file);
    if(temp != initial) {
      //      printf("Block %u not uniform at %u\n ",offset,i);
      //fflush(stdout);
      return(0);
    };
  };
  
  return(1);
}
/* This function locates which disk the parity is on.
 offset is a number of blocks into the disk to test. Note that individual disk offsets are taken into account through the raid linkes list already.

 Returns the number of the disk where the parity is probably on. (Note this is not a definite answer its just a high probability. returns -1 if we cant tell. */
int locate_parity(long long int offset) {
  struct raid_element *i;
  int text_num =0;
  int non_text_num =0;
  int result = 0;
  int count = 0;

  for(i=&raid; i->next; i=i->next) {
    //If one of the blocks is blank, we cant tell where the parity is so we give up.
    if(uniform(offset,i->fd)) {
      return(-1);
    } else if(text_block(offset,i->fd)) {
      text_num++;
    } else {
      non_text_num++;
      result = count;
    };

    count++;
  };

  //If the number of non-text blocks is exactly 1, its likely to be the parity.
  if(non_text_num == 1) {
    printf("insert into %s set offset='%llu',disk='%u';\n",tbl_name,offset,result);
    return(result);
  };
  return(-1);
};

#define TEMPSIZE 512
void map_parity(long long int offset) {
  struct raid_element *i = &raid;
  int flag = 0;
  int k = 0;
  char line[TEMPSIZE];
  memset(line,' ',TEMPSIZE-1);
  do {
    if(text_block(offset,i->fd)) {
      k+=snprintf(line+k,40," %s: t%u ",i->name,(int)(offset/blocksize));
      flag=1;
    } else {
      k+=snprintf(line+k,40," %s: ****** ",i->name);
    }
    i = i->next;
  } while(i->next);

  if(flag) {
    line[k+1]=0;
    printf("%s\n",line);
  };
};

void usage(char *myProg) {
	printf("usage: raidtools [options] image_name image_name image_name ...\n");
	printf("\timage_name is a path to a dd image of a disk from a raid set\n");
	printf("\t-v: verbose output to stderr\n");
	printf("\t-t: output table name\n");
	printf("\t-p: Analyse parity across the disks\n");
	printf("\t-h: Find headers before each raid disk\n");
	printf("\t-V: Print version\n");
    	printf("\t-d (create|drop): Print create or drop table strings\n");
	exit(1);
}

void print_version(void) {
  printf("Version %s",version);
};

enum action { NONE,LOCATE_PARITY,FIND_HEADERS };

int main(int argc, char **argv) {
  int i;
  struct raid_element *j = &raid;
  char cs_buffer[blocksize];
  char ch;
  extern char *optarg;
  extern int optind;
  enum action act=NONE;

  //Start off by nulling the raid list:
  bzero(j,sizeof(*j));

  /* Getopt option parsing */
  while ((ch = getopt(argc, argv, "t:phVf:")) > 0) {
    switch (ch) {
    case '?':
    default: 
      usage(argv[0]);
    case 't':
      tbl_name = optarg;
      break;
    case 'p':
      act=LOCATE_PARITY;
      break;
    case 'h':
      act=FIND_HEADERS;
      break;
    case 'V':
      print_version();      
      exit(0);
      break;
    }
  }

  while(optind<argc) {
    fprintf(stderr,"Got file %s\r\n",argv[optind]);
    // Got to the end of the raid list:
    for(j=&raid; j->next; j=j->next);
    j->fd = fopen(argv[optind],"r");
    if(!j->fd) {
      perror("Could not open filename");
      exit(-1);
    };
    
    j->offset = start;
    j->name = argv[optind];
    j->next = new_raid_element();
    j=j->next;
    optind++;
  };

  if(act==LOCATE_PARITY){
    for(i=start/blocksize;i<end/blocksize;i++) {
      locate_parity(i);
    };
    exit(0);
  } else if(act==FIND_HEADERS){
    //This is the largest int
    unsigned long long int min_offset= -1;
    
    while(!checksum(cs_buffer) && advance_raid_element(&raid));

    //Find the minimum offset
    for(j=&raid; j->next; j=j->next){
      if(j->offset<min_offset) min_offset=j->offset;
    };
    
    min_offset-=blocksize*max_dev;

    //Reset the relative offsets so that the minimum is max_dev blocks:
    for(j=&raid; j->next; j=j->next){
      j->offset-=min_offset;
    };
    printf("Minimum offset is %llu\n",min_offset);

    //Advance the offsets backwards until the checksums stop working
    while(checksum(cs_buffer)) {
      for(j=&raid; j->offset>0 && j->next; j=j->next) {
	j->offset-=blocksize;	
      };
      if(j->offset <= 0) break;
      printf("Testing block %llu\n",raid.offset);
    };

    //Print out the result:
    for(j=&raid; j->next; j=j->next)
      printf("Disk %s has offset %llu\n",j->name,j->offset);

    exit(0);
  } else if(act==NONE) {
    usage(0);
    exit(0);
  };
  exit(0);
};
