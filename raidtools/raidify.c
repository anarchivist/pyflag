#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

/*

This program simulates a raid distribution like:

Disks:  0  1  2  3  4  5  6
---------------------------
S 0     0  1  2  3  4  5  P
  1     P  6  7  8  9 10 11
  2    17  P 12 13 14 15 16
  3    22 23  P 18 19 20 21
  4    27 28 29  P 24 25 26
  5    32 33 34 35  P 30 31
  6    37 38 39 40 41  P 36
*/


#define BUFFSIZE 1024*4

struct raid_element {
  int fd;
  char *name;
  char *data;
  struct raid_element *next;
} *raid;

struct raid_element *new_raid_element() {
  struct raid_element *tmp = (struct raid_element *)malloc(sizeof(struct raid_element));
  tmp->next = 0;
  tmp->fd = 0;
  tmp->data=(char *)malloc(BUFFSIZE+10);
  return (tmp);
};

void usage() {
  printf("Reassemble the raid:\n\tusage:\n\t\treassemble -f outfile file1 file2 .. \n");

};

//Rebuild the raid. out_file_name is the name of the output files. raid is the first raid element in the ring, number_of_elements is the total number of elements in the raid ring (we could figure that out anyway). maximum_file_size is the total size of the output file after which we start a new file.
void raidify(char *in_file_name,struct raid_element *raid,int number_of_elements ) 
{
  int i,j;
  int len=0;
  int infd=open(in_file_name, O_RDONLY);
  char buf[BUFFSIZE+10];

  while(1) {
    memset(buf,0,BUFFSIZE);

    for(i=number_of_elements-1;i>0;i--){
      //Read the next block from this file:
      len=read(infd,raid->data,BUFFSIZE);
      for(j=0;j<BUFFSIZE;j++) {
	buf[j]^=raid->data[j];
      };

      if(len!=BUFFSIZE) perror("read");
      if(len==0) {
	printf("Done reading from %s, exiting...\n",raid->name);
	exit(0);
      } else if(len<0) {
	perror(raid->name);
	exit(-1);
      };

      //Write the data into the output file:
      len=write(raid->fd,raid->data,BUFFSIZE);
      raid=raid->next;
    };

    //    memset(raid->data,'P',BUFFSIZE);
    //This is the parity of the next row we skip that block
    len=write(raid->fd,buf,BUFFSIZE);
    raid=raid->next;
    
    raid=raid->next;
  };
};

int main(int argc, char **argv) {
  char *in_file_name=NULL;
  char ch;
  struct raid_element *j=NULL;
  int number=0;
  //Maximum size in kb
  int max_size=100000;

  raid=new_raid_element();
  
  /* Getopt option parsing */
  while ((ch = getopt(argc, argv, "hf:s:")) > 0) {
    switch (ch) {
    case 'h':
    default: 
      usage(argv[0]);
      return(0);
      break;
    case 's':
      max_size=atoi(optarg);
    case 'f':
      in_file_name=optarg;
      break;
    };
  };
  
  while(optind<argc) {
    fprintf(stderr,"Got file %s\r\n",argv[optind]);
    // Got to the end of the raid list:
    for(j=raid; j->next; j=j->next);
    j->fd = creat(argv[optind],S_IRWXU);
    if(j->fd<0) {
      perror("Could not open filename");
      exit(-1);
    };
    
    j->name = argv[optind];
    j->next = new_raid_element();
    if(optind+1<argc) {
      j=j->next;
    };
    number++;
    optind++;
  };
  
  if(j) {
    //Connect the last element to the first to form a loop:
    j->next=raid;

    raidify(in_file_name,raid,number);
  } else usage(argv[0]);
  return 0;
};
