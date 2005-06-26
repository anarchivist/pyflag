#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <glib.h>
#include "wiretap.h"
#include <unistd.h>

struct packet_data_t {
  long unsigned int packet_id;
  long unsigned int data_offset;
  int caplen;
  long unsigned int sec;
  long unsigned int usec;
  int encap;
};

#define MAX_BUFF_SIZE 1024

static struct packet_data_t buffer[MAX_BUFF_SIZE+1];
static int buffer_count=0;

void print_buffer(tableName) {
  int i;
  struct packet_data_t *p=buffer;

  printf("INSERT INTO `%s` VALUES (%lu,%lu,%u,%lu,%lu,%u)",tableName,
	 p->packet_id, p->data_offset, p->caplen,p->sec,p->usec,p->encap);

  for(i=1;i<buffer_count;i++) {
    p=&buffer[i];

    printf(",(%lu,%lu,%u,%lu,%lu,%u)", 
	   p->packet_id, p->data_offset, p->caplen,p->sec,p->usec,p->encap);
  };
  printf(";\n");
};

void printUsage() {
  printf ("\nUSAGE: $ ./pcap_parse -t tablename [-c] inputfile [inputfile]...\n");
  printf ("-c: create new tables before insertion\n\n");
}

int main(int argc, char **argv) {
  wtap  *wth;
  int err=0;
  gchar *err_info;
  char *fname=NULL;
  long unsigned int data_offset;
  long unsigned int packet_id = 0;
  int file_id = 0;
  int createNewTable = 0;
  char *tableName = NULL;
  int index, c;

  while ((c = getopt (argc, argv, "t:c")) != -1) {
    switch(c) {
    case 'c':
      createNewTable = TRUE;
      break;
    case 't':
      tableName = optarg;
      break;
    default:
      printUsage();
      exit(0);
    };
  };

  if ((argc < 2) || (tableName == NULL)) {
    printUsage();
    exit(0);
  }

  if (createNewTable == TRUE) {
    /* will prob need to do some validation of tableName */
    printf ("CREATE TABLE `%s` ( \n", tableName);
    printf ("  `id` INT NOT NULL , \n");
    printf ("  `offset` INT NOT NULL , \n");
    printf ("  `length` INT NOT NULL , \n");
    printf ("  `ts_sec` INT NOT NULL , \n");
    printf ("  `ts_usec` INT NOT NULL, \n");
    printf ("  `link_type`  TINYINT not null\n");
    printf ("); \n\n");

    exit(0);
  }

  /* If there's an error with an input file, print an error and then
     try the next file */
  for (index = optind; index < argc; index++) {
    fname = argv[index];
    wth = wtap_open_offline(fname, &err, &err_info, FALSE);
    
    if (wth == NULL)
      printf("Problem opening %s. Error code: %i\n", fname, err);
    else {
      while(wtap_read(wth,&err,&err_info,&data_offset)) {
	buffer[buffer_count].packet_id = packet_id;
	buffer[buffer_count].data_offset=data_offset;
	buffer[buffer_count].caplen = (int) wth->phdr.caplen;
	buffer[buffer_count].sec = (long unsigned int)wth->phdr.ts.tv_sec;
	buffer[buffer_count].usec= (long unsigned int)wth->phdr.ts.tv_usec;
	buffer[buffer_count].encap= wth->phdr.pkt_encap;
	buffer_count++;

	if(buffer_count>=MAX_BUFF_SIZE) {
	  print_buffer(tableName);
	  buffer_count=0;
	};
        packet_id++;
      }

      //Get the left over packets in the buffer
      if(buffer_count>0)
	print_buffer(tableName);
      
      file_id++;
      wtap_close(wth);
    }
  }

  return (0);
}
