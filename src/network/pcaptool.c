/****************************************************************
   Uses libpcap to parse pcap files and emit SQL to index them.

   We queue up many packets so that we can emit a single SQL insert
   for all of them. Using sql extended insert syntax makes the db
   _much_ faster.
*****************************************************************/
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
#  Version: FLAG  $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>

#define TRUE 1

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

//We start counting packets from one so we are matched to ethereal.
long unsigned int packet_id = 1;
pcap_t *pfh;
char *tableName = NULL;
char *iosource_name=NULL;

void print_buffer(char *tableName) {
  int i;
  struct packet_data_t *p=buffer;

  printf("INSERT INTO `%s` VALUES (Null,'%s',%lu,%u,%lu,%lu,%u)",tableName,iosource_name,
	 p->data_offset, p->caplen,p->sec,p->usec,p->encap);

  for(i=1;i<buffer_count;i++) {
    p=&buffer[i];

    printf(",(Null,'%s',%lu,%u,%lu,%lu,%u)", 
	   iosource_name, p->data_offset, p->caplen,p->sec,p->usec,p->encap);
  };
  printf(";\n");
};

void printUsage() {
  printf ("\nUSAGE: $ ./pcaptool -t tablename [-c] inputfile [inputfile]...\n");
  printf ("-c: create new tables before insertion\n\n");
}


void handler(u_char *data, const struct pcap_pkthdr *header, 
	     const u_char *user_data) {
  FILE *fp = pcap_file(pfh);
  int data_offset = ftell(fp);
  int pkt_encap = pcap_datalink(pfh);
  
  buffer[buffer_count].packet_id = packet_id;
  buffer[buffer_count].data_offset=data_offset - (int) header->caplen;
  buffer[buffer_count].caplen = (int) header->caplen;
  buffer[buffer_count].sec = (long unsigned int)header->ts.tv_sec;
  buffer[buffer_count].usec= (long unsigned int)header->ts.tv_usec;
  buffer[buffer_count].encap= pkt_encap;
  buffer_count++;
  
  if(buffer_count>=MAX_BUFF_SIZE) {
    print_buffer(tableName);
    buffer_count=0;
  };
  packet_id++;
};

int main(int argc, char **argv) {
  char err_info[PCAP_ERRBUF_SIZE];
  char *fname=NULL;
  int file_id = 0;
  int createNewTable = 0;
  int index, c;

  while ((c = getopt (argc, argv, "t:ci:p:")) != -1) {
    switch(c) {
    case 'c':
      createNewTable = TRUE;
      break;
    case 't':
      tableName = optarg;
      break;
    case 'i':
      iosource_name = optarg;
      break;
    case 'p':
      packet_id = atol(optarg);
    default:
      printUsage();
      exit(0);
    };
  };

  if (createNewTable == TRUE) {
    /* will prob need to do some validation of tableName */
    printf ("CREATE TABLE `%s` ("
	    "  `id` INT NOT NULL auto_increment,"
	    "  `iosource` varchar(50), "
	    "  `offset` INT NOT NULL ,"
	    "  `length` INT NOT NULL ,"
	    "  `ts_sec` INT NOT NULL ,"
	    "  `ts_usec` INT NOT NULL,"
	    "  `link_type`  TINYINT not null,"
	    " KEY `id` (`id`)"
	    ");", tableName);

    exit(0);
  }

  if (!tableName || !iosource_name ) {
    printUsage();
    exit(0);
  }
  
  //sleep(10);
  
  /* If there's an error with an input file, print an error and then
     try the next file */
  for (index = optind; index < argc; index++) {
    fname = argv[index];
    pfh = pcap_open_offline(fname, err_info);
    
    if (pfh == NULL) {
      fprintf(stderr,"Unable to open %s as a pcap file: %s. Quitting\n", 
	      fname, err_info);
      exit(-1);
    } else {
      pcap_dispatch(pfh, -1, handler, NULL);

      //Get the left over packets in the buffer
      if(buffer_count>0)
	print_buffer(tableName);
      
      file_id++;
      pcap_close(pfh);
    }
  }

  return (0);
}
