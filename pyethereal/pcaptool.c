#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <glib.h>
#include "wiretap.h"
#include <unistd.h>

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
        printf("INSERT INTO `%s` VALUES (%lu,%lu,%u,%lu,%lu,%u);\n", tableName, packet_id, data_offset,(int) wth->phdr.caplen,(long unsigned int)wth->phdr.ts.tv_sec,(long unsigned int)wth->phdr.ts.tv_usec,wth->phdr.pkt_encap);
        packet_id++;
      }
      file_id++;
      wtap_close(wth);
    }
  }
  return (0);
}
