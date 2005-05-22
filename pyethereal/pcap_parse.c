#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <glib.h>
#include <wtap-int.h>
#include <wtap.h>
#include <unistd.h>

void printUsage() {
  printf ("\nUSAGE: $ ./pcap_parse -t tablename [-c] inputfile [inputfile]...\n");
  printf ("-c: create new tables before insertion\n\n");
}

int main(int argc, char **argv) {
  wtap  *wth;
  int err=0;
  gchar *err_info;
  //char err_msg[2048+1]; //not needed?
  char *fname=NULL;
  long data_offset;
  int packet_id = 0;
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
      case '?':
        printUsage();
        break;
    };
  };

  if ((argc == 1) || (tableName == NULL) || (strcmp(tableName,"-c") == 0)) {
    printUsage();
    exit(0);
  }

  if (createNewTable == TRUE) {
    /* will prob need to do some validation of tableName */
    printf ("CREATE TABLE `%s` ( \n", tableName);
    printf ("  `file_id` INT NOT NULL , \n");
    printf ("  `packet_id` INT NOT NULL , \n");
    printf ("  `offset` INT NOT NULL , \n");
    printf ("  `length` INT NOT NULL , \n");
    printf ("); \n\n");

    /* Should the name of this table be a command line arg? */
    printf ("CREATE TABLE `filename` ( \n");
    printf ("  `file_id` INT NOT NULL ,\n");
    printf ("  `filename` VARCHAR( 255 ) NOT NULL ,\n");
    printf ("  PRIMARY KEY ( `file_id` )\n");
    printf (");\n\n");

  }

  /* If there's an error with an input file, print an error and then
     try the next file */
  for (index = optind; index < argc; index++) {
    fname = argv[index];
    wth = wtap_open_offline(fname, &err, &err_info, FALSE);

    if (wth == NULL)
      printf("Problem opening %s. Error code: %i\n", fname, err);
    else {
      printf ("INSERT INTO `filename` (`file_id`,`filename`) VALUES (%i, '%s');\n", file_id, fname);
      while(wtap_read(wth,&err,&err_info,&data_offset)) {
        printf("INSERT INTO `%s` (`file_id`,`packet_id`,`offset`,`length`) VALUES (%i,%i,%li,%i);\n", tableName, file_id, packet_id, data_offset, wth->phdr.caplen);
        packet_id++;
      }
      file_id++;
      wtap_close(wth);
    }
  }
  return (0);
} //main
