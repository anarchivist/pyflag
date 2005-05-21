#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <glib.h>
#include <wtap.h>

int main(int argc, char **argv ) {
  wtap  *wth;
  char *table="pcap";
  int err=0;
  gchar *err_info;
  char err_msg[2048+1];
  char *fname="/tmp/test.pcap";
  long data_offset;
  int id=0;
  
  if(argc>1 && !strcmp(argv[1],"-c")) {
    printf("CREATE TABLE `%s` (`id` BIGINT NOT NULL ,`offset` BIGINT NOT NULL ,`length` SMALLINT NOT NULL ,PRIMARY KEY ( `id` ));\n",table);
    exit(0);
  };
  if(argc>1 && !strcmp(argv[1],"-d")) {
    printf("DROP TABLE `%s`;\n",table);
    exit(0);
  };

  wth = wtap_open_offline(fname, &err, &err_info, FALSE);
  while(wtap_read(wth,&err,&err_info,&data_offset)) {
    struct wtap_pkthdr *hdr = wtap_phdr(wth);
    printf("insert into %s set id='%lu',offset='%lu',length='%lu';\n",table,id,data_offset,hdr->caplen);
    id++;
  };
  
  
};
