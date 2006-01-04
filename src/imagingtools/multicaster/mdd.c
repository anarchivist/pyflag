#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "except.h"
#include "multicaster.h"

extern void client(struct config_t config);
extern void server(struct config_t config);

void print_version() 
{
  printf("Version %s\n",VERSION);
};

void usage(char *name) 
{
  printf("%s: A multicast imaging tool\n",name);
};

int main(int argc, char **argv) 
{
  char ch;
  char mode=0;
  struct config_t config;
  config.in_filename=NULL;
  config.out_filename=NULL;
  config.server_listening_port=6666;
  config.client_listening_port=6667;
  config.key=md5sum(KEY);
  config.multicast_addr="239.1.1.1";
  config.server_addr=0;
  config.prefered_interface=0;
  config.blocksize=1500;
  config.timeout=100;

   /* Getopt option parsing */
  while ((ch = getopt(argc, argv, "t:pk:cm:shVf:")) > 0) {
    switch (ch) {
    case '?':
    default: 
      usage(argv[0]);
      break;
    case 'm':
      config.multicast_addr=optarg;
    case 't':
      config.timeout=atol(optarg);
      break;
    case 'k':
      free(config.key);
      config.key=md5sum(optarg);
      break;
    case 's':
    case 'c':
      mode=ch;
      break;
    case 'V':
      print_version();      
      exit(0);
      break;
    }
  }

  if(optind<argc) {
    switch(mode) {
    case 'c':
      config.out_filename=argv[optind];
      break;
    case 's':
      config.in_filename=argv[optind];
      break;
    };
  };

  switch(mode) {
  case 'c':
    client(config);
    break;
  case 's':
    server(config);
    break;
  default:
    RAISE(E_GENERIC,NULL,"Mode not selected - select client or server mode");
  }

  return(0);
};
