#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern void init_hooker();

void usage(char *prog) {
  printf("\nThis program wraps library calls to enable binaries to operate on images with various formats. NOTE: Ensure that libio_wrap.so is in your LD_LIBRARY_PATH before running this wrapper. \n\n");
  printf("Usage: %s -i subsys -o option -x prog arg1 arg2 arg3...\n",prog);
  printf("\t-i subsys: The name of a subsystem to use (help for a list)\n");
  printf("\t-o optionstr: The option string for the subsystem (help for an example)\n");
  printf("\t-x prog arg1 arg2 ... : The program to execute followed by its args.\n\n");

  exit(0);
};

int main(int argc, char **argv) 
{
  char ch;
  
  while ((ch = getopt(argc, argv, "i:o:x")) > 0) {
    switch (ch) {
    case 'i':
      setenv("IO_SUBSYS",optarg,1);
      if(!strcmp(optarg,"help")) {
	init_hooker();
	exit(0);
      };
      break;

    case 'o':
      setenv("IO_OPTS",optarg,1);
      if(!strcmp(optarg,"help")) {
	init_hooker();
	exit(0);
      };
      break;

    case 'x':
      setenv("LD_PRELOAD","libio_hooker.so",1);
      printf (argv[optind]);
      execvp(argv[optind],&argv[optind]);
      break;
    case '?':
    default: 
      usage(argv[0]);
    };
  };

  //If we get here, just call usage:
  usage(argv[0]);
  return(0);
};
  
