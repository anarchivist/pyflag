/*
  fdd - The Flag dd utility is a utility similar to the traditional dd
  - in that it reads and writes to files. However the flag version
  fully supports io-subsystems which are supported by flag. This
  allows fdd to read data from comressed images, encase images and
  raid sets.

*/

#include "fs_tools.h"
#include "fs_io.h"
#include "error.h"
#include <ctype.h>
#include "except.h"
#include "fs_io.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


void 
usage(char *myProg)  
{
	printf("usage: %s [opts] [-i IOsubsystem] [[-o] options for subsystem]\n", myProg);
	printf("\t--if,-I: Input file \n");
	printf("\t--of,-O: Output file\n");
	printf("\t--bs,-b: blocksize\n");
	printf("\t-i: select IO Subsystems. Try help for a list of subsystems\n");
	printf("\t-v: verbose output to stderr\n");
	printf("\t-V: display version\n");
	printf("\t--count,-c: number of blocks to read\n");
	printf("\t--skip,-s: number of blocks to skip in the input file\n");
	exit(1);
}

int 
main(int argc, char **argv) 
{
	char ch;
	extern int optind;
	char *io_subsys=NULL;
	char *io_subsys_opts=NULL;
	IO_INFO *io=NULL;
	int blocksize=512;
	int ifd=0;
	int ofd=1;
	unsigned long long int count=-1;
	unsigned long long int skip=0;
	char *buf;
	char s;
	int m=1;

	progname = argv[0];
	
	
	while ((ch = getopt(argc, argv, "I:O:b:i:o:vVc:s:")) > 0) {
	  switch (ch) {
	  case 'I':
	    
	    break;
	  case 'O':
	    ofd=creat(optarg,S_IRWXU);
	    if(ofd<0) RAISE(E_IOERROR,NULL,"Unable to open %s for writing.",optarg);
	    break;
	  case 's':
	    skip=atoll(optarg);
	    break;
	  case 'i':
	    io_subsys=optarg;
	    break;
	  case 'o':
	    io_subsys_opts=optarg;
	    break;
	  case 'b':
	    s=optarg[strlen(optarg)-1];
	    
	    switch(s) {
	    case 'k':
	    case 'K':
	      m=1024;
	      break;
	    case 'm':
	    case 'M':
	      m=1024*1024;
	      break;
	      
	    default:
	      m=1;
	    };
	
	    blocksize=atoi(optarg)*m;
	    break;
	  case 'c':
	    count=atoll(optarg);
	    break;
	  case 'v':
	    verbose++;
	    logfp = stderr;
	    break;
	  case 'V':
	    print_version();
	    exit(0);
	    break;
	  case '?':
	  default:
	    usage(argv[0]);
	  }
	}


	skip *= blocksize;
	
	/* User chose to set the io_subsystem */
	if(io_subsys) {
	  io=io_open(io_subsys);
	} else {
	  /* If the user did not specify a subsystem, we choose the standard one */
	  io=io_open("standard");
	};
	
	if(!io) {
	  error("Could not set io subsystem %s",io_subsys);
	};

	/* Send the options to the subsystem */
	if(io_subsys_opts) {
	  io_parse_options(io,io_subsys_opts);
	};

	//Parse the rest of the args as options to the io filesystem:
	while(optind<argc) {
	    io_parse_options(io,argv[optind++]);
	};

	//Allocate memory for the block:
	buf=(char *)malloc(blocksize);

	while(count>0) {
	  int result;
	  result=io->read_random(io,buf,blocksize,skip,"fdd");
	  write(ofd,buf,result);
	  skip+=result;
	  count--;
	};

	return 0;
}

