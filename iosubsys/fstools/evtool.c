/*****************************************************
 * Eye Witness Compression Format Support
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Michael Cohen <scudette@users.sourceforge.net> (C) 2004
 *****************************************************/
#include "libevf.h"
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include "except.h"

#ifndef CYGWIN
#define O_BINARY 0
#endif

// Constant messages:
static char Malloc[]="Cant Malloc\n";
static char Open[]="Cant open %s for reading\n";
extern int evf_verbose;

/* Prints usage information for evftool */
void usage() {
  printf("evtool - Expert Witness Format conversion utility\n");
  printf("(c) 2004\n");
  printf("usage: evftool [options] [file1] [file2]\n");
  printf("  -d --decompress filename\tdecompress into a filename\n");
  printf("  -s --size INT\tSets the approximate size of the output files in bytes. This is only important for compression\n");
  printf("  -c --compress filename\tcompresses stdin into the series of files given by filename (with the last 2 chars replaced with the segment number)\n");
  printf("  -h --help\t\tgive this help\n");
  printf("  -l --list file\tTests index integrity for file and list stats\n");
  printf("  -f --force\t\tIgnore errors and process files anyway - you should have -v with this\n");
  printf("  -L --license\t\tdisplay software license\n");
  printf("  -v --verbose\t\tverbose mode\n");
  printf("  -V --version\t\tdisplay version number\n");
  printf("  file... files to (de)compress. If none given, use standard input/output.\n");
};

void debug(int level,const char *message, ...)
{
	va_list ap;
	if(evf_verbose<level) return;

	va_start(ap, message);
	vfprintf(stderr,message, ap);
	va_end(ap);
};

void license(void)
{
  printf( "evftool - Expert Witness Format conversion utility\n\
Type evftool -h for help.\n\
\n\
Copyright (C) 2004, Michael Cohen\n\
\n\
This program is free software; you can redistribute it and/or modify\n\
it under the terms of the GNU General Public License as published by\n\
the Free Software Foundation; either version 2 of the License, or (at\n\
your option) any later version.\n\
\n\
This program is distributed in the hope that it will be useful, but\n\
WITHOUT ANY WARRANTY; without even the implied warranty of\n\
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU\n\
General Public License for more details.\n\
\n\
You should have received a copy of the GNU General Public License\n\
along with this program; if not, write to the Free Software\n\
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307\n\
USA\n");
};

int main(int argc, char **argv) {
  char c;

  // 'c' for compress, 'd' for decompress
  char mode='c';
  //Default file size is 640mb
  int size=640*1024*1024;
  struct offset_table offsets;
  int i,outfd=1;
  //Should we stop on errors?
  int force=0;
  struct evf_section_header *section=NULL;

  //Initialise the offset table:
  offsets.max_chunk=0;
  offsets.max_segment=1;
  //Allocate one array entry and realloc the rest when we need it
  offsets.files=(unsigned int *)malloc(sizeof(*offsets.files)*2);
  offsets.files[1]=-1;
  offsets.fd=NULL;
  offsets.size=NULL;
  offsets.offset=NULL;
  offsets.section_list=NULL;
  offsets.chunk_size=32*1024;
  *offsets.files=-1;

  //Parse all options
  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"license", 1, 0, 'L'},
      {"size", 1, 0, 'L'},
      {"help", 0, 0, 'h'},
      {"list",1,0,'l'},
      {"compress",1,0,'c'},
      {"verbose", 0, 0, 'v'},
      {0, 0, 0, 0}
    };
    
    c = getopt_long(argc, argv,
		    "hfc:d:Ls:vb:lR:B:",
		    long_options, &option_index);
    if (c == -1)
      break;
    
    switch (c) {
    case 'v':
      evf_verbose++;
      break;
    case 's':
      size=atoi(optarg);
      break;
    case 'f':
      force=1;
      break;
    case 'c':
      //FIXME:
      evf_compress_fds(1024*32,0,strdup(optarg),size);
      exit(0);
    case 'h':
      usage();
      exit(0);
      break;
    case 'L':
      license();
      exit(0);
      break;
    case 'd':
      mode='d';
	if(strcmp(optarg,"-")){
		outfd=open(optarg,O_CREAT|O_WRONLY|O_TRUNC|O_BINARY,S_IRWXU);
	} else outfd=1;
	break;
    case 'l':
      {
	evf_verbose+=10;
	break;
      };
    default:
      exit(0);
    }
  };

  /* Get our filenames */
  if (optind < argc) {
    while (optind < argc) {
      int fd;
      struct evf_file_header *file_header;

      fd=open(argv[optind],O_RDONLY|O_BINARY);
      if(fd<0) RAISE(E_IOERROR,NULL,Open,argv[optind]);
      debug(2,"Openning file %s\n",argv[optind]);

      file_header=evf_read_header(fd);
      
      //Grow the files array so we can fit the segment in it:
      if(offsets.max_segment<file_header->segment) {
	//Amount of additional memory we will need
	int additional_memory=file_header->segment-offsets.max_segment;

	offsets.files=realloc(offsets.files,(file_header->segment+1)*sizeof(*offsets.files));
	if(!offsets.files) RAISE(E_NOMEMORY,NULL,Malloc);

	//Clear off the newly initialised memory
	memset(offsets.files+offsets.max_segment+1,-1,additional_memory*sizeof(*offsets.files));
	//Adjust the maximum size of the array
	offsets.max_segment = file_header->segment;
      };

      //Store the fd in the correct spot within the files array. So we
      //end up with all the segments ordered regardless of which order
      //we opened them in.
      if(offsets.files[file_header->segment]>0) RAISE(E_GENERIC,NULL,"Error, a segment is specified more than once\n");

      offsets.files[file_header->segment]=fd;
      optind++;
      free(file_header);
    };
  } else {
    usage();
  };

  //When we get here we should have all the files opened, and ready to
  //go. So we just check for consistency that we do not have any files
  //that were not specified:
  for(i=1;i<=offsets.max_segment;i++) {
    if(offsets.files[i]<0) {
      if(force) {
	evf_warn("Missing a segment file for segment %u, but will continue anyway as requested\n",i);
	continue;
      };
      RAISE(E_IOERROR,NULL,"Missing a segment file for segment %u",i);
    }
    //Now process each file in order until we build the whole index
    for(section=evf_read_section(offsets.files[i]);section->size>0;section=evf_read_section(offsets.files[i])) {

      //This will update offsets.fds and offsets.offset
      process_section(section,i,&offsets);

      //Go to the next section
      if(lseek(offsets.files[i],section->next,SEEK_SET)<0) {
	RAISE(E_IOERROR,NULL,"Could not seek");
      };
      free(section);
    };
  };

  //Check to see if we are done?
  if(strcasecmp(section->type,"done") && !force) 
    RAISE(E_IOERROR,NULL,"No ending section, Cant find the last segment file\n");

  evf_decompress_fds(&offsets,outfd);
  return(0);
};
