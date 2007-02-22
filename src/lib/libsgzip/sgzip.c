#include "sgzlib.h"
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>

/* Prints usage information for sgzip */
void usage(void) {
  printf("sgzip - A seekable compressed format\n");
  printf("(c) 2004\n");
  printf("usage: sgzip [file1] [file2]\n");
  printf("  -d --decompress\tdecompress\n");
  printf("  -h --help\t\tgive this help\n");
  printf("  -R --rebuild file\tRebuilds the Index on this compressed file\n");
  printf("  -b --benchmark file\tbenchmarks file and file.sgz\n");
  printf("  -B --block blocksize\tSet the blocksize for created files (in kilobytes)\n");
  printf("  -L --license\t\tdisplay software license\n");
  printf("  -v --verbose\t\tverbose mode\n");
  printf("  -V --version\t\tdisplay version number\n");
  printf("  -# (0-9)\t\tCompression level (0=no compression). Default is 1\n");
  printf("  file... files to (de)compress. If none given, use standard input/output.\n");
};

void license(void)
{
  printf( " sgzip - A seekable compressed storage format\n\
Type sgzip -h for help.\n\
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

void compress_file(char *filename, int blocksize) {
  // These are the defaults if filename is not supplied.
  int fd=0;
  int outfd=1;
  SgzipFile sgzip;
  char *out_filename;
  
  // Make a local copy for memory allocations.
  filename = talloc_strdup(NULL,filename);

  if(strcmp(filename, "-") || filename==NULL) {
    // Make up the output filename:
    out_filename = talloc_asprintf(filename, "%s.sgz", filename);
    outfd = open(out_filename, O_CREAT|O_WRONLY|O_TRUNC|O_BINARY,S_IRWXU);
    if(outfd<0) {
      raise_errors(EIOError, "Unable to open file %s for writing\n" , out_filename);
      goto error;
    };
    
    fd = open(filename, O_RDONLY);
    if(fd<0) {
      raise_errors(EIOError, "Cant open %s for reading\n", filename);
      goto error;
    };
  };
  
  sgzip = CONSTRUCT(SgzipFile, SgzipFile, CreateFile, filename, outfd, blocksize);
  while(1) {
    char buff[BUFF_SIZE];
    int len;
    
    len = read(fd, buff, BUFF_SIZE);
    if(len==0) break;
    CALL(sgzip, append, buff, len);
  };

 error:
  // Remove the file (this should close it all off):
  talloc_free(filename);
  fprintf(stderr, "%s" , _error_buff);
};

void decompress_file(char * filename ) {
  // These are the defaults if filename is not supplied.
  int outfd=1;
  SgzipFile sgzip;
  char *out_filename = talloc_strdup(NULL, filename);

  if(strlen(filename)<4 || strncasecmp(filename+strlen(filename)-4,".sgz",4)) {
    raise_errors(EIOError,"File %s does not have correct extension (.sgz)\n",filename+strlen(filename)-4);
    goto error;
  };

  // Try to open the file
  sgzip = CONSTRUCT(SgzipFile, SgzipFile, OpenFile, out_filename, filename);
  if(!sgzip) {
    goto error;
  };

  //Lose the extension on the filename
  out_filename[strlen(filename)-4]=0;
  //Make sure we do not trash anything
  outfd = open(out_filename,O_EXCL|O_CREAT|O_WRONLY|O_TRUNC|O_BINARY,S_IRWXU);
  if(outfd<0) {
    if(errno==EEXIST) {
      raise_errors(EIOError, "Pathname already exist, please remove %s. I will not overwrite a file!\n",out_filename);
    } else {
      raise_errors(EIOError, "Cant create file %s\n",out_filename);
    };

    goto error;
  };

  // Now decompress the file into the output:
  while(1) {
    char buff[BUFF_SIZE];
    int len;

    len = CALL(sgzip, read, buff, BUFF_SIZE);
    if(len==0) break;
    if(len<0) goto error;
    write(outfd, buff,len);
  };

  return;
 error:
  // Remove the file (this should close it all off):
  talloc_free(out_filename);
  fprintf(stderr, "%s" , _error_buff);
};

int main(int argc, char **argv) {
  char c;
  // 'c' for compress, 'd' for decompress
  char mode='c';
  int level;
  int verbose;
  int blocksize=32*1024;

  //Parse all options
  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"license", 1, 0, 'L'},
      {"help", 0, 0, 'h'},
      {"list",1,0,'l'},
      {"benchmark",1,0,'b'},
      {"rebuild",1,0,'R'},
      {"block",1,0,'B'},
      {"decompress",1,0,'d'},
      {"verbose", 0, 0, 'v'},
      {0, 0, 0, 0}
    };
    
    c = getopt_long(argc, argv,
		    "hdLvb:l:R:B:0123456789",
		    long_options, &option_index);
    if (c == -1)
      break;
    
    switch (c) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9': {
      char tmp[]="\0\0\0";
      tmp[0]=c;
      level = atoi(tmp);
      break;
    };

    case 'v':
      verbose++;
      break;

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
      break;

    case 'B':
      blocksize = atol(optarg)*1024;
      break;

#if 0
    case 'l':
      {
	char *filename=optarg;
	char temp[5];
	int fdin,count;
	int flag=0;
	uint64_t *index,*derived_index;

	fdin=open(filename,O_RDONLY|O_BINARY);
	if(fdin<0) die(Open,filename);

	sgzip->header=sgzip_read_header(fdin);
	if(!sgzip->header) die(Open,filename);
	memcpy(temp,sgzip->header->x.compression,4);
	temp[4]=0;
	 
	printf(" Blocksize=%u Compression Engine=%s, ",sgzip->header->blocksize,temp);
	index=sgzip_read_index(fdin,sgzip);
	for(count=1;index[count];count++)
	  debug(1,"\n     Block %u is at offset %llu",count,index[count]);
	debug(1,"\n");

	printf(" Index size %u entries ",count);
	if(!index) {
	  printf(" No index ");
	} else {
	  //This is needed in order to seek into the correct place in the file
	  sgzip->header=sgzip_read_header(fdin);
	  derived_index=sgzip_calculate_index_from_stream(fdin,sgzip);
	  
	  //Iterate over all indexes to see if they are the same
	  for(count=1;index[count]!=0 && derived_index[count]!=0; count++) {
	    if(index[count]!=derived_index[count]) {
	      printf(" Incorrect Index ");
	      debug(1," ( block %u has Read %llu, Derived %llu) ",count,index[count],derived_index[count]);
	      flag=1;
	      break;
	    };
	  };
	  if(!flag) {
	    printf(" Correct Index ");
	  };
	};
	printf("\n");
	exit(0);
	break;
      };

    case 'R': //Rebuild index
      {
	char *filename=optarg;
	uint64_t *index;
	int fdin;

	fdin=open(filename,O_RDWR|O_BINARY);
	if(fdin<0) die(Open,filename);

	sgzip->header=sgzip_read_header(fdin);
	index=sgzip_calculate_index_from_stream(fdin,sgzip);
	sgzip_write_index(fdin,index+1);
	close(fdin);
      };
#endif

    default:
      exit(0);
    }
  };

  /* Get our filenames */
  if (optind < argc) {
    while (optind < argc) {
      if(mode == 'c') {
	compress_file(argv[optind++], blocksize);
      } else {
	decompress_file(argv[optind++]);
      };
    };
  } else {  //No args given
    compress_file(NULL, blocksize);
  };

  return(0);
};
