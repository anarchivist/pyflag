/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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
# ******************************************************
*/
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <getopt.h>
#include "sgzlib.h"
#include <string.h>
#include <errno.h>
#include <except.h>

#ifndef CYGWIN
#define O_BINARY 0
#endif

// Constant messages:
static char Malloc[]="Cant Malloc\n";
static char Open[]="Cant open %s for reading\n";
static struct sgzip_header *header=NULL;
extern int sgz_verbose;

static void die(const char *message, ...)
{
	va_list ap;
	va_start(ap, message);
	vprintf(message, ap);
	va_end(ap);
	exit(-1);
};

/* This harness tests the correctness of the sgzip implementation.

It does this by seeking random locations in both files and reading a
random amount from both files. The test is passed if the result is the
same for both the uncompressed file and the compressed file.

@arg filename: The filename of an uncompressed image size
@arg cfd:   A file descriptor for a compressed file
*/
void test_harness(char *filename,int cfd,unsigned long long int *index,const struct sgzip_header *header) {
  int fd1;
  int offset,count=0;
  int read_size;
  char *data1,*data2;

  fd1=open(filename,O_RDONLY|O_BINARY);
  
  while(1) {
    count++;
    offset= 1+(rand() % 150*header->blocksize);
    read_size = 1+(rand() % (3*header->blocksize));

    data1=(char *)malloc(read_size+1024);
    data2=(char *)malloc(read_size+1024);

    lseek(fd1,offset,SEEK_SET);
    read(fd1,data1,read_size);
    sgzip_read_random(data2,read_size,offset,cfd,index,header);

    if(!memcmp(data1,data2,read_size)) {
      printf("Passed test %u,  read %u bytes from offset %u\n",count,read_size,offset);
    } else {
      printf("Failed test %u\n",count);
    };

    free(data1);
    free(data2);
  };
};

/* Prints usage information for sgzip */
void usage() {
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
  printf("  file... files to (de)compress. If none given, use standard input/output.\n");
};

void debug(int level,const char *message, ...)
{
	va_list ap;
	if(sgz_verbose<level) return;

	va_start(ap, message);
	vprintf(message, ap);
	va_end(ap);
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

/* compress the filename given. Note that unlike gzip, we do not
   unlink the original file!! */
void compress_file(char *filename) {
  int infd=0,outfd=1;
  char *out_filename;

  out_filename=(char *)malloc(strlen(filename)+4);
  if(!out_filename) die(Malloc);
  // For filename of - we use stdin, stdout
  if(strcmp(filename,"-")) {    
    //Make up the new filename
    strcpy(out_filename,filename);
    strcpy(out_filename+strlen(filename),".sgz");
    
    //Open the files
    infd=open(filename,O_RDONLY|O_BINARY);
    if(infd<0) die(Open,filename);
    outfd=open(out_filename,O_CREAT|O_WRONLY|O_TRUNC|O_BINARY,S_IRWXU);
    if(outfd<0) die("Cant create file %s\n",out_filename);
  };

  header=sgzip_write_header(outfd,header);
  sgzip_compress_fds(infd,outfd,header);

  close(infd);
  close(outfd);
  free(out_filename);
};

/* decompress the filename given. Note that unlike gzip, we do not
   unlink the original file!! We do not do anything if the file already exists */
void decompress_file(char *filename) {
  int infd=0,outfd=1;
  char *out_filename;

  // For filename of - we use stdin, stdout
  if(strcmp(filename,"-")) {    
    //Check that the file extension is correct:
    if(strlen(filename)<4 || strncasecmp(filename+strlen(filename)-4,".sgz",4)) {
      die("File %s does not have correct extension (.sgz)\n",filename+strlen(filename)-4);
    };
    
    out_filename=strdup(filename);
    if(!out_filename) die(Malloc);

    //Lose the extension on the filename
    *(out_filename+strlen(filename)-4)=0;
    
    //Open the files
    infd=open(filename,O_RDONLY|O_BINARY);
    if(infd<0) die(Open,filename);
    //Make sure we do not trash anything
    outfd=open(out_filename,O_EXCL|O_CREAT|O_WRONLY|O_TRUNC|O_BINARY,S_IRWXU);
    if(outfd<0) {
      if(errno==EEXIST) die("Pathname already exist, please remove %s. I will not overwrite a file!\n",out_filename);
      die("Cant create file %s\n",out_filename);
    };
  free(out_filename);
  };

  header=sgzip_read_header(infd);
  sgzip_decompress_fds(infd,outfd,header);

  close(infd);
  close(outfd);
};

void handle_file(char *filename,char mode) {
  if(mode=='c') {
    compress_file(filename);
  } else if(mode=='d') {
    decompress_file(filename);
  };
  if(sgz_verbose>0)
    fprintf(stderr,"\r\n");
};

int main(int argc, char **argv) {
  unsigned long long int *index;
  char c;
  // 'c' for compress, 'd' for decompress
  char mode='c';

  //Set the default header
  header=sgzip_default_header();

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
		    "hdLvb:l:R:B:",
		    long_options, &option_index);
    if (c == -1)
      break;
    
    switch (c) {
    case 'v':
      sgz_verbose++;
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
      header->blocksize=atol(optarg)*1024;
      break;
    case 'b':
      // do the benchmark for a file
      {
	char *filename=optarg;
	char *comp_filename;
	int fdin;
	
	//Workout the compressed filename
	comp_filename=(char *)malloc(strlen(filename)+4);
	if(!comp_filename) die(Malloc);

	//Make the new filename
	strcpy(comp_filename,filename);
	strcpy(comp_filename+strlen(filename),".sgz");

	fdin=open(comp_filename,O_RDONLY|O_BINARY);
	if(fdin<0) die(Open,comp_filename);
	header=sgzip_read_header(fdin);
	index=sgzip_read_index(fdin,header);
	test_harness(filename,fdin,index,header);
	break;
      };
    case 'l':
      {
	char *filename=optarg;
	char temp[5];
	int fdin,count;
	int flag=0;
	unsigned long long int *index,*derived_index;

	fdin=open(filename,O_RDONLY|O_BINARY);
	if(fdin<0) die(Open,filename);

	header=sgzip_read_header(fdin);
	if(!header) die(Open,filename);
	memcpy(temp,header->x.compression,4);
	temp[4]=0;
	 
	printf(" Blocksize=%u Compression Engine=%s, ",header->blocksize,temp);
	index=sgzip_read_index(fdin,header);
	for(count=1;index[count];count++)
	  debug(1,"\n     Block %u is at offset %llu",count,index[count]);
	debug(1,"\n");

	printf(" Index size %u entries ",count);
	if(!index) {
	  printf(" No index ");
	} else {
	  //This is needed in order to seek into the correct place in the file
	  header=sgzip_read_header(fdin);
	  derived_index=sgzip_calculate_index_from_stream(fdin,header);
	  
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
	unsigned long long int *index;
	int fdin;

	fdin=open(filename,O_RDWR|O_BINARY);
	if(fdin<0) die(Open,filename);

	header=sgzip_read_header(fdin);
	index=sgzip_calculate_index_from_stream(fdin,header);
	sgzip_write_index(fdin,index+1);
	close(fdin);
      };
    default:
      exit(0);
    }
  };

  /* Get our filenames */
  if (optind < argc) {
    while (optind < argc) {
      handle_file(argv[optind++],mode);
    };
  } else {  //No args given
    handle_file("-",mode);
  };

  return(0);
};
