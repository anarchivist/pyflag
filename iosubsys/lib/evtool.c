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

/* my version of "uncompress" from zlib
   upon entry destLen is size of dest buffer
   upon exit destLen is size copied into dest buffer
       (ie. the uncompressed size)
   upon entry sourceLen is size of source buffer
   upon exit sourceLen is amount consumed from source buffer
       (ie. compressed size)
*/

int myuncompress (dest, destLen, source, sourceLen)
    Bytef *dest;
    uLongf *destLen;
    const Bytef *source;
    uLongf *sourceLen;
{
    z_stream stream;
    int err;

    stream.next_in = (Bytef*)source;
    stream.avail_in = (uInt)*sourceLen;
    /* Check for source > 64K on 16-bit machine: */
    if ((uLong)stream.avail_in != *sourceLen) return Z_BUF_ERROR;

    stream.next_out = dest;
    stream.avail_out = (uInt)*destLen;
    if ((uLong)stream.avail_out != *destLen) return Z_BUF_ERROR;

    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;

    err = inflateInit(&stream);
    if (err != Z_OK) return err;

    err = inflate(&stream, Z_FINISH);
    if (err != Z_STREAM_END) {
        inflateEnd(&stream);
        if (err == Z_NEED_DICT || (err == Z_BUF_ERROR && stream.avail_in == 0))
            return Z_DATA_ERROR;
        return err;
    }
    *destLen = stream.total_out;
    *sourceLen = stream.total_in;

    err = inflateEnd(&stream);
    return err;
}

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

  /* alternate algorithm for processing ewf from stdin
     does so without knowledge of the offsets table etc
     unsure how reliable it is, but worked in basic tests!
          Dave <daveco@users.sourceforge.net>
  */
  if (mode == 'd' && (optind == argc || strcmp(argv[optind],"-") == 0)) {
    int fd;
    struct evf_file_header *file_header;
    int readcount; //keep track of possition in segment
    int done = 0;
    fd = 0; // stdin
    int segcount = 1;
    int chunk_size = 0;
    int total_chunks = 0;
    int chunk_count = 0;

    // process each segment
    while(!done) {
      readcount = 0;
      file_header = evf_read_header(fd);
      readcount += sizeof(*file_header);

      if(file_header->segment != segcount) {
	fprintf(stderr, "Got segment %i, expecting %i, are files in order?\n", file_header->segment, segcount);
	if(!force)
	  exit(0);
      }
      //fprintf(stderr, "reading segment %i from stdin\n", file_header->segment);
      
      // process each section
      int last_section = 0;
      while(!last_section) {

	// read a section header
	section=evf_read_section(fd);
	readcount += sizeof(*section);
	fprintf(stderr, "  reading section: %s size: %lli next: %lli\n", section->type,
		section->size, section->next);

	if(!strncmp(section->type, "volume", strlen("volume"))) {
	  //read in volume header
	  struct evf_volume_header *volume;
	  volume=(struct evf_volume_header *)malloc(sizeof(*volume));
	  if(!volume) RAISE(E_NOMEMORY,NULL,Malloc);
	  
	  if(read_from_stream(fd,volume,sizeof(*volume))<sizeof(*volume)) 
	    RAISE(E_IOERROR,NULL,"Error reading volume header");
	  readcount += sizeof(*volume);

	  total_chunks = volume->chunk_count;
	  chunk_size = volume->sectors_per_chunk * volume->bytes_per_sector;

	  if(chunk_size != 32*1024)
	    fprintf(stderr, "Got unexpected chunk_size: %i\n", chunk_size);
	  free(volume);
	}
	else if(!strncmp(section->type, "sectors", strlen("sectors"))) {
	  // process the actual compressed data

	  int data_size = chunk_size;
	  int cdata_size = chunk_size+1024;
	  char *data, *cdata;
	  data = (char *)malloc(data_size);
	  cdata = (char *)malloc(cdata_size);
	  if(!data || !cdata) RAISE(E_NOMEMORY,NULL,Malloc);

	  int toread; //amount to try and read
	  int result;
	  int compcount = 0; //amount processed so far
	  int uncompcount = 0; //data produced to far
	  int compreadcount = 0; //amount read so far
	  int comp = 0, uncomp = 0; //processed in this loop

	  char *ptr = cdata; //write pointer into cdata buffer

	  /* process the compressed data
	     we dont know how big each compressed chunk is
	     so we have to read more than we need, and then keep rotating 
	     and topping up the compressed buffer as needed until we've
	     read and processed all the compressed data.
	  */
	  int total = section->size - sizeof(*section); //size of this section
	  while(compcount < total) {

	    // rotate the buffer
	    if(comp > 0) {
	      memmove(cdata, (cdata + comp), (cdata_size - comp));
	      ptr = cdata + (cdata_size - comp);
	      toread = comp;
	    }
	    else {
	      // this is the first pass
	      toread = cdata_size;
	    }

	    // make sure we dont read past the end of the section
	    if((compreadcount + toread) > total) {
	      toread = total - compreadcount;
	    }
	    
	    //top up the buffer
	    if(toread > 0) {
	      if(read_from_stream(fd,ptr,toread) < toread)
	      	RAISE(E_IOERROR,NULL,"Error reading sector Data");
	      //fprintf(stderr, "read another %i bytes from stdin\n", toread);
	      readcount += toread;
	      compreadcount += toread;
	    }
	    
	    //uncompress the mofo
	    uncomp = data_size; //set to buffer sizes on input
	    comp = cdata_size;

	    //fprintf(stderr, "uncompressing a block\n");
	    result = myuncompress(data,(long int *)&uncomp,cdata,(long int *)&comp);
	    if(result!=Z_OK) {
	      //fprintf(stderr, "ERROR in myuncompress: %i block: %i\n", result, chunk_count);	      
	      // decompression failed, the chunk is either uncompressed or the data is corrupt
	      // lets assume that the block is uncompressed, and copy it verbatim
	      // If it turns out to be an error, the rest of the image is completely screwed
	      // Whats more there's not a lot you can do about it here!!!
	      // (how much compressed data u gonna skip? ...thought so)
	      // I suppose you could keep a record, then when you get to the table, compare which ones
	      // we think are uncompressed with which ones actually are, then you can at least you
	      // can report the error, but who can be bothered??
	      // OR maby you can keep advancing a pointer by one and trying to decompress until you
	      // sucessfully get 32k out of it, again, too much work, maby another day.
	      memcpy(data, cdata, data_size);
	      comp = uncomp = data_size;
	    }
	    if(uncomp != data_size) {
	      fprintf(stderr, "Probable ERROR: Compression returned unexpected volume %i\n", uncomp);
	    }
	    compcount += comp;
	    uncompcount += uncomp;
	    
	    //fprintf(stderr, "comp: %i uncomp: %i\n", comp, uncomp);
	    //write the output
	    if(write(outfd,data,uncomp)<uncomp) {
	      free(data);
	      free(cdata); 
	      RAISE(E_IOERROR,NULL,"Write failure in decompression");
	    }
	    chunk_count++;
	  }
	  free(data);
	  free(cdata);
	}
	else if(!strncmp(section->type, "done", strlen("done"))) {
	  done = 1;
	}
	
	// move on to next section
	if(readcount < section->next) {
	  if(advance_stream(fd, section->next - readcount) < section->next - readcount)
	    RAISE(E_IOERROR,NULL,"Reached end of stream");
	  readcount = section->next;
	}
	else if(readcount > section->next) {
	  if(readcount == (section->next - sizeof(*section)) || section->size == 0) {
	    // i think this means we're at a 'next' or 'done' section, just continue
	    last_section = 1;
	  }
	  else {
	    //dont know how that happened, but we're screwed now
	    RAISE(E_IOERROR,NULL,"Got too far ahead in stream: %i vs: %i", readcount, section->next);
	  }
	}
	free(section);
      }

      //Check to see if we are done?
      //if(strcasecmp(section->type,"done") && !force) 
      //  RAISE(E_IOERROR,NULL,"No ending section, Cant find the last segment file\n");
      
      free(file_header);
      segcount++;
    }
    if(chunk_count < total_chunks) {
      fprintf(stderr, "only processed %i of %i chunks!\n", chunk_count, total_chunks);
    }
    return(0);
  }

  /* return to the reliable method (where the evt file must be a seekable file) */
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

