/*
 * Copyright (C) 2003, by Keith J. Jones.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

//
/* This is the default block size for an activity record */
//
#define BLOCK_SIZE	0x80

char *tbl_name;
char *path;

#ifdef CYGWIN
ssize_t pread( int d, void *buf, size_t nbytes, off_t offset) {
  lseek( d, offset, SEEK_SET );
  read( d, buf, nbytes );
}
#endif

/* print out sql safe string ptr. We will malloc a new buffer and return that (it may be longer than the buffer we got) */
char *print_sql_data(char *ptr) {
  int length;
  char *result;
  int i=0;
  int j=0;

  length = strlen(ptr);
  if (length==0) {
    result=(char *)calloc(10,1);    
  } else {
    result=(char *)calloc(length*2,1);
  };

  for(i=0;i<length;i++) {
    switch(*(ptr+i)) {
    case 0:
      result[j++]='\\';
      result[j++]='0';
      break;
    case '\'':
    case '\"':
      result[j++]='\\';
      result[j++]=*(ptr+i);
      break;
    case '\n':
      result[j++]='\\';
      result[j++]='n';
      break;
    case '\\':
      result[j++]='\\';
      result[j++]='\\';
      break;
    default:
      result[j++]=*(ptr+i);
    };
  };
  result[j]=0;
  return (result);
}

//
/* Backwards ASCII Hex to Integer */
//
unsigned int bah_to_i( char *val, int size ) {
  int total;
  int i;

  total = 0;

  for ( i=0; i < size; i++ ) {
    total += ((unsigned char)val[i] << 8*i);
  }

  return total;
}

//
/* Backwards 8 byte ASCII Hex to time_t */
//
time_t win_time_to_unix( char *val ) {
  unsigned long low, high;
  double dbl;
  time_t total;

  char fourbytes[4]; 

  fourbytes[0] = val[0];
  fourbytes[1] = val[1];
  fourbytes[2] = val[2];
  fourbytes[3] = val[3];

  low = bah_to_i( fourbytes, 4 );

  fourbytes[0] = val[4];
  fourbytes[1] = val[5];
  fourbytes[2] = val[6];
  fourbytes[3] = val[7];

  high = bah_to_i( fourbytes, 4 );

  dbl = ((double)high)*(pow(2,32));
  dbl += (double)(low);

  if ( dbl==0 ) {
    return 0;
  }

  dbl *= 1.0e-7;
  dbl -= 11644473600;

  total = (double)dbl;

  return total;
}

//
/* This function prepares a string for nice output */
//
int printablestring( char *str ) {
  int i;

  i = 0;
  while ( str[i] != '\0' ) {
    if ( (unsigned char)str[i] < 32 || (unsigned char)str[i] > 127 ) {
      str[i] = ' ';
    }
    i++; 
  }
  return 0;
}

//
/* This function parses a REDR record. */
//
int parse_redr( int history_file, int currrecoff, char *delim, int filesize, char *type ) {
  char fourbytes[4];
  char hashrecflagsstr[4];
  char chr;
  int filenameoff;
  int httpheadersoff;
  int i;
  int reclen;
  int dirnameoff;
  time_t modtime;
  time_t accesstime;
  char *url;
  char *filename;
  char *httpheaders;
  char ascmodtime[26], ascaccesstime[26];
  char dirname[9];


  pread( history_file, fourbytes, 4, currrecoff+4 );
  reclen = bah_to_i( fourbytes, 4 )*BLOCK_SIZE; 

  url = (char *)malloc( reclen+1 );
            
  i = 0;
  pread( history_file, &chr, 1, currrecoff+0x10 );
  while ( chr != '\0' && currrecoff+0x10+i+1 < filesize ) {
    url[i] = chr;
    pread( history_file, &chr, 1, currrecoff+0x10+i+1 );
    i++; 
  } 
  url[i] = '\0';

  filename = (char *)malloc( 1 );
  filename[0] = '\0';

  httpheaders = (char *)malloc( 1 );
  httpheaders[0] = '\0';

  dirname[0] = '\0';

  ascmodtime[0] = '\0';
  ascaccesstime[0] = '\0';
  dirname[0] = '\0';

  modtime = 0;
  accesstime = 0;

  printablestring( type );
  printablestring( url );
  printablestring( ascmodtime );
  printablestring( ascaccesstime );
  printablestring( filename );
  printablestring( dirname );
  printablestring( httpheaders );

  char *c_type = print_sql_data( type );
  char *c_url = print_sql_data( url );
  //  char *c_ascmodtime = print_sql_data( ascmodtime );
  //  char *c_ascaccesstime = print_sql_data( ascaccesstime );
  char *c_path = print_sql_data( path );
  char *c_filename = print_sql_data( filename );
  char *c_dirname = print_sql_data( dirname );
  char *c_httpheaders = print_sql_data( httpheaders );

  // split the url into bits
  //char *real_url = index(c_url, '@');
  //*real_url++ = '\0';
  //char *user = index(c_url, ' ');
  //*--user = '\0';
  //user++; user++;

  //    printf( "INSERT INTO history_%s VALUES('%s','%s','%s','%s',from_unixtime(%d),from_unixtime(%d),'%s','%s','%s');\n", tbl_name, c_type, c_url, user, real_url, modtime, accesstime, c_filename, c_dirname, c_httpheaders );
    printf( "INSERT INTO history_%s VALUES('%s','%s','%s',from_unixtime(%d),from_unixtime(%d),'%s','%s','%s');\n", tbl_name, path, c_type, c_url, modtime, accesstime, c_filename, c_dirname, c_httpheaders );

  // printf( "INSERT INTO history_%s VALUES('%s','%s','%s','%s','%s','%s','%s');\n", tbl_name, c_type, c_url, c_ascmodtime, c_ascaccesstime, c_filename, c_dirname, c_httpheaders );

  type[0] = '\0';

  free( url );
  free( filename );
  free( httpheaders );

  free(c_type);
  free(c_url);
  //free(c_ascmodtime);
  //free(c_ascaccesstime);
  free(c_path);
  free(c_filename);
  free(c_dirname);
  free(c_httpheaders);
}

//
/* This function parses a URL and LEAK activity record. */
//
int parse_url( int history_file, int currrecoff, char *delim, int filesize, char *type ) {
  char fourbytes[4];
  char hashrecflagsstr[4];
  char eightbytes[8];
  char chr;
  int filenameoff;
  int httpheadersoff;
  int urloff;
  int i;
  int reclen;
  int dirnameoff;
  time_t modtime;
  time_t accesstime;
  char ascmodtime[26], ascaccesstime[26];
  char dirname[9];
  char *url;
  char *filename;
  char *httpheaders;


  pread( history_file, fourbytes, 4, currrecoff+4 );
  reclen = bah_to_i( fourbytes, 4 )*BLOCK_SIZE; 

  pread( history_file, eightbytes, 8, currrecoff+8 );
  modtime = win_time_to_unix( eightbytes );
  
  pread( history_file, eightbytes, 8, currrecoff+16 );
  accesstime = win_time_to_unix( eightbytes );
 
  //ctime_r( &accesstime, ascaccesstime );
  //ctime_r( &modtime, ascmodtime );
  
  //if (accesstime == 0) {
  //  ascaccesstime[0] = '\0';
  //}

  //if (modtime == 0) {
  //  ascmodtime[0] = '\0';
  //}
  
  url = (char *)malloc( reclen+1 );

  pread( history_file, &chr, 1, currrecoff+0x34 );
  urloff = (unsigned char)chr;

  i = 0;
  pread( history_file, &chr, 1, currrecoff+urloff );
  while ( chr != '\0' && currrecoff+urloff+i+1 < filesize ) {
    url[i] = chr;
    pread( history_file, &chr, 1, currrecoff+urloff+i+1 );
    i++; 
  } 
  url[i] = '\0';

  filename = (char *)malloc( reclen+1 );

  pread( history_file, fourbytes, 4, currrecoff+0x3C );
  filenameoff = bah_to_i( fourbytes, 4 ) + currrecoff; 

  i = 0;
  pread( history_file, &chr, 1, filenameoff );
  while ( chr != '\0' && filenameoff+i+1 < filesize ) {
    filename[i] = chr;
    pread( history_file, &chr, 1, filenameoff+i+1 );
    i++; 
  } 
  filename[i] = '\0';

  pread( history_file, &chr, 1, currrecoff+0x39 );
  dirnameoff = (unsigned char)chr;

  if (0x50+(12*dirnameoff)+8 < filesize) {
    pread( history_file, dirname, 8, 0x50+(12*dirnameoff) );
    dirname[8] = '\0';
  } else {
    dirname[0] = '\0';
  }

  httpheaders = (char *)malloc( reclen+1 );

  pread( history_file, fourbytes, 4, currrecoff+0x44 );
  httpheadersoff = bah_to_i( fourbytes, 4 ) + currrecoff; 

  i = 0;
  pread( history_file, &chr, 1, httpheadersoff );

  while ( chr != '\0' && httpheadersoff+i+1 < currrecoff+reclen && httpheadersoff+i+1 < filesize ) {
    httpheaders[i] = chr;
    pread( history_file, &chr, 1, httpheadersoff+i+1 );
    i++; 
  } 
  httpheaders[i] = '\0';
 
  printablestring( type );
  printablestring( url );
  //printablestring( ascmodtime );
  //printablestring( ascaccesstime );
  printablestring( filename );
  printablestring( dirname );
  printablestring( httpheaders );

  if (type[3] == ' ') {
    type[3] = '\0';
  }
  char *c_type = print_sql_data( type );
  char *c_url = print_sql_data( url );
  //char *c_ascmodtime = print_sql_data( ascmodtime );
  //char *c_ascaccesstime = print_sql_data( ascaccesstime );
  char *c_path = print_sql_data( path );
  char *c_filename = print_sql_data( filename );
  char *c_dirname = print_sql_data( dirname );
  char *c_httpheaders = print_sql_data( httpheaders );

  // split the url into bits
  //char *real_url = index(c_url, '@');
  //*real_url++ = '\0';
  //char *user = index(c_url, ' ');
  //*--user = '\0';
  //user++; user++;

  //  printf( "INSERT INTO history_%s VALUES('%s','%s','%s','%s',from_unixtime(%d),from_unixtime(%d),'%s','%s','%s');\n", tbl_name, c_type, c_url, user, real_url, modtime, accesstime, c_filename, c_dirname, c_httpheaders );
  printf( "INSERT INTO history_%s VALUES('%s','%s','%s',from_unixtime(%d),from_unixtime(%d),'%s','%s','%s');\n", tbl_name, path, c_type, c_url, modtime, accesstime, c_filename, c_dirname, c_httpheaders );

  //  printf( "%s%s%s%s%s%s%s%s%s%s%s%s%s\n", type, delim, url, delim, ascmodtime, delim, ascaccesstime, delim, filename, delim, dirname, delim, httpheaders );

  type[0] = '\0';
  dirname[0] = '\0';
  //ascmodtime[0] = '\0';
  //ascaccesstime[0] = '\0';

  free( url );
  free( filename );
  free( httpheaders );

  free(c_type);
  free(c_url);
  //free(c_ascmodtime);
  //free(c_ascaccesstime);
  free(c_path);
  free(c_filename);
  free(c_dirname);
  free(c_httpheaders);
}

int parse_unknown( int history_file, int currrecoff, char *delim, int filesize, char *type ) {
  type[0] = '\0'; 
}

//
/* This function prints the usage message */
//
void usage( void ) {
  printf("\nUsage:  pasco [options] <filename>\n" );
  printf("\t-d Undelete Activity Records\n" );
  printf("\t-t <name> base table name\n" );
  printf("\t-p <path> original name of input file\n" );
  printf("\t-g <create|drop> print create of drop statements\n" );
  printf("\n\n");
}


//
/* MAIN function */
//
int main( int argc, char **argv ) {
  int history_file;
  char fourbytes[4];
  char chr;
  char delim[10];
  int currrecoff;
  int filesize;
  int i;
  int opt;
  time_t modtime;
  time_t accesstime;
  char type[5];
  char hashrecflagsstr[4];
  int hashoff;
  int hashsize;
  int nexthashoff;
  int offset;
  int hashrecflags;
  int deleted = 0;
  char *dbaction = NULL;


  if (argc < 2) {
    usage();
    exit( -2 );
  }

  strcpy( delim, "," );

  while ((opt = getopt( argc, argv, "dg:t:p:f:")) != -1) {
    switch(opt) {
    case 't':
      tbl_name = optarg;
      break;
      
    case 'd':
      deleted = 1;
      break;
      
    case 'g':
      dbaction = optarg;
      break;
      
    case 'p':
      path = optarg;
      break;
      
    default:
      usage();
      exit(-1);
    }
  }
//	     "	`action` VARCHAR(20) NOT NULL,\n" \
//	     "	`user` VARCHAR(20) NOT NULL,\n" \

  if (dbaction) {
    if(strcmp(dbaction, "create") == 0) {
      printf("CREATE TABLE IF NOT EXISTS history_%s (\n" \
	     "  `path` TEXT NOT NULL, \n" \
	     "	`type` VARCHAR(20) NOT NULL,\n" \
	     "	`url` TEXT NOT NULL,\n" \
	     "	`modified` TIMESTAMP NOT NULL,\n" \
	     "	`accessed` TIMESTAMP NOT NULL,\n" \
	     "	`filename` VARCHAR(250), \n" \
	     "  `filepath` VARCHAR(250), \n" \
	     "  `headers` TEXT);\n\n", tbl_name);
    } else if(strcmp(dbaction, "drop") == 0) {
      printf("DROP TABLE IF EXISTS history_%s\n\n", tbl_name);
    } else {
      usage();
    }
    exit(0);
  }

  //fprintf(stderr, "History File: %s\n", argv[argc-1]);
  history_file = open( argv[argc-1], O_RDONLY, 0 );

  if ( history_file <= 0 ) { 
    fprintf(stderr, "ERROR - The index.dat file cannot be opened!\n\n");
    usage();
    exit( -3 ); 
  }

  pread( history_file, fourbytes, 4, 0x1C );
  filesize = bah_to_i( fourbytes, 4 );


    //printf( "TYPE%sURL%sMODIFIED TIME%sACCESS TIME%sFILENAME%sDIRECTORY%sHTTP HEADERS\n", delim, delim, delim, delim, delim, delim );


  if (deleted == 0) {

    pread( history_file, fourbytes, 4, 0x20 );
    hashoff = bah_to_i( fourbytes, 4 );
  
    while (hashoff != 0 ) {

      pread( history_file, fourbytes, 4, hashoff+8 );
      nexthashoff = bah_to_i( fourbytes, 4 );

      pread( history_file, fourbytes, 4, hashoff+4 );
      hashsize = bah_to_i( fourbytes, 4 )*BLOCK_SIZE;

      for (offset = hashoff + 16; offset < hashoff+hashsize; offset = offset+8) {
        pread( history_file, hashrecflagsstr, 4, offset );
        hashrecflags = bah_to_i( hashrecflagsstr, 4 );

        pread( history_file, fourbytes, 4, offset+4 );
        currrecoff = bah_to_i( fourbytes, 4 );

        if (hashrecflagsstr[0] != 0x03 && currrecoff != 0xBADF00D ) {
          if (currrecoff != 0) {

            pread( history_file, fourbytes, 4, currrecoff );

            for (i=0;i < 4;i++) {
              type[i] = fourbytes[i];
            }
            type[4] = '\0';

            if (type[0] == 'R' && type[1] == 'E' && type[2] == 'D' && type[3] == 'R' ) {

              parse_redr( history_file, currrecoff, delim, filesize, type );

            } else if ( (type[0] == 'U' && type[1] == 'R' && type[2] == 'L') || (type[0] == 'L' && type[1] == 'E' && type[2] == 'A' && type[3] == 'K') ) {

              parse_url( history_file, currrecoff, delim, filesize, type );

            } else {

              parse_unknown( history_file, currrecoff, delim, filesize, type );

            }
          }
        }
      }  
    hashoff = nexthashoff;
    }
  } else if (deleted == 1) {

    currrecoff = 0;

    while (currrecoff < filesize ) {

      pread( history_file, fourbytes, 4, currrecoff );

      for (i=0;i < 4;i++) {
        type[i] = fourbytes[i];
      }
      type[4] = '\0';

      if (type[0] == 'R' && type[1] == 'E' && type[2] == 'D' && type[3] == 'R' ) {

        parse_redr( history_file, currrecoff, delim, filesize, type );

      } else if ( (type[0] == 'U' && type[1] == 'R' && type[2] == 'L') || (type[0] == 'L' && type[1] == 'E' && type[2] == 'A' && type[3] == 'K') ) {

        parse_url( history_file, currrecoff, delim, filesize, type );

      } else {

        parse_unknown( history_file, currrecoff, delim, filesize, type );

      }

      currrecoff = currrecoff + BLOCK_SIZE;
    }

  }
  close (history_file);
}
