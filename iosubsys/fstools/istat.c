/*
** istat
** The Sleuth Kit 
**
** Display all inode info about a given inode.  This is a more verbose 
** version of 'ils -a'.  The body of this program was built around
** it (ils.c).
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** TCTUILs
** Brian Carrier [carrier@cerias.purdue.edu]
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**
** 1. Redistributions of source code must retain the above copyright notice,
**    this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote
**    products derived from this software without specific prior written
**    permission.     
**
**
** THIS SOFTWARE IS NOT AFFILIATED WITH PURDUE UNIVERSITY OR THE CENTER FOR
** EDUCATION IN INFORMATION ASSURANCE AND SECURITY (CERIAS) AND THEY BEAR
** NO RESPONSIBILITY FOR ITS USE OR MISUSE.
**
**
** THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
** WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR ANY PARTICULAR PURPOSE.
**
** IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
** INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS OR
** BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
** WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
** OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
** ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/

#include "fs_tools.h"
#include "error.h"
#include <time.h>
#include "except.h"
#include "fs_io.h"

FILE   *logfp;



/* atoinum - convert string to inode number */
INUM_T  
atoinum(const char *str)
{
    char   *cp, *dash;
    INUM_T  inum;

    if (*str == 0)
		return (0);

	/* if we are given the inode in the inode-type-id form, then ignore
	 * the other stuff w/out giving an error 
	 *
	 * This will make scripting easier
	 */
	if ((dash = strchr(str, '-')) != NULL) {
		*dash = '\0';
	}
    inum = STRTOUL(str, &cp, 0);
    if (*cp || cp == str)
		error("bad inode number: %s", str);
    return (inum);
}

/* usage - explain and terminate */

static void usage() {
    printf("usage: %s [-b num] [-f fstype] [-z zone] [-i IOsubsystem]  [-s seconds] [-vV] image inum\n", progname);
	printf("\t-v: verbose output to stderr\n");
	printf("\t-V: print version\n");
	printf("\t-b num: force the display of NUM address of block pointers\n");
	printf("\t-z zone: time zone of original machine (i.e. EST5EDT or GMT)\n");
	printf("\t-i: select IO Subsystems. Try help for a list of subsystems\n");
	printf("\t-s seconds: Time skew of original machine (in seconds)\n");
	printf("\t-f fstype: Image file system type\n");
	printf("Supported file system types:\n");
	fs_print_types();
	exit(1);
}


int
main(int argc, char **argv) 
{
	INUM_T	inum;
    int     ch;
    char   *fstype = DEF_FSTYPE;
	FS_INFO		*fs;
	int32_t	sec_skew = 0;
	char *io_subsys=NULL;
	IO_INFO *io=NULL;
	/* When > 0 this is the number of blocks to print, used for -b arg */
	int numblock = 0; 

    progname = argv[0];


    while ((ch = getopt(argc, argv, "b:f:i:s:vVz:")) > 0) {
	switch (ch) {
	default:
	    usage();
    case 'b':
		numblock = atoi(optarg);
		if (numblock < 1) {
			printf("invalid argument: must be positive: %d\n", numblock);
			usage();
		}
		break;
	case 'f':
	    fstype = optarg;
	    break;
		case 'i':
		  io_subsys=optarg;
		  break;

	case 's':
		sec_skew = atoi(optarg);
		break;
	case 'v':
	    verbose++;
	    logfp = stderr;
	    break;
	case 'V':
		print_version();
		exit(0);
	case 'z':
		{
		char envstr[32];
		snprintf(envstr, 32, "TZ=%s", optarg);
		if (0 != putenv(envstr)) {
				error ("error setting environment");
		}

		tzset();
		}
		break;

	}
    }


    /* User chose to set the io_subsystem */
    if(io_subsys) {
      io=io_open(io_subsys);
    } else {
      /* If the user did not specify a subsystem, we choose the standard one */
      io=io_open("standard");
    };
    
    if(!io) {
      RAISE(E_GENERIC,NULL,"Could not set io subsystem %s",io_subsys);
    };

    inum=-1;
    //Parse the rest of the args as options to the io filesystem:
    while(optind<argc) {
      char *endptr;
      int temp;
      
      //We need to guess if this option is actually numeric, then its probably an inode number
      temp = strtol(argv[optind],&endptr,10);
      //Was this a valid number? If not it must be an option...
      if(argv[optind] && *endptr=='\0') {
	inum=temp;
	optind++;
      } else {	
	TRY {
	io_parse_options(io,argv[optind]);
	} EXCEPT(E_ANY) {
	  printf("Error loading option %s: %s\n",argv[optind],except_str);
	  exit(-1);
	};
	optind++;
      }
    };
    
    TRY {
      fs = fs_open(io, fstype);
      if(!fs) RAISE(E_GENERIC,NULL,"do you need to specify FS type?");
      
    } EXCEPT(E_ANY) {
      printf("Could not open filesystem: %s\n",except_str);
      exit(-1);
    };
    
    if (inum > fs->last_inum) {
      printf ("Inode value is too large for image (%lu)\n", 
	      (ULONG)fs->last_inum);
      return 1;
    }

	if (inum < fs->first_inum) {
		printf ("Inode value is too small for image (%lu)\n", 
		  (ULONG)fs->first_inum);
		return 1;
	}

	fs->istat(fs, stdout, inum, numblock, sec_skew);

    fs->close(fs);
    exit(0);
}
