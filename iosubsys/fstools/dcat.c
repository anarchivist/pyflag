/*
** bcat
** The  Sleuth Kit 
**
** Given an image , block number, and size, display the contents
** of the block to stdout.
** 
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2004 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** TCTUTILs
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
#include "fs_io.h"
#include "error.h"
#include <ctype.h>
#include "except.h"
#include "fs_io.h"

/* local flags */
#define HEX 0x1
#define ASCII 0x2
#define HTML 0x4
#define STAT 0x8

#define DLS_TYPE "dls"
#define RAW_STR "raw"

void 
usage(char *myProg)  
{
	printf("usage: %s [-ahsvVw] [-i IOsubsystem] [-f fstype] [-u usize] image unit_addr [len]\n", myProg);
	printf("\t-a: displays in all ASCII \n");
	printf("\t-h: displays in hexdump-like fashion\n");
	printf("\t-s: display basic block stats such as unit size, fragments, etc.\n");
	printf("\t-i: select IO Subsystems. Try help for a list of subsystems\n");
	printf("\t-v: verbose output to stderr\n");
	printf("\t-V: display version\n");
	printf("\t-w: displays in web-like (html) fashion\n");
	printf("\t-f fstype: Image file system type\n");
	printf("\t-u usize: size of each data unit in image (for raw, dls, swap)\n"); 
	printf("\t[len] is the number of data units to display (default is 1)\n");
    printf("Supported file system types:\n");
	fs_print_types();
	printf("\t%s (Unallocated Space)\n", DLS_TYPE);

	exit(1);
}

void 
stats (FS_INFO *fs) 
{
	printf("%d: Size of Addressable Unit\n", fs->block_size);
}

FILE *logfp;

int 
main(int argc, char **argv) 
{
	FS_INFO *fs = NULL;
	DADDR_T block;
	char   *fstype = DEF_FSTYPE;
	int size, usize = 0;
	FS_BUF *buf;
	char format = 0;
	char ch;
	extern int optind;
	char *io_subsys=NULL;
	char *io_subsys_opts=NULL;
	IO_INFO *io=NULL;
	//FILE *hSwap = NULL;
	progname = argv[0];

	while ((ch = getopt(argc, argv, "af:hi:su:vVw")) > 0) {
		switch (ch) {
		case 'a':
			format |= ASCII;
			break;
		case 'f':
			fstype = optarg;
			if (strcmp(fstype, DLS_TYPE) == 0) 
				fstype = RAW_STR;

			break;
		case 'h':
			format |= HEX;
			break;
		case 'i':
		  io_subsys=optarg;
		  break;
		case 'o':
		  io_subsys_opts=optarg;
		  break;
		case 's':
			format |= STAT;
			break;
		case 'u':
			usize = atoi(optarg);
			break;
		case 'v':
			verbose++;
			logfp = stderr;
			break;
		case 'V':
			print_version();
			exit(0);
			break;
		case 'w':
			format |= HTML;
			break;
		case '?':
		default:
			usage(argv[0]);
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

	if (format & STAT) {
		if (optind + 1 != argc)
			usage(argv[0]);

		if (format & (HTML | ASCII | HEX)) {
			printf ("NOTE: Additional flags will be ignored\n");
		}
	}
	else if ((optind + 3 != argc) && (optind + 2 != argc))  {
		usage(argv[0]);
	}


	if ((format & ASCII) && (format & HEX)) {
		printf("Ascii and Hex flags can not be used together\n");
		usage(argv[0]);
	}


	/* open the file */
	fs = fs_open(io, fstype);

	/* Set the default size if given */
	if ((usize != 0) && 
	  (((fs->ftype & FSMASK) == RAWFS_TYPE) ||
	   ((fs->ftype & FSMASK) == SWAPFS_TYPE) ) ) {

		DADDR_T sectors;
		int orig_dsize, new_dsize;

		if (usize % 512) {
			printf("New data unit size not a multiple of 512\n");
			usage(argv[0]);
		}

		/* We need to do some math to update the block_count value */

		/* Get the original number of sectors */
		orig_dsize = fs->block_size / 512;
		sectors = fs->block_count * orig_dsize;

		/* Convert that to the new size */
		new_dsize = usize / 512;
		fs->block_count = sectors / new_dsize;
		if (sectors % new_dsize)
			fs->block_count++;
		fs->last_block = fs->block_count - 1; 

		fs->block_size = usize;
		fs->file_bsize = usize;
	}

	if (format & STAT) {
		stats(fs);
		fs->close(fs);
		return 0;
	}


	block = atoi(argv[optind++]);
	/* default number of units is 1 */
	size = 1;
	if (optind + 1 == argc) {
		size = atoi(argv[optind++]);
		if (size <= 0) { 
			error("Invalid size: %i\n", size);
		} 
	}

	/* Multiply number of units by block size  to get size in bytes */
	size *= fs->block_size;

	if (format & HTML) {
		printf("<HTML>\n");
		printf("<HEAD>\n");
		printf("<TITLE>%s   Unit: %lu   Size: %i bytes</TITLE>\n",
			argv[optind-3], (ULONG)block, size);
		printf("</HEAD>\n");
		printf("<BODY>\n"); 

	}

	buf = fs_buf_alloc(size);

	/* Read the data */
	if (block > fs->last_block) {
		printf("Error: block is larger than last block in image (%lu)\n",
		  (ULONG)fs->last_block);
		fs->close(fs);
		return 1;
	}
	fs->read_block(fs, buf, size, block, "");


	/* do a hexdump like printout */
	if (format & HEX) {
		unsigned int idx1, idx2;

		if (format & HTML) 
			printf("<TABLE BORDER=0>\n");

		for (idx1 = 0; idx1 < size; idx1+=16) {
			if (format & HTML) 
				printf("<TR><TD>%i</TD>", idx1);
			else
				printf("%i\t", idx1);
			

			for (idx2 = 0; idx2 < 16; idx2++) {
				if ((format & HTML) && (0 == (idx2%4)) )
					printf("<TD>");

				printf("%.2x", buf->data[idx2+idx1] & 0xff);

				if (3 == (idx2 % 4)) {
					if (format & HTML) 
						printf("</TD>");
					else
						printf(" ");
				}
			}

			printf("\t");
			for (idx2 = 0; idx2 < 16; idx2++) {
				if ((format & HTML) && (0 == (idx2%4)) )
					printf("<TD>");

				if ((isascii((int)buf->data[idx2+idx1])) && 
				  (!iscntrl((int)buf->data[idx2+idx1])))
					printf("%c", buf->data[idx2+idx1]);
				else
					printf(".");

				if (3 == (idx2 % 4)) {
					if (format & HTML) 
						printf("</TD>");
					else
						printf(" ");
				}
			}

			if (format & HTML) 
				printf("</TR>");

			printf("\n");
		}


		if (format & HTML) 
			printf("</TABLE>\n");
		else
			printf("\n");

	} /* end of if hexdump */

	/* print in all ASCII */
	else if (format & ASCII) {
		int iIdx; 
		for (iIdx = 0; iIdx < size; iIdx++) {

			if ((isprint((int)buf->data[iIdx])) || (buf->data[iIdx] == '\t')) {
				printf("%c", buf->data[iIdx]);
			}
			else if ((buf->data[iIdx] == '\n') || (buf->data[iIdx] == '\r')) {
				if (format & HTML) 
					printf("<BR>");
				printf("%c", buf->data[iIdx]);
			}
			else
				printf(".");
		}
		if (format & HTML) 
			printf("<BR>");

		printf("\n");	
	}

	/* print raw */
	else  {
		if (fwrite(buf->data, size, 1, stdout) != 1)
			error("write: %m");

		if (format & HTML) 
			printf("<br>\n");
	} 

	fs_buf_free(buf);

	fs->close(fs);

	if (format & HTML) 
		printf("</BODY>\n</html>\n");

	return 0;
}

