/*
** ffind  (file find)
** The Sleuth Kit 
**
** Find the file that uses the specified inode (including deleted files)
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
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
#include "ffs.h"
#include "ext2fs.h"
#include "fatfs.h"

FILE *logfp;

void
usage(char *myProg)
{
    printf("usage: %s [-vV] -f fstype] image addr\n", myProg);
    printf("\t-v: Verbose output to stderr\n");
    printf("\t-V: Print version\n");
    printf("\t-f fstype: Image file system type\n");
    printf("Supported file system types:\n");
    fs_print_types();
    
    exit(1);
}

static u_int8_t
dstat (FS_INFO *fs, DADDR_T addr, char *buf, int flags, char *ptr)
{
	switch (fs->ftype & FSMASK) {
	  case EXTxFS_TYPE:
	  case FFS_TYPE:
		printf("Fragment: %lu\n", (ULONG)addr);
		break;
	  case FATFS_TYPE:
		printf("Sector: %lu\n", (ULONG)addr);
		break;
	  case NTFS_TYPE:
		printf("Cluster: %lu\n", (ULONG)addr);
		break;
	  default:
		printf("Unsupported File System\n");
		exit(1);
	}

	printf("%sAllocated%s\n", (flags & FS_FLAG_DATA_ALLOC) ? "" : "Not ",
	  (flags & FS_FLAG_DATA_META) ? " (Meta)" : "");

    if ((fs->ftype & FSMASK) == FFS_TYPE) {
        FFS_INFO *ffs = (FFS_INFO *) fs;
        printf("Group: %lu\n", (ULONG)ffs->cg_num);
    }
    else if ((fs->ftype & FSMASK) == EXTxFS_TYPE) {
        EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs;
	if (ext2fs->grpnum != -1)
        	printf("Group: %lu\n", (ULONG)ext2fs->grpnum);
    }	
	else if ((fs->ftype & FSMASK) == FATFS_TYPE) {
		FATFS_INFO *fatfs = (FATFS_INFO *) fs;
		/* Does this have a cluster address? */
		if (addr >= fatfs->firstclustsect) {
			printf("Cluster: %lu\n", 
			  (ULONG) (2 + (addr - fatfs->firstclustsect) / fatfs->csize));
		}
	}

    return WALK_STOP;
}


int
main(int argc, char **argv)
{ 
    char 		*fstype = DEF_FSTYPE;
    char 		ch;
    extern int 	optind;
	DADDR_T 	addr;
	FS_INFO 	*fs;
	int 		flags = (FS_FLAG_DATA_UNALLOC | FS_FLAG_DATA_ALLOC | FS_FLAG_DATA_META | FS_FLAG_DATA_CONT);

    while ((ch = getopt(argc, argv, "f:uvV")) > 0) {
        switch (ch) {
        case 'f':
            fstype = optarg;
            break;
        case 'v':   
            verbose++;
            logfp = stderr;
            break;
        case 'V':
            print_version();
            exit(0);
        case '?':
        default:
            usage(argv[0]);
        }
    }

    if (optind + 2 != argc)
        usage(argv[0]);
            
    /* open image */
    fs = fs_open(argv[optind++], fstype);

    addr = atoi(argv[optind]);
	if (addr > fs->last_block) {
		printf("Data unit address too large for image (%lu)\n", 
		  (ULONG)fs->last_block);
		return 1;
	}
	if (addr < fs->first_block) {
		printf("Data unit address too small for image (%lu)\n", 
		  (ULONG)fs->first_block);
		return 1;
	}
    fs->block_walk(fs, addr, addr, flags, dstat, "dstat");
            
    fs->close(fs);
  
    return 0;
}


