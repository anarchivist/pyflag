/*
** flag dbtool

   Author:         David Collett (daveco@users.sourceforge.net)
   Version: 0.2
   Copyright (2004).

   This software traverses an image and produces SQL statements which
   can be forwarded to a database for offline analysis. This program
   forms part of pyflag, which can be found on:

   http://pyflag.sourceforge.net/

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA
*/

#include "fs_tools.h"
#include "error.h"
#include "ntfs.h"
#include "except.h"

/* Time skew of the system in seconds */
static int32_t sec_skew = 0;

char *tbl_name=NULL;
char *fstype=NULL;
char *mount_point=NULL;
int file_count = 0;
int inode_count = 0;
int inode_total = 0;

typedef struct file_run {
  unsigned long addr;
  INUM_T inum;
  int type;
  int id;
  struct file_run *next;
} RUN;

/* some prototypes */

void print_dent2(FILE *hFile, FS_DENT *fs_dent, int flags, FS_INFO *fs, 
  FS_DATA *fs_data);

static u_int8_t
print_inode(FS_INFO *fs, FS_INODE *fs_inode, int flags,
			        char *unused_context);
void print_sql_string(FILE *fh, const char *ptr, int length);

static u_int8_t
print_addr(FS_INFO *fs, DADDR_T addr, char *buf,
  int size, int flags, char *ptr);

void print_blocks(INUM_T inum, int type, int id, RUN *run);
void cleanup_deleted(char *name);
void create_tables(char *name);
void drop_tables(char *name);

//Function prints the string given in ptr as an SQL escaped string sequence. 
void print_sql_string(FILE *fh, const char *ptr, int length) {
  int i;
  for(i=0;i<length;i++) {
    switch(*(ptr+i)) {
    case 0:
      fprintf(fh,"\\0");
      break;
    case '\'':
      fprintf(fh,"\\'");
      break;
    case '\"':
      fprintf(fh,"\\\"");
      break;
    case '\n':
      fprintf(fh,"\\n");
      break;
    case '\\':
      fprintf(fh,"\\\\");
      break;
    default:
      fprintf(fh,"%c",*(ptr+i));
    };
  };
}

//Prints the string given in ptr as an SQL escaped string
//sequence. The escaped string is written on 'string' which is
//expected to have been malloced. The string is realloced if its not
//large enough to ensure that it is not overflown. Caller must free string.
//If string is NULL, memory is malloced.
int escape_sql_string(char **string, int *strlen, const char *ptr, int length) {
  int i=0;
  int j=0;

  if(!*string) {
    *strlen=100;
    (*string)=(char *)malloc(100);
  };

  for(;i<length;i++) {
    if(j>=(*strlen)-1) {
      (*strlen)+=100;
      (*string)=(char *)realloc(*string,*strlen);
      if(!(*string)) RAISE(E_NOMEMORY,NULL,"malloc");
    };
    
    switch(ptr[i]) {
    case '\\':
    case '\"':
    case '\'':
      (*string)[j++]='\\';
      (*string)[j++]=ptr[i];
      break;

    case 8:
      (*string)[j++]='\\';
      (*string)[j++]='b';
      break;

    case 0:
      (*string)[j++]='\\';
      (*string)[j++]='0';
      break;

    case '\n':
      (*string)[j++]='\\';
      (*string)[j++]='n';
      break;

    default:
      (*string)[j++]=ptr[i];
    };
  };

  *strlen=j;
  return(j);
};

/*
 * function for cleaning filenames
 */
void cleanup_deleted(char *name) {
	int char_count = 0;
	int i=0;
	int len = strlen(name);

	for(i=0; i<len; i++) {
		if(name[i] < 20 || name[i] > 126) {
			char_count+=6;
		}
		else if(name[i] == 46) {
			char_count++;
		}
	}

	//if(char_count > len/2) {
	if(char_count > 5) {
		strncpy(name, "<UNKNOWN>", len);
	}
	return;
}

/*
 * print usage message
 */
void usage(char *myProg) {
	printf("usage: %s [-vV] [-t table_name] [-f fstype] [-z ZONE] [-s seconds] [-m mntpoint] [-d (create|drop)] image\n", 
	  myProg);
	printf("\tIf [inode] is not given, the root directory is used\n");
	printf("\t-v: verbose output to stderr\n");
	printf("\t-t: output table name\n");
	printf("\t-V: Print version\n");
	printf("\t-z: Time zone of original machine (i.e. EST5EDT or GMT) (only useful with -l)\n");
	printf("\t-s seconds: Time skew of original machine (in seconds) (only useful with -l & -m)\n");
    	printf("\t-f fstype: Image file system type\n");
	printf("\t-m mount point: Mount point \n");
    	printf("\t-d (create|drop): Print create of drop table strings\n");
	printf("Supported file system types:\n");
	fs_print_types(stderr);

	exit(1);
}

FILE *logfp;

/* 
 * call back action function for dent_walk
 * calls print_dent2 to do actual printing, since it 
 * must be called once for each data stream in NTFS
 */
static u_int8_t
print_dent (FS_INFO *fs, FS_DENT *fs_dent, int flags, char *ptr) 
{

  // print progress message
  file_count++;
  if(file_count % 200 == 0)
    fprintf(stderr, "Loaded %d file entries\n", file_count);
        /* have to make a special case for NTFS */
	if (((fs->ftype & FSMASK) == NTFS_TYPE) && (fs_dent->fsi)) {

		FS_DATA *fs_data = fs_dent->fsi->attr;

		while ((fs_data) && (fs_data->flags & FS_DATA_INUSE)) {

			if (fs_data->type == NTFS_ATYPE_DATA) {
				mode_t mode = fs_dent->fsi->mode; 
				u_int8_t ent_type = fs_dent->ent_type;


				/* 
				 * A directory can have a Data stream, in which
				 * case it would be printed with modes of a
				 * directory, although it is really a file
				 * So, to avoid confusion we will set the modes
				 * to a file so it is printed that way.  The
				 * entry for the directory itself will still be
				 * printed as a directory
				 */

				if ((fs_dent->fsi->mode & FS_INODE_FMT) == FS_INODE_DIR) {
					
					fs_dent->fsi->mode &= ~FS_INODE_FMT;	
					fs_dent->fsi->mode |= FS_INODE_REG;	
					fs_dent->ent_type = FS_DENT_REG;
				}
				
				print_dent2(stdout, fs_dent, flags, fs, fs_data);

				fs_dent->fsi->mode = mode; 
				fs_dent->ent_type = ent_type;
			}
			else if (fs_data->type == NTFS_ATYPE_IDXROOT) {
				if (!(ISDOT (fs_dent->name)))
					print_dent2(stdout, fs_dent, flags, fs, fs_data);
			}

			fs_data = fs_data->next;
		}

	}
	else {
		if (!(ISDOT (fs_dent->name)))
			print_dent2(stdout, fs_dent, flags, fs, NULL);
	}

	return WALK_CONT;
}

/*
 * Print one directory entry for file table
 */
void
print_dent2(FILE *hFile, FS_DENT *fs_dent, int flags, FS_INFO *fs, 
  FS_DATA *fs_data)
{
	char mode[4];
	char status[10] = "alloc";

	FS_INODE *fs_inode = fs_dent->fsi;
	char *t1,*t2,*t3,*t4,*t5;
	int s1,s2,s3,s4,s5;
	
	t1=NULL; t2=NULL; t3=NULL; t4=NULL; t5=NULL;
	
	/* type of file - based on dentry type */
	if ((fs_dent->ent_type & FS_DENT_MASK) < FS_DENT_MAX_STR)
		sprintf(mode, "%s/", fs_dent_str[fs_dent->ent_type & FS_DENT_MASK]);
	else {
		strcpy(mode, "-/");
	}

	/* type of file - based on inode type: we want letters though for
	 * regular files so we use the dent_str though */
	if (fs_inode) {
		int typ = (fs_inode->mode & FS_INODE_FMT)>>FS_INODE_SHIFT;
		if ((typ & FS_INODE_MASK) < FS_DENT_MAX_STR)
			strcat(mode, fs_dent_str[typ & FS_INODE_MASK]);
		else {
			strcat(mode, "-");
		}
	}
	else {
		strcat(mode, "-");
	}

	mode[3] = '\0';


	/* deleted */
	if (flags & FS_FLAG_NAME_UNALLOC) {
		if((fs_inode) && (fs_inode->flags & FS_FLAG_META_ALLOC)) {
			strcpy(status, "realloc");
		}
		else {
			strcpy(status, "deleted");
		}
	}

	if(strcmp(status, "alloc") != 0) {
		cleanup_deleted(fs_dent->name);
	}
	escape_sql_string(&t1,&s1,mode,strlen(mode)); t1[s1]=0;
	escape_sql_string(&t2,&s2,status,strlen(status)); t2[s2]=0;
	escape_sql_string(&t3,&s3,fs_dent->path,strlen(fs_dent->path)); t3[s3]=0;
	escape_sql_string(&t4,&s4,fs_dent->name,strlen(fs_dent->name)); t4[s4]=0;
	
	if(fs_data) {
	  escape_sql_string(&t5,&s5,fs_data->name,strlen(fs_data->name)); t5[s5]=0;

	  /* print the data stream name if we the non-data NTFS stream */
	  if ( (((fs_data->type == NTFS_ATYPE_DATA) && 
			    (strcmp(fs_data->name, "$Data") != 0)) ||
			   ((fs_data->type == NTFS_ATYPE_IDXROOT) && 
			    (strcmp(fs_data->name, "$I30") != 0))) ) {
            fprintf(hFile, "INSERT INTO file VALUES('I%s|D%llu-%i-%i','%s','%s','%s/%s','%s:%s');\n", 
		    tbl_name,
		    fs_dent->inode, fs_data->type, fs_data->id,
		    t1,t2,mount_point,t3,t4,t5);

	  } else {
	    fprintf(hFile, "INSERT INTO file VALUES('I%s|D%llu-%i-%i','%s','%s','%s/%s','%s');\n", 
		    tbl_name,
		    fs_dent->inode, fs_data->type, fs_data->id, 
		    t1,t2,mount_point,t3,t4);
	  } 
	  free(t5);

	  //No Data stream
	} else {	    
	  fprintf(hFile, "INSERT INTO file VALUES('I%s|D%llu','%s','%s','%s/%s','%s');\n", 
		  tbl_name,
		  fs_dent->inode,
		  t1,t2,mount_point,t3,t4); 
	};

	free(t1); 
	free(t2); 
	free(t3);
	free(t4);

	return;
}

/* 
 * call back action function for inode_walk
 */
static u_int8_t
print_inode(FS_INFO *fs, FS_INODE *fs_inode, int flags,
			        char *unused_context)
{
  time_t dtime = 0;
  char *link=0;
  int lsize;

  // print progress message
  inode_count++;
  if(inode_count % 200 == 0)
    fprintf(stderr, "Loaded %d of %d Inodes\n", inode_count, inode_total);

	// is this a symlink?
	if(fs_inode->link != NULL) {
		escape_sql_string(&link,&lsize,fs_inode->link,strlen(fs_inode->link)); link[lsize]=0;
		cleanup_deleted(link);
	} else
		link = strdup("");

	if((fs_inode->uid == 0) && (fs_inode->gid == 0) && 
			(fs_inode->mtime == 0) && (fs_inode->atime == 0) &&
	   		(fs_inode->ctime == 0) && (fs_inode->dtime == 0) &&
	   		(fs_inode->nlink == 0) && (fs_inode->size == 0)) 
		return WALK_CONT;

	// adjust times if necessary
	if (sec_skew != 0) {
		fs_inode->mtime -= sec_skew;
		fs_inode->atime -= sec_skew;
		fs_inode->ctime -= sec_skew;
	}

	// do we have dtime?
	//if (fs->flags & FS_HAVE_DTIME) {
		if (sec_skew != 0) 
			fs_inode->dtime -= sec_skew;

		dtime = fs_inode->dtime;
		if (sec_skew != 0) 
			fs_inode->dtime += sec_skew;
	//}

	/* now print data blocks (for each data stream in NTFS) */
	if (((fs->ftype & FSMASK) == NTFS_TYPE) && (fs_inode)) {
		FS_DATA *fs_data;
		fs_data = fs_inode->attr;

	    	while (fs_data) {
			if (fs_data->flags & FS_DATA_INUSE) {
				if(fs_data->type == NTFS_ATYPE_DATA) {
					RUN run;
					RUN *ptr;

					run.addr = -1;
					run.inum = fs_inode->addr;
					run.type = fs_data->type;
					run.id = fs_data->id;
					run.next = NULL;
					ptr = &run;
					
					printf("INSERT INTO inode VALUES('I%s|D%lu-%d-%d','%c','%d','%d','%lu'," \
					       "'%lu','%lu',%lu,'%lo','%d','%s','%lu','');\n",
					       tbl_name,
					       (ULONG) fs_inode->addr, fs_data->type, fs_data->id,
					       (flags & FS_FLAG_META_ALLOC) ? 'a' : 'f',
					       (int) fs_inode->uid, (int) fs_inode->gid,
					       (ULONG) fs_inode->mtime, (ULONG) fs_inode->atime,
					       (ULONG) fs_inode->ctime, (ULONG) dtime,
					       (ULONG) fs_inode->mode, (int) fs_inode->nlink, link,
					       (ULONG) fs_data->size);
					
	 		           	fs->file_walk(fs, fs_inode, fs_data->type, fs_data->id,
					     FS_FLAG_FILE_AONLY | FS_FLAG_FILE_RECOVER | FS_FLAG_FILE_NOSPARSE | FS_FLAG_FILE_NOABORT,
	 	              			(FS_FILE_WALK_FN) print_addr, (char *)&ptr);
		
					print_blocks(fs_inode->addr, fs_data->type, fs_data->id, &run);
	 		       	}
			}
			fs_data = fs_data->next;
		}
	}
	else {

	  printf("INSERT INTO inode VALUES('I%s|D%lu','%c','%d','%d','%lu'," \
		 "'%lu','%lu',%lu,'%lo','%d','%s','%lu','');\n",
		 tbl_name,
		 (ULONG) fs_inode->addr, (flags & FS_FLAG_META_ALLOC) ? 'a' : 'f',
		 (int) fs_inode->uid, (int) fs_inode->gid,
		 (ULONG) fs_inode->mtime, (ULONG) fs_inode->atime,
		 (ULONG) fs_inode->ctime, (ULONG) dtime,
		 (ULONG) fs_inode->mode, (int) fs_inode->nlink, link,
		 (ULONG) fs_inode->size);
	  
	  if(fs_inode->size > 0) {
	    RUN run;
	    RUN *ptr;
	    run.addr = -1;
	    run.next = NULL;
	    ptr = &run;   
	    
	    fs->file_walk(fs, fs_inode, 0, 0, 
			  (FS_FLAG_FILE_AONLY | FS_FLAG_FILE_RECOVER | FS_FLAG_FILE_NOSPARSE | FS_FLAG_FILE_NOABORT),
			  (FS_FILE_WALK_FN) print_addr, (char *)&ptr);
	    
	    print_blocks(fs_inode->addr, 0, 0, &run);
	  }
	}

	// adjust times back again
	if (sec_skew != 0) {
	  fs_inode->mtime += sec_skew;
	  fs_inode->atime += sec_skew;
	  fs_inode->ctime += sec_skew;
	}
	free(link);
	return WALK_CONT;
}

/* 
 * call back action function for file_walk
 * simply populate a linked list
 */
static u_int8_t
print_addr (FS_INFO *fs, DADDR_T addr, char *buf,
	    int size, int flags, char *ptr)
{
    RUN **run = (RUN **)ptr;

  // skip if no data
  if(size > 0) {
    if(flags & FS_FLAG_DATA_RESIDENT) {
      // we have resident ntfs data
      printf("INSERT INTO resident values('I%s|D%lu-%d-%d','", 
	     tbl_name,
	     (ULONG)(*run)->inum, (*run)->type, (*run)->id);
      
      print_sql_string(stdout, buf, size);
      printf("');\n");
    }
    else {
      (*run)->addr = (unsigned long)addr;
      (*run)->next = (RUN *)malloc(sizeof(RUN));
      if(!(*run)->next) {
	printf("unable to allocate memory\n");
	exit(0);
      }
      (*run)->next->addr = -1;
      (*run)->next->next = NULL;
      *run = (*run)->next;
    }
  }
  return WALK_CONT;
}

/* 
 * print file runs
 */
void print_blocks (INUM_T inum, int type, int id, RUN *run) {
	unsigned long index = 0, count = 1;
	unsigned long start_block = 0;
	RUN *ptr = run;
	RUN *ptr2 = run->next;
	RUN *old;

	while(ptr->addr != -1) {
	  if((ptr->next != NULL) && (ptr->next->addr == ptr->addr + 1)) {
	    if(start_block == 0) {
	      start_block = ptr->addr;
	    }
	    count++;
	  }
	  else {
	    if(start_block != 0) {
	      if(type == 0) {
	        printf("INSERT INTO block VALUES('I%s|D%lu','%lu','%lu','%lu');\n", 
		       tbl_name, 
		       (ULONG)inum, index, start_block, count);
	      }
	      else {
	        printf("INSERT INTO block VALUES('I%s|D%lu-%i-%i','%lu','%lu','%lu');\n", 
		       tbl_name, 
		       (ULONG)inum, type, id, index, start_block, count);
	      }
	    }
	    else {
	      if(type == 0) {
	        printf("INSERT INTO block VALUES('I%s|D%lu','%lu','%lu','%lu');\n", 
		       tbl_name, 
		       (ULONG)inum, index, ptr->addr, count);
	      }
	      else {
	        printf("INSERT INTO block VALUES('I%s|D%lu-%i-%i','%lu','%lu','%lu');\n", 
		       tbl_name, 
		       (ULONG)inum, type, id, index, ptr->addr, count);
	      }
	    }
	    start_block = 0;
	    index += count;
	    count = 1;
	  }
	  ptr = ptr->next;
	}
	
	// free memory
	while(ptr2 != NULL) {
	  old = ptr2;
	  ptr2 = ptr2->next;
	  free(old);
	}
	
}

void print_fsinfo(FS_INFO *fs) {
  
  // fill in the metadata about the filesystem
  printf("INSERT INTO meta VALUES\n" \
	 "(NULL,'fstype', '%s'),\n(NULL,'first_inode','%lu'),\n" \
	 "(NULL,'last_inode','%lu'),\n(NULL,'root_inode','%lu'),\n" \
	 "(NULL,'first_block','%lu'),\n(NULL,'last_block','%lu'),\n" \
	 "(NULL,'block_size','%lu');\n\n",
	 fstype, 
	 (ULONG)fs->first_inum, (ULONG)fs->last_inum, 
	 (ULONG)fs->root_inum, (ULONG)fs->first_block, 
	 (ULONG)fs->last_block, (ULONG)fs->block_size);
}

/* 
 * main
 */
int 
main(int argc, char **argv) 
{
	int f_flags = FS_FLAG_NAME_ALLOC | FS_FLAG_NAME_UNALLOC | FS_FLAG_NAME_RECURSE;
	int i_flags = 0; i_flags |= ~0;
	char ch;
	FS_INFO 	*fs;
	IMG_INFO *img;
	char *dbaction = NULL;
	extern int optind;	

	progname = argv[0];
	//fstype = DEF_FSTYPE;
	fstype = NULL;

	i_flags |= ~0;

	while ((ch = getopt(argc, argv, "i:m:t:f:d:s:vVz:")) > 0) {
	  switch (ch) {
	  case '?':
	  default: 
	    usage(argv[0]);
	  case 'f':
	    if(strstr(optarg, "auto")==NULL)
	      fstype = optarg;
	    break;
	  case 't':
	    tbl_name = optarg;
	    break;
	  case 'd':  
	    dbaction=optarg;
	    break;
	  case 'm':
	    {
	      int len=0;
	      escape_sql_string(&mount_point,&len,optarg,strlen(optarg)); 
	      if(mount_point[len-1]=='/') len--;
	      mount_point[len]=0;
	    };
	    break;
	  case 's':
	    sec_skew = atoi(optarg);
	    break;
	  case 'v':
	    verbose++;
	    logfp = stderr;
	    break;
	  case 'V':
	    print_version(stdout);
	    
	    exit(0);
	    break;
	  case 'z':
	    {
	      char envstr[32];
	      snprintf(envstr, 32, "TZ=%s", optarg);
	      if (0 != putenv(envstr)) {
		RAISE (E_GENERIC,NULL,"error setting environment");
	      }
	      
	      /* we should be checking this somehow */
	      tzset();
	    }
	    break;
	  }
	}

	if(!tbl_name) 
	  RAISE(E_GENERIC,NULL,"IO Source name not specified!!");

	if(!mount_point)
	  RAISE(E_GENERIC,NULL,"mount point not specified!!");

	/* create/drop tables */
	if(dbaction) {
	  if(!strcmp(dbaction, "create")) {
	    create_tables(tbl_name);
	    exit(0);
	  } else if(dbaction && !strcmp(dbaction, "drop")) {
	    drop_tables(tbl_name);
	    exit(0);
	  } else {
	    RAISE(E_GENERIC,NULL,"Only valid parameters to -d are create or drop");
	  };
	};
	
	if(optind == argc)
	  usage(argv[0]);

	img = img_open(NULL, NULL, 1,
		       (const char **) &argv[optind++]);

	/* open image */
	//	fs = fs_open(argv[optind++], fstype);
	fs = fs_open(img, fstype);
	if(!fs) RAISE(E_GENERIC,NULL,"Unable to open file system as %s",fstype);

	/* print filesystem info 
	 * This fills in the meta table
	 */
	print_fsinfo(fs);

	/* directory walk, fills in the file table
	 */
	fprintf(stderr, "Loading Directory Entries\n");
	fs->dent_walk(fs, fs->root_inum, f_flags, (FS_DENT_WALK_FN) print_dent, (char *)0); 

	fs->close(fs);
	fs = NULL;
	fs = fs_open(img, fstype);
	if(!fs) RAISE(E_GENERIC,NULL,"Unable to open file system as %s",fstype);

	/* inode walk
	 * This fills in the inode table, the callback also calls file_walk
	 * which fills in the blocks table.
	 */
	inode_count = fs->first_inum;
	inode_total = fs->last_inum;
	fprintf(stderr, "Loading Inode Entries\n");
	fs->inode_walk(fs, fs->first_inum, fs->last_inum, i_flags, 
		      (FS_INODE_WALK_FN) print_inode, (char *)0);
	/* close file */
	fs->close(fs);

	exit (0);
}

void create_tables(char *name) {
	/* create tables */
	printf("CREATE TABLE IF NOT EXISTS inode (\n" \
	"	`inode` VARCHAR(250) NOT NULL,\n" \
	"	`status` INT,\n" \
	"	`uid` INT,\n" \
	"	`gid` INT,\n" \
	"	`mtime` INT NOT NULL,\n" \
	"	`atime` INT NOT NULL,\n" \
	"	`ctime` INT NOT NULL,\n" \
	"	`dtime` INT,\n" \
	"	`mode` INT,\n" \
	"	`links` INT,\n" \
	"	`link` TEXT,\n" \
	"	`size` BIGINT NOT NULL);\n\n");;

	printf("CREATE TABLE IF NOT EXISTS file (\n" \
	"	`inode` VARCHAR(250) NOT NULL,\n" \
	"	`mode` VARCHAR(3) NOT NULL,\n" \
	"	`status` VARCHAR(8) NOT NULL,\n" \
	"	`path` TEXT,\n" \
	"	`name` TEXT);\n\n");

	printf("CREATE TABLE IF NOT EXISTS block (\n" \
	"	`inode` VARCHAR(250) NOT NULL,\n" \
	"	`index` INT NOT NULL,\n" \
	"	`block` BIGINT NOT NULL,\n" \
	"	`count` INT NOT NULL);\n\n");

	printf("CREATE TABLE IF NOT EXISTS resident (\n" \
	"	`inode` VARCHAR(250) NOT NULL,\n" \
	"	`data` TEXT);\n\n");
}

void drop_tables(char *name) {
	/* drop tables */
	printf("DROP TABLE IF EXISTS  inode, file, block, resident;\n");
}
