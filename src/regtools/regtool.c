/*
 * regtool.c - program to dump windows 9x/NT registry's as SQL
 * Copyright (C) 2003
 * David Collett <daveco@users.sourceforge.net>
 * Michael Cohen <scudette@users.sourceforge.net>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <errno.h>
// chntpw stuff
#include "ntreg.h"
#include "sam.h"
// regutils stuff
#include "registry.h"
#include "regformat.h"
#include "misc.h"
#include "timeconv.h"
#define MAX_HIVES 10

extern char *val_types[REG_MAX+1];
struct hive *hive[MAX_HIVES+1];
char *tablename="registry";
char *path_prefix="";
char *progname;
char *warnings = 0;
char *filename=NULL;

// sortkey, sortval are utility functions from regedit
static int
sortkey(const void *a1, const void *a2)
{
  RegistryKey *k1 = (RegistryKey *) a1, *k2 = (RegistryKey *) a2;
  return strcasecmp(k1->entry->name, k2->entry->name);
}

static int
sortval(const void *a1, const void *a2)
{
  RegistryValue **v1 = (RegistryValue **) a1, **v2 = (RegistryValue **) a2;
  return strcasecmp((*v1)->name, (*v2)->name);
}

/* print out sql safe string ptr. We will malloc a new buffer and return that (it may be longer than the buffer we got) */
char *print_sql_data(char *ptr,int length) {
  int i=0;
  int j=0;

  char *result=malloc(length*2);

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
};

// main function for regedit
static void
dump_key(RegistryKey key, const char *pathname, FILE *fp, int extendedTypes)
{
  RegistryKey *ch = 0, child;
  RegistryValue **val;
  char childpath[1024];
  int i;
  int nchild, nalloc;
    
  //fprintf(fp, "[%s]\n", pathname);
  if (registry_nvalues(key) != 0) {
    val = (RegistryValue **) xmalloc(sizeof(RegistryValue *) * registry_nvalues(key));
    for (i = 0; i < registry_nvalues(key); i++)
      val[i] = registry_value(key, i);
    qsort(val, registry_nvalues(key), sizeof(RegistryValue *), sortval);
    for (i = 0; i < registry_nvalues(key); i++) {
      char *string;
      char *type;
      int len;
      RegistryValue *v = val[i];
      if (v->name == NULL)
	continue;
      //if (v->name[0] == '\0')
      //	putc('@', fp);
      //   else
      //	dump_string(v->name, strlen(v->name), fp);
      //   putc('=', fp);
      len = v->datalen;
      switch (v->type) {
      case STRING_VALUE:
	type = strdup("REG_SZ");
	string = (char *)malloc(len+10);
	memcpy(string,v->data,len);
	len++;
	break;
      case HEX_VALUE:
	string = (char *)malloc(len+10);
	type = strdup("REG_BINARY");
	memcpy(string,v->data,len);
	len++;
	break;
      case DWORD_VALUE:
	type = strdup("REG_DWORD");
	string = (char *)malloc(15);
	snprintf(string, 14, "0x%08x", *((u_int *) v->data));
	break;
      case USTRINGZ_VALUE:
	type = strdup("REG_SZ");
	string = (char *)malloc(len+10);
	cheap_uni2ascii(v->data,string,len);
	len=len/2;
	break;
      case STRINGZ_VALUE:
	type = strdup("REG_SZ");
	string = (char *)malloc(len+10);
	memcpy(string,v->data,len);
	len++;
	break;
      default:
	type = strdup("Unknown");
	string = (char *)malloc(len+10);
	memcpy(string,v->data,len);
	len++;
      }

      {
	char *temp=strdup(pathname);
	char *clean_name;
	char *clean_value;
	char *clean_path;
	int i;
	    
	//Convert all \ in name to /:
	for(i=0; i<strlen(temp);i++) if(temp[i]=='\\') temp[i]='/';
	    
	clean_path=print_sql_data(temp,strlen(temp));
	free(temp);
	clean_name=print_sql_data(v->name,strlen(v->name));
	clean_value=print_sql_data(string,len-1);
	
	fprintf(fp, " insert into %s set `path`='%s/%s',`size`='%d',`type`='%s',`reg_key`='%s',`value`='%s' ;\n",tablename,path_prefix,clean_path, v->datalen, type, clean_name,clean_value); 
	    
	free(clean_value);
	free(clean_path);
	free(clean_name);
      };
      free(type);
      free(string);
      //putc('\n', fp);
    }
    free(val);
  }
  //putc('\n', fp);
  nalloc = 0;
  nchild = 0;
  child = registry_first_subkey(key);
  while (child.entry != NULL) {
    if (nchild == nalloc) {
      RegistryKey *nch;
      if (nalloc == 0)
	nalloc = 8;
      else
	nalloc *= 4;
      nch = (RegistryKey *) xmalloc(sizeof(RegistryKey) * nalloc);
      if (nchild != 0) {
	memcpy(nch, ch, sizeof(RegistryKey) * nchild);
	free(ch);
      }
      ch = nch;
    }
    ch[nchild++] = child;
    child = registry_next_subkey(child);
  }
  if (nchild != 0) {
    qsort(ch, nchild, sizeof(RegistryKey), sortkey);
    for (i = 0; i < nchild; i++) {
      sprintf(childpath, "%s\\%s", pathname,
	      registry_key_name(ch[i]));
      dump_key(ch[i], childpath, fp, extendedTypes);
    }
    free(ch);
  }
}

/* ls -r - list a 'nk' nodes subkeys and values recursively
 * vofs - offset to start of data (skipping block linkage)
 * type - 0 = full, 1 = keys only. 2 = values only
 */
void nk_ls_r(struct hive *hdesc, char *path, int vofs, int type)
{
  struct nk_key *key;
  int nkofs;
  struct ex_data ex;
  struct vex_data vex;
  int count = 0, countri = 0;
  
  nkofs = trav_path(hdesc, vofs, path, 0);

  if(!nkofs) {
    //printf("nk_ls: Key <%s> not found\n",path);
    abort();
    return;
  }
  nkofs += 4;

  key = (struct nk_key *)(hdesc->buffer + nkofs);
  //  printf("ls of node at offset 0x%0x\n",nkofs);

  if (key->id != 0x6b6e) {
    //printf("Error: Not a 'nk' node!\n");

    //   debugit(hdesc->buffer,hdesc->size);
    
  }
  
  //  printf("Node has %ld subkeys and %ld values\n",key->no_subkeys,key->no_values);
  count = 0;
  if (key->no_values) {
    //    printf("offs        size      type   value name                    [value if type DWORD]\n");
    while ((ex_next_v(hdesc, nkofs, &count, &vex) > 0)) {
      void *data; 
      char *string;
      int i;
      int len=vex.vk->len_data;

      if (vex.vk->len_data & 0x80000000)  {
	len=4;
	data = &(vex.vk->ofs_data);
      } else {
	data = hdesc->buffer + vex.vk->ofs_data +0x1004;
      };

      switch (vex.type) {
      case REG_SZ:
      case REG_EXPAND_SZ:
      case REG_MULTI_SZ:
	string = (char *)malloc(len+10);
	cheap_uni2ascii(data,string,len);
	len=len/2;
	break;
      case REG_DWORD:
	string = (char *)malloc(15);
	snprintf(string,14,"0x%08lx",vex.vk->ofs_data);
	break;
      default:
	string = strdup("Unknown");
	break;
      case REG_BINARY:
	string = (char *)malloc(len+10);
	memcpy(string,data,len);
	//	hexdump((char *)data, 0, len, 1);
	len++;
      }
      //     if (vex.type == REG_DWORD) printf(" %*d [0x%x]",25-strlen(vex.name),vex.val , vex.val);
      {
	char *temp=strdup(path);
	char *clean_name;
	char *clean_value;
	char *clean_path;
	char *root_key = NULL;
	int i;
	char *bname,*dname,*dirc, *basec;

	//Convert all \ in name to /:
	for(i=0; i<strlen(temp);i++) if(temp[i]=='\\') temp[i]='/';
	
	clean_path=print_sql_data(temp,strlen(temp));
	free(temp);
	clean_name=print_sql_data(vex.name,strlen(vex.name));
	clean_value=print_sql_data(string,len-1);
	
	//The splitting of the path into a dirname and basename are done here so that the searching is faster in the database.
	/*	dirc=strdup(clean_path);
		basec=strdup(clean_path);
		bname=basename(basec);
		dname = dirname(dirc);
		if(!strcmp(dname,"/")) dname="";
		printf(" insert into %s set `dirname`='%s',`basename`='%s',`size`='%d',`type`='%s',`reg_key`='%s',`value`='%s' ;",tablename,dname,bname,vex.size,  (vex.type < REG_MAX ? val_types[vex.type] : "(unknown)"), clean_name,clean_value); 
		free(dirc);
		free(basec);
	
		free(clean_value);
		free(clean_path);
		free(clean_name);
	*/
	if(strncasecmp(basename(filename), "system", 6) == 0) {
	  root_key = strdup("/HKEY_LOCAL_MACHINE/System");
	} else if(strncasecmp(basename(filename), "software", 8) == 0) {
	  root_key = strdup("/HKEY_LOCAL_MACHINE/Software");
	} else if(strncasecmp(basename(filename), "sam", 3) == 0) {
	  root_key = strdup("/HKEY_LOCAL_MACHINE/SAM");
	} else if(strncasecmp(basename(filename), "ntuser", 6) == 0) {
	  root_key = strdup("/HKEY_LOCAL_MACHINE/HKEY_CURRENT_USER");
	} else {
	  root_key = strdup("/UNKNOWN");
	}

	// Process timestamp
	time_t key_time;
	DWORD rem;
	key_time = fileTimeToUnixTime((FILETIME *)key->timestamp, &rem);
	//fprintf(stderr, "%s\n", fileTimeToAscii((FILETIME *)key->timestamp));

	printf(" insert into %s set `path`='%s%s%s',`size`='%d',`type`='%s',`modified`='%u',`remainder`='%u',`reg_key`='%s',`value`='%s' ;",tablename,path_prefix,root_key,clean_path,vex.size,  (vex.type < REG_MAX ? val_types[vex.type] : "(unknown)"), key_time, rem, clean_name,clean_value);
	free(root_key);
      };

      printf("\n");
      free(string);
      FREE(vex.name);
    }
  }

  if (key->no_subkeys) {
    //    printf("offs          key name\n");
    while ((ex_next_n(hdesc, nkofs, &count, &countri, &ex) > 0)) {
      //Allocate some memory to append the stings together
      char *new_path=(char *)malloc(strlen(ex.name)+strlen(path)+10);
      strcpy(new_path,path);
      strcat(new_path,"\\");
      strcat(new_path,ex.name);
      //      printf("[%6x]   <%s>\n", ex.nkoffs, new_path);
      nk_ls_r(hdesc,new_path,vofs,type);
      free(new_path);
      FREE(ex.name);
    }
  }

};

void license(void)
{
  printf("regtool - reads a windows registry hive and generates SQL statements\n\
Type regtool -h for help.\n\
\n\
Copyright (C) 2003, \n\
Michael Cohen (scudette@users.sourceforge.net)\n\
David Collett (daveco@users.sourceforge.net)\n\
\n\
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.\n\
\n\
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.\n\
\n\
You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA\n\
\n\
Heavily based on chntpw and regedit (regtools)\
\n\
chntpw is Copyright (c) 1997-2002 Petter Nordahl-Hagen.\n\
regutils is Copyright (C) 1998 Memorial University of Newfoundland\n\
\n\
");
};

/* help: output a help message */
void help(void)
{
  printf("regtool - Dumps a windows registry hive into SQL insert statements.\n\
Usage: regtool [options]\n\
\n\
-l,--license\t\tPrints out the License terms for this product\n\
-h,--help\t\tThis cruft\n\
-f,--file STR\t\tFilename to open (mandatory)\n\
-t,--table STR\t\tTable name to insert entries into (registry)\n\
-d,--ddl create|drop\tDump DDL to create or drop tables\n\
");
};

void create_table(char *table) {
  printf("    CREATE TABLE `%s` (\n\
    `path` CHAR(250) NOT NULL,\n\
    `size` SMALLINT NOT NULL,\n\
    `modified` INT(11),\n\
    `remainder` INT(11),\n\
    `type` CHAR(12) NOT NULL,\n\
    `reg_key` VARCHAR(200) NOT NULL,\n\
    `value` text\n\
    )\n", table);
}

void drop_table(char *table) {
  printf("    DROP TABLE `%s`\n", table);
}

// checks registry type, returns 0 for NT, 1 for 9x, -1 on error
int regtype(char *filename) {
  char sig[4];
  int fd;
  fd = open(filename, O_RDONLY);
  if(fd == -1) {
    printf("Could not open file %s\n", filename);
    exit(1);
  }
  read(fd, &sig, 4);
  close(fd);
  
  if (strncmp(sig, "regf", 4) == 0)
    return 0;
  else if (strncmp(sig, "CREG", 4) == 0)
    return 1;
  return -1;
}

void process_NT(char *filename) {
  struct hive *hdesc;
  int cdofs;

  if(!(hdesc = openHive(filename, HMODE_RO) )) {
    printf("Unable to open/read a hive, exiting..\n");
    exit(1);
  };
  cdofs = hdesc->rootofs;
  nk_ls_r(hdesc,"",cdofs+4,0);
}

void process_9x(char *filename) {
  Registry *r;
  RegistryKey key;
  char *topkeyname = NULL;
  char *base;
  char *p;

  base = strrchr(filename, '/');
  if (base != NULL)
    base++;
  else
    base = filename;

  if ((r = registry_open(filename, 0)) == NULL) {
    printf("Could not open registry file\n");
    exit(1);
  }
  key = registry_key(r, NULL, 0);
  
  if (strncasecmp(base, "user.", 5) == 0
      || ((p = strrchr(base, '/'))
	  && strncasecmp(p + 1, "user.", 5) == 0))
    topkeyname = "HKEY_USERS";
  else
    topkeyname = "HKEY_LOCAL_MACHINE";
  
  dump_key(key, topkeyname, stdout, 1);
  fflush(stdout);
}

int main(int argc, char *argv[])
{
  int c;
  int type;
  char *ddl = NULL;

  // progname is a global used in regedit...
  progname = argv[0];
  if (!progname || !*progname)
    progname = "regtool";  

  //Parse all options
  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"license", 0, 0, 'l'},
      {"help", 0, 0, 'h'},
      {"file", 1, 0, 'f'},
      {"table",1,0,'t'},
      {"ddl",1,0,'d'},
      {0, 0, 0, 0}
    };
    
    c = getopt_long(argc, argv,
		    "p:lhf:t:d:",
		    long_options, &option_index);
    if (c == -1)
      break;
    
    switch (c) {
    case 'f':
      filename=optarg;
      break;
    case 't':
      tablename=optarg;
      break;
    case 'h':
      help();
      exit(0);
      break;
    case 'l':
      license();
      exit(0);
      break;
    case 'd':
      ddl=optarg;
      break;
    case 'p':
      path_prefix=optarg;
      //printf("using path %s" , path_prefix);
      break;
    default:
      printf("Unknown option '%c'", c);
      exit(-1);
    }
  }
  if (optind < argc) {
    printf("non-option ARGV-elements: ");
    while (optind < argc)
      printf("%s ", argv[optind++]);
    printf("\n");
  }
  
  if(ddl) {
    if(strcmp(ddl, "create") == 0)
      create_table(tablename);
    else if (strcmp(ddl, "drop") == 0)
      drop_table(tablename);
    else
      help();
    exit(1);
  }

  if(!filename) {
    help();
    exit(1);
  };
  
  /* now check if we have a 9x registry or an NT one */
  type = regtype(filename);
  if(type == 0)
    process_NT(filename);
  else if(type == 1)
    process_9x(filename);
  else {
    printf("File %s is not a know registry file\n", filename);
  }

  exit(0);
}
