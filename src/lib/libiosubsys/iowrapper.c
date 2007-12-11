/*
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC5 Date: Wed Dec 12 00:45:27 HKT 2007$
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
#define _GNU_SOURCE

#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "except.h"
#include "hooker.h"

extern enum context_t context;

void usage(char *prog) {
  printf("\nThis program wraps library calls to enable binaries to operate on images with various formats. NOTE: Ensure that libio_hooker.so is in your LD_LIBRARY_PATH before running this wrapper. \n\n");
  printf("Usage: %s -i subsys -o option prog arg1 arg2 arg3...\n",prog);
  printf("\t-i subsys: The name of a subsystem to use (help for a list)\n");
  printf("\t-o optionstr: The option string for the subsystem (help for an example)\n");
  printf("\t-f wrapped filename: All wrapped filenames will start with this string. This is useful for programs that need to open other files as well as the target file (for example /usr/bin/file needs to open magic files as well).\n");
  exit(0);
};

#define STRCMP(x,y) !strncasecmp(&(x),#y,strlen(#y)+1)

int main(int argc, char **argv) 
{
  int i;
  char *opts=NULL;
  
  setenv("LD_LIBRARY_PATH",PYFLAG_LIBDIR,0);
  setenv("LD_PRELOAD","libio_hooker.so",1);
  context = UNHOOKED;
  
  //Parse all the options:
  for(i=1;i<argc;) {
    //This is an option:
    if(argv[i][0]=='-') {
      //Specify a file filter
      if(STRCMP(argv[i][1],f) || STRCMP(argv[i][1],-filter)) {
	i++;
	setenv("IO_FILENAME",argv[i],1);
	i++;
	continue;
	//Specify a subsystem
      } else if(STRCMP(argv[i][1],h)|| STRCMP(argv[i][1],-help)) {
	usage(argv[0]);
	exit(0);

      } else if(STRCMP(argv[i][1],i)|| STRCMP(argv[i][1],-subsystem)) {
	i++;
	setenv("IO_SUBSYS",argv[i],1);
	if(!strcmp(argv[i],"help")) {
	  init_hooker();
	  exit(0);
	};
	i++;
	continue;
	//Specify a single option to the subsystem
      } else if(STRCMP(argv[i][1],o) || STRCMP(argv[i][1],-options)) {
	i++;
	setenv("IO_OPTS",argv[i],1);
	if(!strcmp(argv[i],"help")) {
	  init_hooker();
	  exit(0);
	};
	i++;
	continue;
	//A noop -- function used as a seperator between args
      } else if(STRCMP(argv[i][1],-)) {
	i++;
	continue;
      } else {
	int j;
	char *option=&(argv[i][1]);

	i++;
	//Arbitrary arg used for passing into subsystem. Here we allow
	//a sequence of args until the next option (starting with
	//-). This sequence will be joined by , and passed to subsystem
	for(j=0;j+i<=argc;j++) {
	  //Quit if we hit an arg
	  if(argv[i+j][0]=='-') {
	    break;
	  } else {
	    if(opts) {
	      if(asprintf(&opts,"%s,%s=%s",opts,option,argv[i+j])<0)
		RAISE(E_NOMEMORY,NULL,"Can not asprintf malloc\n");
	    } else {
	      if(asprintf(&opts,"%s=%s",option,argv[i+j])<0)
		RAISE(E_NOMEMORY,NULL,"Can not asprintf malloc\n");
	    };
	    setenv("IO_OPTS",opts,1);
	  };
	};
	i+=j;
	continue;
      };

    } else {
      if(i==argc) RAISE(E_GENERIC,NULL,"No file to execute ... maybe you need a -- somewhere?");
      //Check that IO_SUBSYS has been set before:
      if(!getenv("IO_SUBSYS")) RAISE(E_GENERIC,NULL,"No subsystem has been set!!");
      //Specify a commandline to execute (Note this must be the last option)
      execvp(argv[i],&argv[i]);
      //If we get here we failed to execp
      RAISE(E_GENERIC,NULL,"Could not exec %s\n",argv[i]);
    };

  };

  //If we are here something went horribly wrong:
  RAISE(E_GENERIC,NULL,"No file to execute ... maybe you need a -- somewhere?");
  return -1;
};
  
