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

int main(int argc, char **argv) 
{
  char ch;
  
  setenv("LD_PRELOAD","libio_hooker.so",1);
  context = UNHOOKED;

  while ((ch = getopt(argc, argv, "+i:o:f:")) > 0) {
    switch (ch) {
    case 'i':
      setenv("IO_SUBSYS",optarg,1);
      if(!strcmp(optarg,"help")) {
	init_hooker();
	exit(0);
      };
      break;

    case 'f':
      setenv("IO_FILENAME",optarg,1);
      break;

    case 'o':
      setenv("IO_OPTS",optarg,1);
      if(!strcmp(optarg,"help")) {
	init_hooker();
	exit(0);
      };
      break;

    case '?':
    default: 
      usage(argv[0]);
      _exit(0);
    };
  };

  //Any extra args are interpreted as the command to exec
  if(optind<argc) {
    execvp(argv[optind],&argv[optind]);
    RAISE(E_GENERIC,NULL,"Could not exec %s: %s\n",argv[optind],strerror(errno));
  };

  //If we get here, just call usage:
  usage(argv[0]);
  return(0);
};
  
