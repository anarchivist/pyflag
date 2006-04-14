/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
  See the file COPYING for license details.
*/

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "tcp.h"
#include "util.h"
#include "nids.h"

void
nids_no_mem(char *func)
{
  fprintf(stderr, "Out of memory in %s.\n", func);
  exit(1);
}

char *
test_malloc(int x)
{
  char *ret = malloc(x);
  
  if (!ret)
    nids_params.no_mem("test_malloc");

  return ret;
}

inline int
before(u_int seq1, u_int seq2)
{
  return ((int)(seq1 - seq2) < 0);
}

inline int
after(u_int seq1, u_int seq2)
{
  return ((int)(seq2 - seq1) < 0);
}
