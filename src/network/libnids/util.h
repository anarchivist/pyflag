/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_UTIL_H
#define _NIDS_UTIL_H

#define mknew(x)	(x *)test_malloc(sizeof(x))
#define b_comp(x,y)	(!memcmp(&(x), &(y), sizeof(x)))

struct proc_node {
  void (*item)();
  struct proc_node *next;
};

struct lurker_node {
  void (*item)();
  void *data;
  char whatto;
  struct lurker_node *next;
};

void nids_no_mem(char *);
char *test_malloc(int);
inline int before(u_int seq1, u_int seq2);
inline int after(u_int seq1, u_int seq2);

#endif /* _NIDS_UTIL_H */
