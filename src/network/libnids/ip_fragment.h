/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@icm.edu.pl>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_IP_FRAGMENT_H
#define _NIDS_IP_FRAGMENT_H

#define IPF_NOTF 1
#define IPF_NEW  2
#define IPF_ISF  3

int ip_frag_init(int);
int ip_defrag_stub(struct ip *, struct ip **);

#endif /* _NIDS_IP_FRAGMENT_H */
