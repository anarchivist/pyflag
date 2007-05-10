#ifndef _REASSEMBLER_H
#define _REASSEMBLER_H

#include <Python.h>

typedef struct {
  PyObject_HEAD
  PyObject *packet_callback;

  // The main reassembler hash table:
  struct TCPHashTable *hash;
} Reassembler;

#endif
