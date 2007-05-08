#ifndef __PYPACKET_H
#define __PYPACKET_H

#include <Python.h>

typedef struct {
  PyObject_HEAD
  Packet obj;
} PyPacket;

#endif
