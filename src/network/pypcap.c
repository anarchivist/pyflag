#include "config.h"
#include "pcap.h"
#include "stringio.h"
#include "network.h"
#include <Python.h>

/** This is a python module which provides access to the pcap packet
    interface in pcap.c
*/

// This is a global reference to the pypacket module (for import
// pypacket)
static PyObject *g_pypacket_module=NULL;

typedef struct {
  PyObject_HEAD

  // A buffer to be used to read from:
  StringIO buffer;

  // A python file like object - we only care that it has a read
  // method. We use the read method to repeatadely fill the buffer
  // with large chunks.
  PyObject *fd;

  // The file header:
  PcapFileHeader file_header;
  PcapPacketHeader packet_header;
  StringIO dissection_buffer;

  // Default id to use for newly dissected packets:
  int packet_id;
} PyPCAP;


#define FILL_SIZE (1024 * 100)
#define MAX_PACKET_SIZE (2 * 1024)

// This is called to fill the buffer when it gets too low:
static int PyPCAP_fill_buffer(PyPCAP *self, PyObject *fd) {
  PyObject *data = PyObject_CallMethod(fd, "read", "l", FILL_SIZE);
  char *buff;
  int len;
  int current_readptr = self->buffer->readptr;

  if(!data) return -1;

  if(0 > PyString_AsStringAndSize(data, &buff, &len)) return -1;

  // Append the data to the end:
  CALL(self->buffer, seek, 0, SEEK_END);

  // Copy the data into our buffer:
  CALL(self->buffer, write, buff, len);

  self->buffer->readptr = current_readptr;

  return len;
};

/** The constructor - we fill our initial buffer from the fd (and
    detect if it has a read method in the process...
    
    We then parse the pcap file header from the fd (and detect if its
    a pcap file at all).
*/
static int PyPCAP_init(PyPCAP *self, PyObject *args, PyObject *kwds) {
  PyObject *fd = NULL;
  int len;
  static char *kwlist[] = {"fd", NULL};
  
  if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist,
				  &fd))
    return -1;

  // Create the new buffer - the buffer is used as our talloc context:
  self->buffer = CONSTRUCT(StringIO, StringIO, Con, NULL);

  //Fill it up:
  if(PyPCAP_fill_buffer(self, fd)<0) {
    goto fail;
  };

  // Read the header from our buffer:
  self->file_header = (PcapFileHeader)CONSTRUCT(PcapFileHeader, Packet, 
						super.Con, self->buffer, NULL);
  
  len = self->file_header->super.Read((Packet)self->file_header, self->buffer);

  if(self->file_header->header.magic != 0xA1B2C3D4) {
    PyErr_Format(PyExc_IOError, "File does not have the right magic");
    goto fail;
  };

  CALL(self->buffer, skip, self->buffer->readptr);

  // Take over the fd
  self->fd = fd;
  Py_INCREF(fd);

  self->dissection_buffer = CONSTRUCT(StringIO, StringIO, Con, self->buffer);

  // Ok we are good.
  return 0;

 fail:
    return -1;
};

static void PyPCAP_dealloc(PyPCAP *self) {
  if(self->buffer)
    talloc_free(self->buffer);

  if(self->fd) {
    Py_DECREF(self->fd);
  };

  self->ob_type->tp_free((PyObject*)self);
};

// this returns an object representing the file header:
static PyObject *file_header(PyPCAP *self, PyObject *args) {
  PyObject *result = PyObject_CallMethod(g_pypacket_module, "PyPacket", "N",
					 PyCObject_FromVoidPtr(self->file_header, 
							       NULL),
					 "PcapFileHeader");

  return result;
};

/** Dissects the current packet returning a PyPacket object */
static PyObject *PyPCAP_dissect(PyPCAP *self, PyObject *args, PyObject *kwds) {
  Root root;
  PyObject *result;
  int packet_id=-1;
  static char *kwlist[] = {"id", NULL};

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist,
				  &packet_id)) return NULL;
  
  if(packet_id<0) {
    packet_id = self->packet_id;
    self->packet_id++;
  };

  CALL(self->dissection_buffer, truncate, 0);
  CALL(self->dissection_buffer, write, 
       self->packet_header->header.data, self->packet_header->header.len);

  CALL(self->dissection_buffer, seek, 0,0);

  root = CONSTRUCT(Root, Packet, super.Con, NULL, NULL);
  root->packet.link_type = self->file_header->header.linktype;
  root->packet.packet_id = packet_id;

  // Read the data:
  root->super.Read((Packet)root, self->dissection_buffer);

  // Create a new PyPacket object to return:
  result = PyObject_CallMethod(g_pypacket_module, "PyPacket", "N",
			       PyCObject_FromVoidPtr(root, NULL),
			       "PcapPacketHeader");

  talloc_free(root);

  return result;
};

static PyObject *PyPCAP_next(PyPCAP *self) {
  PyObject *result;
  int len;

  // Make sure our buffer is full enough:
  if(self->buffer->size < MAX_PACKET_SIZE) {
    len = PyPCAP_fill_buffer(self, self->fd);
    
    if(len<0) return NULL;
  };

  // Free old packets:
  if(self->packet_header) talloc_free(self->packet_header);

  // Make a new packet:
  self->packet_header = (PcapPacketHeader)CONSTRUCT(PcapPacketHeader, Packet,
						    super.Con, self->buffer, NULL);

  // Adjust the endianess if needed
  if(self->file_header->little_endian) {
    self->packet_header->super.format = PCAP_PKTHEADER_STRUCT_LE;
  };

  // Read the packet in:
  len = self->packet_header->super.Read((Packet)self->packet_header, self->buffer);

  // Did we finish?
  if(len<=0) {
    return PyErr_Format(PyExc_StopIteration, "Done");
  };
  
  CALL(self->buffer, skip, self->buffer->readptr);

  // create a new pypacket object:
  result = PyObject_CallMethod(g_pypacket_module, "PyPacket", "N",
			       PyCObject_FromVoidPtr(self->packet_header,NULL), "PcapPacketHeader");

  return result;
};

/** With no args we go to the first packet */
static PyObject *PyPCAP_seek(PyPCAP *self, PyObject *args, PyObject *kwds) {
  static char *kwlist[] = {"offset", NULL};
  uint64_t offset=sizeof(struct pcap_file_header);

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "|K", kwlist,
				  &offset))
    return NULL;

  // Flush out the local cache:
  CALL(self->buffer, truncate, 0);
  
  return PyObject_CallMethod(self->fd, "seek", "K", offset);
};

static PyObject *PyPCAP_offset(PyPCAP *self, PyObject *args) {
  PyObject *offset = PyObject_CallMethod(self->fd, "tell", NULL);

  if(!offset) return NULL;

  return PyLong_FromUnsignedLongLong(PyLong_AsUnsignedLongLong(offset) - self->buffer->size);

};

static PyMethodDef PyPCAP_methods[] = {
  {"offset", (PyCFunction)PyPCAP_offset, METH_VARARGS,
   "returns the current offset of the pcap file (so we can seek to it later).\nThis is not the same as the offset of the file object because we do some caching"},
  {"seek", (PyCFunction)PyPCAP_seek, METH_VARARGS|METH_KEYWORDS,
   "seeks the file to a specific place. "},
  {"dissect", (PyCFunction)PyPCAP_dissect, METH_VARARGS|METH_KEYWORDS,
   "dissects the current packet returning a PyPacket object"},
  {"file_header", (PyCFunction)file_header, METH_VARARGS,
   "Returns a pypacket object of the file header"},
  { NULL }
};

static PyTypeObject PyPCAPType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "pypcap.PyPCAP",             /* tp_name */
    sizeof(PyPCAP),            /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)PyPCAP_dealloc,/* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    "PyPCAP Object",           /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    PyObject_SelfIter,         /* tp_iter */
    (iternextfunc)PyPCAP_next, /* tp_iternext */
    PyPCAP_methods,            /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)PyPCAP_init,     /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static PyMethodDef pypcapMethods[] = {
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initpypcap(void) {
  PyObject *m;
#ifdef __DEBUG_V_
  talloc_enable_leak_report_full();
#endif
  
  m = Py_InitModule("pypcap", pypcapMethods);
  
  PyPCAPType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&PyPCAPType) < 0)
    return;
  
  Py_INCREF(&PyPCAPType);
  
  PyModule_AddObject(m, "PyPCAP", (PyObject *)&PyPCAPType);

  // Init out network module
  network_structs_init();

  // Do all the local import statements: FIXME: handle the case where
  // we cant import it.
  g_pypacket_module = PyImport_ImportModule("pypacket");

}
