#include "config.h"
#include "pcap.h"
#include "stringio.h"
#include "network.h"
#include "pypacket.h"
#include <Python.h>

/** This is a python module which provides access to the pcap packet
    interface in pcap.c
*/

// This is a global reference to the pypacket module (for import
// pypacket)
#include "pypcap.h"

static PyObject *g_pypacket_module=NULL;

static PyObject *PyPCAP_next(PyPCAP *self);

// This is called to fill the buffer when it gets too low:
static int PyPCAP_fill_buffer(PyPCAP *self, PyObject *fd) {
  PyObject *data = PyObject_CallMethod(fd, "read", "l", FILL_SIZE);
  char *buff;
  Py_ssize_t len;
  int current_readptr = self->buffer->readptr;

  if(!data) return -1;

  if(0 > PyString_AsStringAndSize(data, &buff, &len)) return -1;
  if(!buff) return -1;

  // Append the data to the end:
  CALL(self->buffer, skip, self->buffer->readptr);
  CALL(self->buffer, seek, 0, SEEK_END);

  // Copy the data into our buffer:
  CALL(self->buffer, write, buff, len);
  CALL(self->buffer, seek, 0, SEEK_SET);

  //  self->buffer->readptr = current_readptr;

  // Finished with the data
  Py_DECREF(data);

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
  static char *kwlist[] = {"fd", "output",NULL};
  int i;
  char *output=NULL;

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "O|s", kwlist,
				  &fd, &output))
    return -1;

  if(output) {
    if(!strcmp(output, "big")) {
      self->output_format = FORCE_BIG_ENDIAN;
    } else if(!strcmp(output,"little")) {
      self->output_format = FORCE_LITTLE_ENDIAN;
    } else {
      PyErr_Format(PyExc_KeyError, 
		   "Unknown value (%s) for endianess - can be only 'big' or 'little'\n", output);
      goto fail;
    };
  };

  // Create the new buffer - the buffer is used as our talloc context:
  self->buffer = CONSTRUCT(StringIO, StringIO, Con, NULL);

  //Fill it up:
  if(PyPCAP_fill_buffer(self, fd)<=0) {
      PyErr_Format(PyExc_IOError, 
		   "Cant read file");
    goto fail;
  };

  // Look for pcap magic somewhere in our buffer:
  for(i=0;i<self->buffer->size; i+=1) {
    uint32_t test = *(uint32_t *)(self->buffer->data + i);
    
    if(test==0xD4C3B2A1 || test==0xA1B2C3D4) {
      CALL(self->buffer, seek, i, SEEK_SET);
      break;
    };
  };

  // Read the header from our buffer:
  self->file_header = (PcapFileHeader)CONSTRUCT(PcapFileHeader, Packet, 
						super.Con, self->buffer, NULL);
  
  len = self->file_header->super.Read((Packet)self->file_header, self->buffer);

  if(self->file_header->header.magic != 0xA1B2C3D4) {
    PyErr_Format(PyExc_IOError, "File does not have the right magic");
    goto fail;
  };

  // Set our initial offset:
  self->pcap_offset = self->buffer->readptr;

  // Skip over the file header:
  //  CALL(self->buffer, skip, self->buffer->readptr);

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
  
  if(!result) return NULL;

  // Adjust the output endianess if needed
  switch(self->output_format) {
  case FORCE_BIG_ENDIAN:
    self->file_header->super.format = PCAP_HEADER_STRUCT;
    break;

  case FORCE_LITTLE_ENDIAN:
    self->file_header->super.format = PCAP_HEADER_STRUCT_LE;
    break;

  default:
    // Do nothing
    break;
  };

  return result;
};

/** Dissects the current packet returning a PyPacket object */
static PyObject *PyPCAP_dissect(PyPCAP *self, PyObject *args, PyObject *kwds) {
  Root root;
  PyPacket *result;
  int packet_id=-1;
  static char *kwlist[] = {"id", NULL};

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist,
				  &packet_id)) return NULL;
  
  if(packet_id<0) {
    packet_id = self->packet_id;
    self->packet_id++;
  };

  // Get the next packet:
  result = (PyPacket *)PyPCAP_next(self);
  if(!result) return NULL;

  // Copy the data into the dissection_buffer:
  CALL(self->dissection_buffer, truncate, 0);

  CALL(self->dissection_buffer, write,
       (char *)&self->packet_header->header, 16);

  CALL(self->dissection_buffer, write, 
       self->packet_header->header.data, self->packet_header->header.caplen);

  CALL(self->dissection_buffer, seek, 16, 
       SEEK_SET);

  // Attach a dissection object to the packet:
  root = CONSTRUCT(Root, Packet, super.Con, result->obj, NULL);
  root->packet.link_type = self->file_header->header.linktype;
  root->packet.packet_id = packet_id;

  // Read the data:
  root->super.Read((Packet)root, self->dissection_buffer);

  /*
  // Create a new PyPacket object to return:
  result = PyObject_CallMethod(g_pypacket_module, "PyPacket", "N",
			       PyCObject_FromVoidPtr(root, NULL),
			       "PcapPacketHeader");

  talloc_unlink(self->buffer, root);
  */
  ((PcapPacketHeader)(result->obj))->header.root = root;
  
  return (PyObject *)result;
};

static PyObject *PyPCAP_next(PyPCAP *self) {
  PyObject *result;
  int len;
  int packet_offset;

  // Make sure our buffer is full enough:
  if(self->buffer->size - self->buffer->readptr < MAX_PACKET_SIZE) {
    len = PyPCAP_fill_buffer(self, self->fd);
    
    if(len<0) return NULL;
  };

  packet_offset = self->buffer->readptr;

  /** This is an interesting side effect of the talloc reference model:
      
  talloc_reference(context, ptr) adds a new context to ptr so ptr is
  now effectively parented by two parents. The two parents are not
  equal however because a talloc free(ptr) will remove the reference
  first and then the original parent.

  This causes problems here because we create the packet_header with
  self->buffer as a context. However other code takes references to it
  - pinning it to other parents. If we did a
  talloc_free(self->packet_header) here we would be removing those
  references _instead_ of freeing the ptr from our own self->buffer
  reference. This will cause both memory leaks (because we will not be
  freeing packet_header at all, and later crashes because important
  references will be removed.

  When references begin to be used extensively I think we need to
  start using talloc_unlink instead of talloc_free everywhere.
  */
  // Free old packets:
  if(self->packet_header) 
    talloc_unlink(self->buffer, self->packet_header);

  // Make a new packet:
  self->packet_header = (PcapPacketHeader)CONSTRUCT(PcapPacketHeader, Packet,
						    super.Con, self->buffer, NULL);

  if(self->file_header->little_endian) {
    self->packet_header->super.format = self->packet_header->le_format;
  };

  // Read the packet in:
  len = self->packet_header->super.Read((Packet)self->packet_header, self->buffer);

  // Did we finish?
  if(len<=0) {
    return PyErr_Format(PyExc_StopIteration, "Done");
  };

  // Make sure the new packet knows its offset:
  self->packet_header->header.offset = self->pcap_offset;

  // Keep track of our own file offset:
  self->pcap_offset += self->buffer->readptr - packet_offset;
  // CALL(self->buffer, skip, self->buffer->readptr);

  // Adjust the output endianess if needed
  switch(self->output_format) {
  case FORCE_BIG_ENDIAN:
    // FIXME - Leaks!!!
    self->packet_header->super.format = PCAP_PKTHEADER_STRUCT;
    break;

  case FORCE_LITTLE_ENDIAN:
    self->packet_header->super.format = PCAP_PKTHEADER_STRUCT_LE;
    break;

  default:
    // Do nothing
    break;
  };

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
  self->pcap_offset = offset;

  return PyObject_CallMethod(self->fd, "seek", "K", offset);
};

static PyObject *PyPCAP_offset(PyPCAP *self, PyObject *args) {
  return PyLong_FromUnsignedLongLong(self->pcap_offset);
};

static PyObject *PyPCAP_set_id(PyPCAP *self, PyObject *args) {
  int id;
  if(!PyArg_ParseTuple(args, "i", &id)) return NULL;

  self->packet_header->header.id = id;

  Py_RETURN_NONE;
};

static PyMethodDef PyPCAP_methods[] = {
  {"offset", (PyCFunction)PyPCAP_offset, METH_VARARGS,
   "returns the current offset of the pcap file (so we can seek to it later).\nThis is not the same as the offset of the file object because we do some caching"},
  {"set_id", (PyCFunction)PyPCAP_set_id, METH_VARARGS,
   "Sets the ID of this packet"},
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
    0,//PyObject_SelfIter,         /* tp_iter */
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
  PyPCAPType.tp_iter = PyObject_SelfIter;

  if (PyType_Ready(&PyPCAPType) < 0)
    return;
  
  Py_INCREF(&PyPCAPType);
  
  PyModule_AddObject(m, "PyPCAP", (PyObject *)&PyPCAPType);

  // Init our network module
  network_structs_init();

  // Do all the local import statements: FIXME: handle the case where
  // we cant import it.
  g_pypacket_module = PyImport_ImportModule("pypacket");

}
