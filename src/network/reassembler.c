/***** This python module is used to reassemble a sequence of packets
       into streams.

This is how it works:

First we register a python callback using set_tcp_callback.

Then we feed packets to the library using process_tcp.

When we finish we call clear_stream_buffers to ensure all remaining
streams are flushed.

When a stream is completed, our callback will be called with a dict
describing the stream.

****/
#include <Python.h>
#include "class.h"
#include "network.h"
#include "tcp.h"

static PyObject *python_cb = NULL;

/** The path prefix which will be used to create stream files */
static char *prefix = NULL;

/* The initial dictionary which will be passed to the callback */
static PyObject *initial_dict=NULL;
static char iosource[255];

static PyObject *New_Stream_Dict(TCPStream tcp_stream, char *direction) {
  PyObject *stream = PyDict_Copy(initial_dict);
  DiskStreamIO file;

  if(!stream) return NULL;

  file = CONSTRUCT(DiskStreamIO, DiskStreamIO, Con, tcp_stream, 
		   talloc_asprintf(tcp_stream, "%sS%u", 
				   prefix, tcp_stream->con_id));

  tcp_stream->file = file;

  /** Store important information about the connection here: */
  if(PyDict_SetItemString(stream, "packets", PyList_New(0))<0)
    return NULL;

    if(PyDict_SetItemString(stream, "seq", PyList_New(0))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "length", PyList_New(0))<0)
      return NULL;

    /** This is the offset in the stream cache file where the payload
	is 
    */
    if(PyDict_SetItemString(stream, "offset", PyList_New(0))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "isn", PyInt_FromLong(0))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "con_id", PyInt_FromLong(tcp_stream->con_id))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "src_ip", PyLong_FromUnsignedLong(tcp_stream->addr.saddr))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "src_port", PyInt_FromLong(tcp_stream->addr.source))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "dest_ip", PyLong_FromUnsignedLong(tcp_stream->addr.daddr))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "dest_port", PyInt_FromLong(tcp_stream->addr.dest))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "reverse", PyInt_FromLong(tcp_stream->reverse->con_id))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "direction", PyString_FromString(direction))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "iosource", PyString_FromString(iosource))<0)
      return NULL;

    return stream;
};

/** This adds another packet to the stream object */
static int add_packet(TCPStream self, IP ip) {
  TCP tcp = (TCP)ip->packet.payload;
  PyObject *stream = (PyObject *)self->data;

  if(PyList_Append(PyDict_GetItem(stream,PyString_FromString("packets")),PyInt_FromLong(ip->id)))
    return 0;

  if(PyList_Append(PyDict_GetItem(stream,PyString_FromString("seq")),PyLong_FromUnsignedLong(tcp->packet.header.seq)))
    return 0;

  if(PyList_Append(PyDict_GetItem(stream,PyString_FromString("length")),PyInt_FromLong(tcp->packet.data_len)))
    return 0;
 
  if(PyList_Append(PyDict_GetItem(stream,PyString_FromString("offset")),PyInt_FromLong(self->file->get_offset(self->file))))
    return 0;
 
  /** Write the data into the cache file: */
  if(self->file->super.write((StringIO)self->file, tcp->packet.data, tcp->packet.data_len)<0) {
    PyErr_Format(PyExc_RuntimeError, "Unable to create or write to cache file %s",self->file->filename);
    return NULL;
  };
;

  return 1;
};

/** A talloc destructor to automatically decref the python objects
    upon free
*/
static int free_data(void *self) {
  TCPStream this=*(TCPStream *)self;
  PyObject *obj=(PyObject *)this->data;

  if(obj) {
    Py_DECREF(obj);
  };

  return 0;
};

static void callback(TCPStream self, IP ip) {
  TCP tcp;
  PyObject *stream=(PyObject *)self->data;

  if(ip) tcp=(TCP)ip->packet.payload;

  switch(self->state) {
  case PYTCP_JUST_EST:
    //The first stream in a pair is the forward stream.
    if(self->reverse->data)
      self->data = New_Stream_Dict(self, "reverse");
    else
      self->data = New_Stream_Dict(self, "forward");

    stream = (PyObject*)self->data;

    // The following add another destructor to self without
    // interfering with whatever destructor self has already.
    {
      TCPStream *tmp = talloc_size(self,sizeof(void *));

      *tmp = self;
      talloc_set_destructor(tmp, free_data);
    };
    break;
  case PYTCP_DATA:
    add_packet(self, ip);
    break;
  case PYTCP_DESTROY:
    if(stream) {
      if(!PyObject_CallFunction(python_cb, "O",stream))
	return;
    } else {
      printf("Connection ID %u -> %u destroyed\n", self->con_id, 
	     self->reverse->con_id);
    };
    
    break;    
  case PYTCP_CLOSE:
    /*    printf("Connection ID %u -> %u (%u) closing\n", self->id, 
	  ip->id, self->reverse->id);*/
    break;
  default:
    break;
  };
};

static PyObject *py_process_packet(PyObject *self, PyObject *args) {
  Root root;
  IP ip;
  TCPHashTable hash;
  PyObject *hash_py;
  PyObject *root_py;
  char *io=NULL;

  if(!PyArg_ParseTuple(args, "OO|s", &hash_py,
		       &root_py, &io)) 
    return NULL;

  if(io && strcmp(io,iosource)) {
    strcpy(iosource,io);
  };

  hash = PyCObject_AsVoidPtr(hash_py);
  if(!hash) {
    return NULL;
  };

  /** Try to parse the packet */
  root = PyCObject_AsVoidPtr(root_py);
  if(!root) return NULL;

  if(!ISSUBCLASS(root,Packet)) {
    return PyErr_Format(PyExc_RuntimeError, "You must pass a valid packet object to this function.");
  };

  /** Find the IP header */
  ip=(IP)root;
  if(!Find_Property((Packet *)&ip, NULL, "ip", "") || !ip) {
    return PyErr_Format(PyExc_RuntimeError, "Unable to find IP headers when procssing packet %d", root->packet.packet_id);
  };

  //  printf("Processing %u\n", root->packet_id);
  ip->id = root->packet.packet_id;

  /** Process the packet */
  hash->process(hash, ip);

  /** Currently there is no way for us to know if the callback
      generated an error (since the callback returns void). So here we
      check the exception state of the interpreter explicitely 
  */
  if(PyErr_Occurred()) {
    return NULL;
  };
  
  Py_INCREF(Py_None);
  return Py_None;  
};

static PyObject *py_process_tcp(PyObject *self, PyObject *args) {
  int link_type;
  int packet_id;
  Root root;
  StringIO tmp=CONSTRUCT(StringIO, StringIO, Con, NULL);
  IP ip;
  TCPHashTable hash;
  PyObject *hash_py;

  if(!PyArg_ParseTuple(args, "Os#II", &hash_py,
		       &tmp->data, &tmp->size, &packet_id, &link_type)) 
    return NULL;

  hash = PyCObject_AsVoidPtr(hash_py);
  if(!hash) {
    talloc_free(tmp);
    return NULL;
  };

  /** Try to parse the packet */
  root = CONSTRUCT(Root, Packet, super.Con, NULL, NULL);
  root->packet.link_type = link_type;

  root->super.Read((Packet)root, tmp);

  /** Find the IP header */
  ip=(IP)root;
  if(!Find_Property((Packet *)&ip, NULL, "ip", "") || !ip) {
    talloc_free(tmp);
    return PyErr_Format(PyExc_RuntimeError, "Unable to find IP headers");
  };

  /** Set the packet id: */
  ip->id = packet_id;

  hash->process(hash, ip);

  /** Currently there is no way for us to know if the callback
      generated an error (since the callback returns void). So here we
      check the exception state of the interpreter explicitely 
  */
  if(PyErr_Occurred()) {
    talloc_free(tmp);
    return NULL;
  };
  
  talloc_free(tmp);
  Py_INCREF(Py_None);
  return Py_None;
};

static PyObject *py_clear_stream_buffers(PyObject *self, PyObject *args) {
  TCPHashTable hash;
  PyObject *hash_py;

  if(!PyArg_ParseTuple(args, "O", &hash_py))
    return NULL;
  
  hash = PyCObject_AsVoidPtr(hash_py);
  if(!hash) return NULL;

  talloc_free(hash);

  Py_INCREF(Py_None);
  return Py_None;
};

static PyObject *set_tcp_callback(PyObject *self, PyObject *args) {
  PyObject *cb;
  PyObject *hash_py;
  TCPHashTable hash;
  
  if(!PyArg_ParseTuple(args, "OO|O", &hash_py, &cb, &initial_dict)) 
    return NULL;
    
  if(!initial_dict) initial_dict=PyDict_New();

  hash = PyCObject_AsVoidPtr(hash_py);
  if(!hash) return NULL;

  if(!PyCallable_Check(cb) && cb!=Py_None)
    return PyErr_Format(PyExc_RuntimeError, "Callback must be callable");
  
  if(python_cb) {
    Py_DECREF(python_cb);
  };

  python_cb = cb;
  Py_INCREF(cb);

  Py_INCREF(Py_None);
  return Py_None;
};

static PyObject *py_init(PyObject *self, PyObject *args) {
  TCPHashTable hash;
  PyObject *result;
  char *new_prefix;

  if(!PyArg_ParseTuple(args, "s", &new_prefix)) 
    return NULL;

  if(prefix) {
    talloc_free(prefix);
  };

  prefix = talloc_strdup(NULL, new_prefix);

  hash = CONSTRUCT(TCPHashTable, TCPHashTable, Con, NULL);
  hash->callback = callback;
  //  result =  PyCObject_FromVoidPtr(hash, (void (*)(void *))talloc_free);
  result =  PyCObject_FromVoidPtr(hash, NULL);

  return result;
};

static PyMethodDef ReassemblerMethods[] = {
  {"init" , py_init, METH_VARARGS,
   "initialise the reassembler returning a handle to it"},
  {"process_tcp",  py_process_tcp, METH_VARARGS,
   "Process a tcp packet.\
    prototype: process_tcp(handle, data, packet_id, link_type);"},
  {"process_packet", py_process_packet, METH_VARARGS,
   "Process an already dissected packet.\
    prototype: process_packet(handle, packet);"},
  {"clear_stream_buffers", py_clear_stream_buffers, METH_VARARGS,
   "Clears all the stream buffers."},
  {"set_tcp_callback", set_tcp_callback, METH_VARARGS,
   "Sets the callback for the TCP streams"},
  {NULL, NULL, 0, NULL}
};


PyMODINIT_FUNC initreassembler(void) {
  network_structs_init();
  (void) Py_InitModule("reassembler", ReassemblerMethods);
};
