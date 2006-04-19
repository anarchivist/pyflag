/***** This python module is use to reassemble a sequence of packets
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
static int con_id = 0;

PyObject *New_Stream_Dict(TCPStream tcp_stream) {
  PyObject *stream = PyDict_New();
  
  if(!stream) return NULL;
  
  /** Store important information about the connection here: */
  if(PyDict_SetItemString(stream, "packets", PyList_New(0))<0)
    return NULL;

    if(PyDict_SetItemString(stream, "seq", PyList_New(0))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "length", PyList_New(0))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "data_offset", PyList_New(0))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "isn", PyInt_FromLong(0))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "con_id", PyInt_FromLong(tcp_stream->id))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "src_ip", PyLong_FromUnsignedLong(tcp_stream->addr.saddr))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "src_port", PyInt_FromLong(tcp_stream->addr.source))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "dest_ip", PyLong_FromUnsignedLong(tcp_stream->addr.daddr))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "dest_port", PyInt_FromLong(tcp_stream->addr.dest))<0)
      return NULL;

    if(PyDict_SetItemString(stream, "reverse", PyInt_FromLong(tcp_stream->reverse->id))<0)
      return NULL;

    return stream;
};

/** This adds another packet to the stream object */
int add_packet(PyObject *stream, IP ip) {
  TCP tcp = (TCP)ip->packet.payload;

  if(PyList_Append(PyDict_GetItem(stream,PyString_FromString("packets")),PyInt_FromLong(ip->id)))
    return 0;

  if(PyList_Append(PyDict_GetItem(stream,PyString_FromString("seq")),PyLong_FromUnsignedLong(tcp->packet.header.seq)))
    return 0;

  if(PyList_Append(PyDict_GetItem(stream,PyString_FromString("length")),PyInt_FromLong(tcp->packet.data_len)))
    return 0;
 
  return 1;
};

static void free_data(void *self) {
  TCPStream this=(TCPStream)self;
  PyObject *obj=(PyObject *)this->data;

  printf("Freeing data %u\n",obj->ob_refcnt);
  Py_DECREF(obj);
};

static void callback(TCPStream self, IP ip) {
  TCP tcp;
  PyObject *stream=(PyObject *)self->data;

  if(ip) tcp=(TCP)ip->packet.payload;

  switch(self->state) {
  case PYTCP_JUST_EST:
    self->data = New_Stream_Dict(self);
    stream = (PyObject*)self->data;
    talloc_set_destructor(self, free_data);
    break;
  case PYTCP_DATA:
    add_packet(stream, ip);
    /*    printf("Connection ID %u -> %u (%u) data %s\n", self->id, self->reverse->id, 
	  ip->id, tcp->packet.data);*/
    break;
  case PYTCP_DESTROY:
    if(stream)
      if(!PyObject_CallFunction(python_cb, "O",stream))
	return;

    /*    printf("Connection ID %u -> %u (%u) destroyed\n", self->id, 
	  ip->id, self->reverse->id);*/
    break;    
  case PYTCP_CLOSE:
    /*    printf("Connection ID %u -> %u (%u) closing\n", self->id, 
	  ip->id, self->reverse->id);*/
    break;
  default:
    break;
  };
};

PyObject *py_process_tcp(PyObject *self, PyObject *args) {
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
  root = CONSTRUCT(Root, Packet, super.Con, tmp);
  root->link_type = link_type;

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

PyObject *py_clear_stream_buffers(PyObject *self, PyObject *args) {
  TCPHashTable hash;
  PyObject *hash_py;
  TCPStream j,k;
  int i;

  if(!PyArg_ParseTuple(args, "O", &hash_py))
    return NULL;
  
  hash = PyCObject_AsVoidPtr(hash_py);
  if(!hash) return NULL;
  
  for(i=0; i<TCP_STREAM_TABLE_SIZE; i++) {
    list_for_each_entry_safe(j, k, &(hash->table[i]->list), list) {
      j->flush(j);
      // list_del(&(j->list));
      //     talloc_free(j);
    };
  };

  Py_INCREF(Py_None);
  return Py_None;
};

PyObject *set_tcp_callback(PyObject *self, PyObject *args) {
  PyObject *cb;
  PyObject *hash_py;
  TCPHashTable hash;
  
  if(!PyArg_ParseTuple(args, "OO", &hash_py, &cb)) 
    return NULL;
  
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

PyObject *py_init(PyObject *self, PyObject *args) {
  TCPHashTable hash = CONSTRUCT(TCPHashTable, TCPHashTable, Con, NULL);
  hash->callback = callback;
  PyObject *result =  PyCObject_FromVoidPtr(hash, (void (*)(void *))talloc_free);

  return result;
};

static PyMethodDef ReassemblerMethods[] = {
  {"init" , py_init, METH_VARARGS,
   "initialise the reassembler returning a handle to it"},
  {"process_tcp",  py_process_tcp, METH_VARARGS,
   "Process a tcp packet"},
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
