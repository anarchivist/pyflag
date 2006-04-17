/***** This python module is use to reassemble a sequence of packets
       into streams.

This is how it works:

First we register a python callback using set_tcp_callback.

Then we feed packets to the library using process_tcp.

When we finish we call clear_stream_buffers to ensure all remaining
streams are flushed.

When a stream is completed, our callback will be called with a dict describing the stream.

****/
#include <Python.h>
#include "class.h"
#include "network.h"
#include "tcp.h"

static PyObject *python_cb = NULL;

static void callback(TCPStream self, IP ip) {
  TCP tcp=(TCP)ip->packet.payload;

  switch(self->state) {
  case PYTCP_JUST_EST:
    printf("Connection ID %u -> %u (%u) New connection event\n", self->id, 
	   self->reverse->id, ip->id);
    break;
  case PYTCP_DATA:
    printf("Connection ID %u -> %u (%u) data %s\n", self->id, self->reverse->id, 
	   ip->id, tcp->packet.data);
    break;
  case PYTCP_DESTROY:
    printf("Connection ID %u -> %u (%u) destroyed\n", self->id, 
	   ip->id, self->reverse->id);
    break;    
  case PYTCP_CLOSE:
    printf("Connection ID %u -> %u (%u) closing\n", self->id, 
	   ip->id, self->reverse->id);
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
  if(!hash) return NULL;

  /** Try to parse the packet */
  root = CONSTRUCT(Root, Packet, super.Con, NULL);
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
  if(PyErr_Occurred()) return NULL;
  
  talloc_free(tmp);
  Py_INCREF(Py_None);
  return Py_None;
};

PyObject *py_clear_stream_buffers(PyObject *self, PyObject *args) {
  //  clear_stream_buffers();

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
  
  if(hash->data) {
    Py_DECREF((PyObject *)hash->data);
  };

  hash->data = cb;
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
