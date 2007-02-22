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

/**  This is a check for gc
void got_freed(void *temp) {
   printf("got freed\n");
};
*/

static PyObject *New_Stream_Dict(TCPStream tcp_stream, char *direction) {
  PyObject *stream = PyDict_Copy(initial_dict);
  CachedWriter file;
  PyObject *tmp;

  if(!stream) return NULL;

  file = CONSTRUCT(CachedWriter, CachedWriter, Con, tcp_stream, 
		   talloc_asprintf(tcp_stream, "%sS%u", 
				   prefix, tcp_stream->con_id));

  tcp_stream->file = file;

  /** Store important information about the connection here: */
  tmp = PyList_New(0);
  if(PyDict_SetItemString(stream, "packets", tmp)<0)
    goto error;
  Py_DECREF(tmp);

  /**
  tmp = PyCObject_FromVoidPtr(file, got_freed);
  if(PyDict_SetItemString(stream, "test", tmp)<0)
    goto error;
  Py_DECREF(tmp);
  **/

  tmp = PyList_New(0);
  if(PyDict_SetItemString(stream, "seq", tmp)<0)
    goto error;
  Py_DECREF(tmp);

  tmp = PyList_New(0);
  if(PyDict_SetItemString(stream, "length", tmp)<0)
    goto error;
  Py_DECREF(tmp);

  /** This is the offset in the stream cache file where the payload
      is 
  */
  tmp = PyList_New(0);
  if(PyDict_SetItemString(stream, "offset", tmp)<0)
    goto error;
  Py_DECREF(tmp);

  tmp = PyInt_FromLong(0);
  if(PyDict_SetItemString(stream, "isn", tmp)<0)
    goto error;
  Py_DECREF(tmp);


  tmp=PyInt_FromLong(tcp_stream->con_id);
  if(PyDict_SetItemString(stream, "con_id", tmp)<0)
    goto error;
  Py_DECREF(tmp);

  tmp = PyLong_FromUnsignedLong(tcp_stream->addr.saddr);
  if(PyDict_SetItemString(stream, "src_ip", tmp)<0)
    goto error;
  Py_DECREF(tmp);


  tmp = PyInt_FromLong(tcp_stream->addr.source);
  if(PyDict_SetItemString(stream, "src_port", tmp)<0)
    goto error;
  Py_DECREF(tmp);

  tmp = PyLong_FromUnsignedLong(tcp_stream->addr.daddr);
  if(PyDict_SetItemString(stream, "dest_ip", tmp)<0)
    goto error;
  Py_DECREF(tmp);

  tmp=PyInt_FromLong(tcp_stream->addr.dest);
  if(PyDict_SetItemString(stream, "dest_port", tmp)<0)
    goto error;
  Py_DECREF(tmp);

  tmp=PyInt_FromLong(tcp_stream->reverse->con_id);
  if(PyDict_SetItemString(stream, "reverse", tmp)<0)
    goto error;
  Py_DECREF(tmp);

  tmp=PyString_FromString(direction);
  if(PyDict_SetItemString(stream, "direction", tmp)<0)
    goto error;
  Py_DECREF(tmp);
  
  tmp=PyString_FromString(iosource);
  if(PyDict_SetItemString(stream, "iosource", tmp)<0)
    goto error;
  Py_DECREF(tmp);

  return stream;
 error:
  Py_DECREF(tmp);
  return NULL;
};

/** This adds another packet to the stream object */
static int add_packet(TCPStream self, IP ip) {
  TCP tcp = (TCP)ip->packet.payload;
  PyObject *stream = (PyObject *)self->data;
  PyObject *t1;

  // All this gymnastics is required because PyList_Append increases
  // the ref count!!!
  t1 = PyInt_FromLong(ip->id);
  if(PyList_Append(PyDict_GetItemString(stream,"packets"),t1))
    goto error;
  Py_DECREF(t1);


  t1=PyLong_FromUnsignedLong(tcp->packet.header.seq);
  if(PyList_Append(PyDict_GetItemString(stream,"seq"),t1))
    goto error;
  Py_DECREF(t1);

  t1=PyInt_FromLong(tcp->packet.data_len);
  if(PyList_Append(PyDict_GetItemString(stream,"length"),t1))
    goto error;
  Py_DECREF(t1);

  t1 =  PyInt_FromLong(self->file->get_offset(self->file));
  if(PyList_Append(PyDict_GetItemString(stream,"offset"),t1))
    goto error;
  Py_DECREF(t1);
 
  /** Write the data into the cache file: */
  if(self->file->super.write((StringIO)self->file, tcp->packet.data, tcp->packet.data_len)<0) {
    PyErr_Format(PyExc_RuntimeError, "Unable to create or write to cache file %s",self->file->filename);
    return 0;
  };
;

  return 1;

 error:
  Py_DECREF(t1);
  return 0;
};

/** A talloc destructor to automatically decref the python objects
    upon free
*/
static int free_data(void *self) {
  TCPStream this=*(TCPStream *)self;
  PyObject *obj=(PyObject *)this->data;

  //  printf("Free Data\n");

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
      talloc_set_destructor((void *)tmp, free_data);
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
      //printf("Connection ID %u -> %u destroyed\n", self->con_id, 
      //     self->reverse->con_id);
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

  /* This does not work becaue root and packet are defined in two shared objects - do we need to maybe do a string comparison?
  if(!ISSUBCLASS(root,Packet)) {
    return PyErr_Format(PyExc_RuntimeError, "You must pass a valid packet object to this function.");
  };
  */

  /** Find the IP header */
  ip=(IP)root;
  if(!Find_Property((Packet *)&ip, NULL, "ip", "") || !ip) {
    // Just silently quit
    goto exit;
    //return PyErr_Format(PyExc_RuntimeError, "Unable to find IP headers when procssing packet %d", root->packet.packet_id);
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

 exit:  
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
  char *data;
  int size;

  if(!PyArg_ParseTuple(args, "Os#II", &hash_py,
		       &data, &size, &packet_id, &link_type)) 
    return NULL;

  hash = PyCObject_AsVoidPtr(hash_py);
  if(!hash) {
    talloc_free(tmp);
    return NULL;
  };

  /** Try to parse the packet */
  root = CONSTRUCT(Root, Packet, super.Con, NULL, NULL);
  root->packet.link_type = link_type;
  tmp->write(tmp, data,size);
  tmp->seek(tmp, 0,SEEK_SET);

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
  int initial_con_id;

  if(!PyArg_ParseTuple(args, "sI", &new_prefix, &initial_con_id)) 
    return NULL;

  if(prefix) {
    talloc_free(prefix);
  };

  prefix = talloc_strdup(NULL, new_prefix);

  hash = CONSTRUCT(TCPHashTable, TCPHashTable, Con, NULL, initial_con_id);
  hash->callback = callback;
  //result =  PyCObject_FromVoidPtr(hash, (void (*)(void *))talloc_free);
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
