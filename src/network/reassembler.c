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
#include "network.h"
#include "tcp.h"
#include "pcap.h"
#include "pypacket.h"
#include "pypcap.h"

typedef struct {
  PyObject_HEAD
  PyObject *packet_callback;

  // The main reassembler hash table:
  TCPHashTable hash;
} Reassembler;

#if 0
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

  /* This stores the offset of each packet in the pcap file */
  tmp = PyList_New(0);
  if(PyDict_SetItemString(stream, "packet_offsets", tmp)<0)
    goto error;
  Py_DECREF(tmp);

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

  t1 = PyInt_FromLong(ip->pcap_offset);
  if(PyList_Append(PyDict_GetItemString(stream,"packet_offsets"),t1))
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

    // The following adds another destructor to self without
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

#endif

static void callback(TCPStream self, IP ip, void *object) {
  PyPacket *dissected = (PyPacket *)object;
  Reassembler *reassembler = (Reassembler *)self->data;

  switch(self->state) {
  case PYTCP_JUST_EST:
#if 0
    //The first stream in a pair is the forward stream.
    if(self->reverse->data)
      self->data = New_Stream_Dict(self, "reverse");
    else
      self->data = New_Stream_Dict(self, "forward");

    stream = (PyObject *)self->data;

    // The following adds another destructor to self without
    // interfering with whatever destructor self has already.
    {
      TCPStream *tmp = talloc_size(self,sizeof(void *));

      *tmp = self;
      talloc_set_destructor((void *)tmp, free_data);
    };
#endif

    break;
  case PYTCP_DATA: {
    PyObject *result;
    if(reassembler->packet_callback && dissected) {
      result = PyObject_CallFunction(reassembler->packet_callback , "sO", "data", dissected);
      Py_XDECREF(result);

      // We no longer need the dissected object:
      Py_XDECREF(dissected);
    };
  };
    break;
  case PYTCP_DESTROY: {
    printf("Connection ID %u -> %u destroyed\n", self->con_id, 
           self->reverse->con_id);
  };
    
    break;    
    // This is not used atm because we dont care when streams are closed:
  case PYTCP_CLOSE:
    /*    printf("Connection ID %u -> %u (%u) closing\n", self->id, 
	  ip->id, self->reverse->id);*/
    break;
  default:
    break;
  };
};

static int Reassembler_init(Reassembler *self, PyObject *args, PyObject *kwds) {
  int initial_con_id;
  static char *kwlist[] = {"initial_id", "packet_callback", NULL};

  if(!PyArg_ParseTupleAndKeywords(args, kwds, "|iO", kwlist,
				  &initial_con_id, &self->packet_callback)) 
    return -1;

  /** Make sure that packet_callback is callable: */
  if(self->packet_callback && !PyCallable_Check(self->packet_callback)) {
    PyErr_Format(PyExc_RuntimeError, "Callback must be callable");
    return -1;
  };

  self->hash = CONSTRUCT(TCPHashTable, TCPHashTable, Con, NULL, initial_con_id);
  self->hash->callback = callback;

  // We pass ourselves to all the callbacks
  self->hash->data = self;

  return 0;
};

static PyObject *process(Reassembler *self, PyObject *args) {
  PyPCAP *pcap;
  PyPacket *root;
  IP ip;

  if(!PyArg_ParseTuple(args, "O", &pcap))
    return NULL;

  // Dissect the current packet:
  root = (PyPacket *)PyObject_CallMethod((PyObject *)pcap, "dissect", NULL);
  if(!root) return NULL;

  // Check to make sure that its the right packet we want:
  //  if(strcmp("Root", NAMEOF(root->obj)))
  //  return PyErr_Format(PyExc_RuntimeError, "Not a dissected object %s", NAMEOF(root->obj));

  ip = (IP)root->obj;
  if(!Find_Property((Packet *)&ip, NULL, "ip", "") || !ip) {
    goto exit;
  };

  // OK we found the ip header - we just load the object into the hash
  // table:
  PyErr_Clear();

  /** Process the packet */
  self->hash->process(self->hash, ip, root);

  /** Currently there is no way for us to know if the callback
      generated an error (since the callback returns void). So here we
      check the exception state of the interpreter explicitely 
  */
  if(PyErr_Occurred()) {
    Py_DECREF(root);
    return NULL;
  };
  
  // Ok - all is good
  Py_RETURN_NONE;

 exit:  
  Py_DECREF(root);

  Py_RETURN_NONE;
};

static PyMethodDef ReassemblerMethods[] = {
  {"process", (PyCFunction)process, METH_VARARGS| METH_KEYWORDS,
   "Process a pcap packet"},
  /*  {"clear_stream_buffers", py_clear_stream_buffers, METH_VARARGS,
      "Clears all the stream buffers."}, 
      {"set_tcp_callback", set_tcp_callback, METH_VARARGS,
      "Sets the callback for the TCP streams"}, */
  {NULL, NULL, 0, NULL}
};

static void Reassembler_dealloc(Reassembler *self) {
  if(self->hash)
    talloc_free(self->hash);

  if(self->packet_callback) {
    Py_DECREF(self->packet_callback);
  };

  self->ob_type->tp_free((PyObject*)self);
};

static PyTypeObject ReassemblerType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "reassembler.Reassembler",             /* tp_name */
    sizeof(Reassembler),          /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)Reassembler_dealloc, /* tp_dealloc */
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
    "Reassembler Object",      /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    ReassemblerMethods,          /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)Reassembler_init, /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static PyMethodDef ReassemblerModuleMethods[] = {
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initreassembler(void) {
  PyObject *module_reference;

  network_structs_init();
  
  module_reference = Py_InitModule("reassembler", ReassemblerModuleMethods);

  ReassemblerType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&ReassemblerType) < 0)
    return;
  
  Py_INCREF(&ReassemblerType);
  
  PyModule_AddObject(module_reference, 
		     "Reassembler", (PyObject *)&ReassemblerType);
};
