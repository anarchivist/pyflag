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
#include "pcap.h"
#include "pypacket.h"
#include "pypcap.h"
#include "reassembler.h"
#include "tcp.h"

static void callback(TCPStream self, PyPacket *dissected) {
  PyObject *result;

  switch(self->state) {
  case PYTCP_JUST_EST: {
    if(!self->stream_object) {
      /* Create a new properties dict to pass into the python cb: This
	 essentially creates a reference cycle because each conection
	 pair points to each other. This is not a problem in our case
	 because the PYTCP_DESTROY event forcably clears both
	 Dictionaries and decreases their refcounts. */
      self->stream_object = PyDict_New();
      self->reverse->stream_object = PyDict_New();

      PyDict_SetItemString(self->stream_object, "reverse", self->reverse->stream_object);
      PyDict_SetItemString(self->reverse->stream_object, "reverse", self->stream_object);
    };

    // Let the callback know we started a new stream:
    if(self->hash->reassembler->packet_callback && dissected) {
      result = PyObject_CallFunction(self->hash->reassembler->packet_callback , "sOO", "est", 
				     dissected, self->stream_object);
      if(result) {
	Py_DECREF(result);
      };
    };
  };
    break;

    // This one carries some data:
  case PYTCP_DATA: {
    if(self->hash->reassembler->packet_callback && dissected && self->stream_object) {
      result = PyObject_CallFunction(self->hash->reassembler->packet_callback , "sOO", "data", 
				     dissected, self->stream_object);
      if(result) {
	Py_DECREF(result);
      };
    };
  };
    break;

    // This is fired when the packet is considered to be of no value
    // to stream reassembly (i.e. retransmission, FIN, RST
    // etc). Callback would normally ignore this.
  case PYTCP_RETRANSMISSION: {
    if(self->hash->reassembler->packet_callback && dissected && self->stream_object) {
      result = PyObject_CallFunction(self->hash->reassembler->packet_callback , "sOO", "retran", 
				     dissected, self->stream_object);
      if(result) {
	Py_DECREF(result);
      };
    };
  };
    break;


  case PYTCP_DESTROY: {
    // Let the callback know we finished the stream
    if(self->hash->reassembler->packet_callback && self->stream_object) {
      result = PyObject_CallFunction(self->hash->reassembler->packet_callback , "sOO", "destroy", 
				     Py_None, self->stream_object);
      if(result) {
	Py_DECREF(result);
      };
    };


    // Deallocated resources
    if(self->stream_object) {
      PyDict_Clear(self->stream_object);
      PyDict_Clear(self->reverse->stream_object);

      Py_DECREF(self->stream_object);
      Py_DECREF(self->reverse->stream_object);
      self->stream_object = NULL;
      self->reverse->stream_object = NULL;
    };
  };
    
    break;    
  case PYTCP_NON_TCP: {
    // Let the callback know we finished:
    if(self->hash->reassembler->packet_callback && dissected) {
      result = PyObject_CallFunction(self->hash->reassembler->packet_callback , "sOO", "misc", 
				     dissected, Py_None);
      if(result) {
	Py_DECREF(result);
      };
    };
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

  if(PyErr_Occurred())
    PyErr_Print();

  return;
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
    // Make sure we keep a reference to this callback
  } else Py_INCREF(self->packet_callback);

  self->hash = CONSTRUCT(TCPHashTable, TCPHashTable, Con, NULL, initial_con_id);
  self->hash->callback = callback;
  self->hash->con_id=0;

  // We pass ourselves to all the callbacks
  self->hash->reassembler = self;

  return 0;
};

static PyObject *process(Reassembler *self, PyObject *args) {
  PyPacket *root;

  if(!PyArg_ParseTuple(args, "O", &root))
    return NULL;

  Py_INCREF(root);
  // OK we found the ip header - we just load the object into the hash
  // table:
  PyErr_Clear();

  /** Process the packet */
  self->hash->process(self->hash, root);

  /** Currently there is no way for us to know if the callback
      generated an error (since the callback returns void). So here we
      check the exception state of the interpreter explicitely 
  */
  if(PyErr_Occurred()) {
    //    Py_DECREF(root);
    return NULL;
  };  

  Py_RETURN_NONE;
};

static PyMethodDef ReassemblerMethods[] = {
  {"process", (PyCFunction)process, METH_VARARGS| METH_KEYWORDS,
   "Process a pcap packet"},
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
