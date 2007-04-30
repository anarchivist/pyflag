/*** This is a python interface to the packet.h system.

This makes it possible to retrieve data parsed from C structures very
efficiently. Only the required data is converted into python types.
**/

#include "packet.h"
#include "pypacket.h"

static char *g_talloc_reference;
static PyObject *g_module_reference;

static PyMethodDef PyPacket_methods[];

/** The constructor:

result: An opaque python object representing a packet,

type: The name of the type as expected by calling NAMEOF(obj) - This
is used to ensure we dont get arbitrary void *pointers (its a way of
doing dynamic typing in C). If Type is not provided this check is not
performed - you are flying dangerously.
*/
static int PyPacket_init(PyPacket *self, PyObject *args) {
  PyObject *result;
  char *type=NULL;

  if(!PyArg_ParseTuple(args, "O|s", &result, &type))
    return -1;

  self->obj = PyCObject_AsVoidPtr(result);
  if(!self->obj)
    goto invalid_object;

  // Check to make sure the object is of the right type. We still have
  // the issue that ISSUBCLASS does not work across modules :-( In a
  // heavily subclassed environment this is probably just as fast.
  if(type && strcmp(type, NAMEOF(self->obj)))
    goto invalid_object;

  // Make sure it doesnt get freed on us
  talloc_reference(g_talloc_reference, self->obj);

  return 0;

 invalid_object:
  PyErr_Format(PyExc_TypeError, "Invalid arg");
  return -1;
};

static void PyPacket_dealloc(PyPacket *self) {
  // Remove our link from the pointer:
  talloc_unlink(g_talloc_reference, self->obj);

  self->ob_type->tp_free((PyObject*)self);
};

static PyObject *PyPacket_list_fields(PyPacket *self, PyObject *args) {
  struct struct_property_t *p;
  PyObject *list = PyList_New(0);

  if(!list) return NULL;

  list_for_each_entry(p, &(self->obj->properties.list), list) {
    if(p->name) {
      PyObject *tmp = PyString_FromString(p->name);
      PyList_Append(list, tmp);
      Py_DECREF(tmp);
    } else break;
  };
    
  return list;
};

static PyObject *PyPacket_get_item_string(PyPacket *self, char *field);

/* Here we get the property named by field. 
*/
static PyObject *PyPacket_getattr(PyPacket *self, char *field) {
  PyObject *result = Py_FindMethod(PyPacket_methods, (PyObject *)self, field);

  if(result) return result;

  //We handle this exception:
  PyErr_Clear();

  return PyPacket_get_item_string(self,field);
};
  
static PyObject *PyPacket_get_item_string(PyPacket *self, char *field) {
  struct struct_property_t *p, *found=NULL;
  void *item;
  int size;
  PyObject *result;

  list_for_each_entry(p, &(self->obj->properties.list), list) {
    if(!p->name) break;

    if(!strcmp(p->name, field)) {
      found =p;
      break;
    };
  };

  if(!found)
    return PyErr_Format(PyExc_KeyError, "Field %s not found", field);

  item = (void *) ((char *)(self->obj->struct_p) + p->item);
  
  if(!found->size) {
    size = *(int *)((char *)(self->obj->struct_p) + p->size_p);
  } else 
    size=p->size;

  /** Now code the return value according to the node and property
      returned 
  */    
  switch(found->field_type) {
  case FIELD_TYPE_PACKET:
    {
      Packet node = *(Packet *)item;

      if(!node) {
	Py_INCREF(Py_None);
	result=Py_None;
	break;
      };

      result = PyObject_CallMethod(g_module_reference, "PyPacket", "N",
				   PyCObject_FromVoidPtr(node, NULL), NAMEOF(node));
      break;
    };

    case FIELD_TYPE_INT:
    case FIELD_TYPE_INT_X:
      result = PyLong_FromUnsignedLong(*(unsigned int *)item); break;

    case FIELD_TYPE_IP_ADDR:
      {
	struct in_addr temp;

	temp.s_addr= htonl(*(uint32_t *)item);
	result = Py_BuildValue("s",inet_ntoa(temp)); 
	break;
      };
    case FIELD_TYPE_CHAR_X:
    case FIELD_TYPE_CHAR:
      result = Py_BuildValue("b", *(unsigned char *)item); break;

    case FIELD_TYPE_SHORT_X:
    case FIELD_TYPE_SHORT:
      result = Py_BuildValue("h", *(uint16_t *)item); break;

    case FIELD_TYPE_STRING_X:
    case FIELD_TYPE_STRING:
      result = Py_BuildValue("s#",*(unsigned char **)item, size); break;

    case FIELD_TYPE_HEX:
      result = Py_BuildValue("s#",(unsigned char *)item, size); break;

    case FIELD_TYPE_ETH_ADD:
      {
	unsigned char *x= (unsigned char *)item;
	char temp[1024];

	snprintf(temp,1024,"%02X:%02X:%02X:%02X:%02X:%02X",
		 (unsigned char)x[0],
		 (unsigned char)x[1],
		 (unsigned char)x[2],
		 (unsigned char)x[3],
		 (unsigned char)x[4],
		 (unsigned char)x[5]
		 );

	result = Py_BuildValue("s", temp);
	break;
      };

    default:
      return PyErr_Format(PyExc_RuntimeError,
			  "Unable to process field of type %u\n", p->field_type);
    
    };
 
  return result;
}

static PyObject *PyPacket_get_field(PyPacket *self, PyObject *args) {
  char *field;

  if(!PyArg_ParseTuple(args, "s", &field)) return NULL;

  return PyPacket_get_item_string(self, field);
};

static PyObject *PyPacket_get_name(PyPacket *self, PyObject *args) {
  return PyString_FromString(NAMEOF(self->obj));
}

static PyObject *PyPacket_get_range(PyPacket *self, PyObject *args) {
  Py_RETURN_NONE;
}

static PyObject *PyPacket_serialise(PyPacket *self, PyObject *args) {
  StringIO tmp = CONSTRUCT(StringIO, StringIO, Con, NULL);
  PyObject *result;

  // Write ourselves onto the stringio:
  CALL(self->obj, Write, tmp);

  // give the results back:
  result = PyString_FromStringAndSize(tmp->data, tmp->size);

  talloc_free(tmp);

  return result;
};

static PyMethodDef PyPacket_methods[] = {
  {"serialise", (PyCFunction)PyPacket_serialise, METH_VARARGS,
   "serialises the packet into a string"},
  {"list", (PyCFunction)PyPacket_list_fields, METH_VARARGS,
   "lists the fields managed by this packet"},
  {"get_field", (PyCFunction)PyPacket_get_field, METH_VARARGS,
   "Gets the field of a dissected node"},
  {"get_name", (PyCFunction)PyPacket_get_name, METH_VARARGS,
   "Returns the name of the current object"},
  {"get_range", (PyCFunction)PyPacket_get_range, METH_VARARGS,
   "Returns the offset of start of an element in the node"},
  { NULL }
};

static PyTypeObject PyPacketType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "pypacket.PyPacket",             /* tp_name */
    sizeof(PyPacket),          /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)PyPacket_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    PyPacket_getattr,        /* tp_getattr */
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
    "PyPacket Object",         /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    PyPacket_methods,          /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)PyPacket_init, /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static PyMethodDef pypacketMethods[] = {
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initpypacket(void) {
#ifdef __DEBUG_V_
    talloc_enable_leak_report_full();
#endif

    //This is a talloc reference that all objects will be tied to
    //(because talloc_increase_ref_count is broken).
    g_talloc_reference = talloc_size(NULL,1);

    g_module_reference = Py_InitModule("pypacket", pypacketMethods);

    PyPacketType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&PyPacketType) < 0)
        return;

    Py_INCREF(&PyPacketType);

    PyModule_AddObject(g_module_reference, 
		       "PyPacket", (PyObject *)&PyPacketType);
}
