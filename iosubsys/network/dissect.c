/********************************************************
    This is a python module which dissects a packet dump. Similar to
    ethereal but much faster.
********************************************************/
#include "packet.h"
#include "network.h"
#include "init.h"

#undef _POSIX_C_SOURCE

#include "Python.h"

static PyObject *dissect(PyObject *self, PyObject *args) {
  PyObject *result;
  Root root;
  int link_type;
  StringIO tmp=CONSTRUCT(StringIO, StringIO, Con, NULL);
  
  if(!PyArg_ParseTuple(args, "s#i", &tmp->data, &tmp->size, &link_type)) 
    return NULL;

  root = CONSTRUCT(Root, Packet, super.Con, NULL);
  root->link_type = link_type;

  root->super.Read((Packet)root, tmp);

  /** Now pass the opaque type back. When this is gced it will be
      properly destroyed 
  */
  result = PyCObject_FromVoidPtr(root, (void (*)(void *))root->super.destroy);

  return result;
};

/** Returns the object in field as a python object. field is a string
    of the format node_name.field_name 
*/
static PyObject *get_field(PyObject *self, PyObject *args) {
  PyObject *result;
  char *element;
  char *e;
  char *property;
  int len;
  Packet root;
  struct struct_property_t *p;
  
  if(!PyArg_ParseTuple(args, "Os",  &result,&element)) 
    return NULL;
  
  e=talloc_strdup(NULL, element);
  root = PyCObject_AsVoidPtr(result);
  if(!root) 
    return PyErr_Format(PyExc_RuntimeError, "node is not valid");

  len=strlen(element);

  for(property=e; property<e+len; property++) 
    if(*property=='.') {
      *property=0;
      property++;
      break;
    };

  if(property> e+len) property=e+len;

  if(Find_Property(&root, &p, e, property)) {
    void *item;
    int size=0;

    talloc_free(e);

    /** If there was no property, we just return the node itself as an
	opaque object 
    */
    if(!p) {
      /** Ensure that we increase root's reference count, because we
	  will try to free it after it gets gc'd
      */
      talloc_increase_ref_count(root);

      return PyCObject_FromVoidPtr(root, (void (*)(void *))root->destroy);
    };

    item = (void *) ((char *)(root->struct_p) + p->item);

    if(!p->size) {
      size = *(int *)((char *)(root->struct_p) + p->size_p);
    } else 
      size=p->size;

    /** Now code the return value according to the node and property
	returned 
    */    
    switch(p->field_type) {
    case FIELD_TYPE_INT:
    case FIELD_TYPE_INT_X:
    case FIELD_TYPE_IP_ADDR:
      result = PyLong_FromUnsignedLong(*(unsigned int *)item); break;

    case FIELD_TYPE_CHAR_X:
    case FIELD_TYPE_CHAR:
      result = Py_BuildValue("b", *(unsigned char *)item); break;

    case FIELD_TYPE_SHORT_X:
    case FIELD_TYPE_SHORT:
      result = Py_BuildValue("h", *(uint16_t *)item); break;

    case FIELD_TYPE_STRING_X:
    case FIELD_TYPE_STRING:
      result = Py_BuildValue("s#",*(unsigned char **)item, size); break;
      
    default:
      return PyErr_Format(PyExc_RuntimeError,
			  "Unable to process field of type %u\n", p->field_type);
    
    };
 
    return result;
  } else {

    talloc_free(e);
    return PyErr_Format(PyExc_KeyError, 
			"Can not find field %s.%s", e,property);
  };
};


static PyMethodDef DissectMethods[] = {
  {"dissect",  dissect, METH_VARARGS,
   "Dissects a packet returning a dissection object"},
  {"get_field", get_field, METH_VARARGS,
   "Gets the field of a dissected node"},
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC init_dissect(void) {
  (void) Py_InitModule("_dissect", DissectMethods);
#include "init.c"
}
