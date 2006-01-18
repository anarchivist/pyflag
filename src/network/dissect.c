/********************************************************
    This is a python module which dissects a packet dump. Similar to
    ethereal but much faster.
********************************************************/

/******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************/
			       
#include "packet.h"
#include "network.h"

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


/** Takes a node, and a field name and returns the offset within the
    packet where the field is located 
*/
static PyObject *get_range(PyObject *self, PyObject *args) {
  PyObject *result;
  struct struct_property_t *p;
  Packet root;
  char *element;
  
  if(!PyArg_ParseTuple(args, "Os",  &result,&element)) 
    return NULL;

  root = PyCObject_AsVoidPtr(result);
  if(!root) 
    return PyErr_Format(PyExc_RuntimeError, "node is not valid");

  // If element is not supplied, we assume this refers to ourselves
  if(strlen(element)==0) {
    PyObject *list = PyList_New(0);
    PyList_Append(list, PyLong_FromUnsignedLong(root->start));
    PyList_Append(list, PyLong_FromUnsignedLong(-1));
    return list;
  };

  if(Find_Property(&root, &p, NAMEOF(root), element)) {
    PyObject *list = PyList_New(0);
    int size;
     
    if(!p->size) {
      size = *(int *)((char *)(root->struct_p) + p->size_p);
    } else 
      size=p->size;

    PyList_Append(list, PyLong_FromUnsignedLong(root->start + p->item));
    PyList_Append(list, PyLong_FromUnsignedLong(size));
    return list;
  } else {

    return PyErr_Format(PyExc_KeyError, 
			"Can not find field %s", element);
  };
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

  len=strcspn(e, ".");
  if(len == strlen(e)) {
    property=e;
    element=NAMEOF(root);
  } else {
    property=e+len+1;
    element=e;
  };

  e[len]=0;

  if(Find_Property(&root, &p, element, property)) {
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
    case FIELD_TYPE_PACKET:
      {
	Packet node = *(Packet *)item;

	if(!node) {
	  Py_INCREF(Py_None);
	  result=Py_None;
	  break;
	};

	result = PyCObject_FromVoidPtr(node, (void (*)(void *))node->destroy);
	/** We are about to return another reference, we need to incref
	    talloc to ensure it does not get destroyed unexpectadly 
	*/
	talloc_increase_ref_count(node);
	break;
      };

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

    case FIELD_TYPE_HEX:
      result = Py_BuildValue("s#",(unsigned char *)item, size); break;

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


/*********************************************************
    Lists the fields in a Packet object
**********************************************************/
static PyObject *list_fields(PyObject *self, PyObject *args) {
  PyObject *result;
  Packet root;
  struct struct_property_t *p;
  PyObject *pylist;
  
  if(!PyArg_ParseTuple(args, "O",  &result)) 
    return NULL;
  
  root = PyCObject_AsVoidPtr(result);
  if(!root) 
    return PyErr_Format(PyExc_RuntimeError, "node is not valid");

  pylist = PyList_New(0);
  list_for_each_entry(p, &(root->properties.list), list) {
    if(p->name) {
      PyList_Append(pylist, PyString_FromString(p->name));
    } else break;
  };

  return pylist;
};

static PyObject *get_name(PyObject *self, PyObject *args) {
  PyObject *result;
  Packet root;
  
  if(!PyArg_ParseTuple(args, "O",  &result)) 
    return NULL;
  
  root = PyCObject_AsVoidPtr(result);
  if(!root) 
    return PyErr_Format(PyExc_RuntimeError, "node is not valid");

  return PyString_FromString(NAMEOF(root));
};


static PyMethodDef DissectMethods[] = {
  {"dissect",  dissect, METH_VARARGS,
   "Dissects a packet returning a dissection object"},
  {"get_field", get_field, METH_VARARGS,
   "Gets the field of a dissected node"},
  {"list_fields", list_fields, METH_VARARGS,
   "Lists the field names in the dissected object"},
  {"get_name", get_name, METH_VARARGS,
   "Returns the name of the current node"},
  {"get_range", get_range, METH_VARARGS,
   "Returns the start of an element in the node"},
  {NULL, NULL, 0, NULL}
};

#include "init.h"
PyMODINIT_FUNC init_dissect(void) {
  (void) Py_InitModule("_dissect", DissectMethods);
#include "init.c"
}
