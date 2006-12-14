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
#  Version: FLAG  $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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

static char *python_talloc_context;

#undef _POSIX_C_SOURCE

#include "Python.h"

static PyObject *dissect(PyObject *self, PyObject *args) {
  PyObject *result;
  Root root;
  int link_type;
  int packet_id;
  StringIO tmp=CONSTRUCT(StringIO, StringIO, Con, NULL);
  char *data;
  int size;

  if(!PyArg_ParseTuple(args, "s#ii", &data, &size, &link_type,
		       &packet_id)) 
    return NULL;

  root = CONSTRUCT(Root, Packet, super.Con, NULL, NULL);
  root->packet.link_type = link_type;
  root->packet.packet_id = packet_id;

  /** Copy the data into our stringio */
  tmp->write(tmp, data, size);
  tmp->seek(tmp,0,SEEK_SET);

  root->super.Read((Packet)root, tmp);

  /** Now pass the opaque type back. When this is gced it will be
      properly destroyed 
  */
  result = PyCObject_FromVoidPtr(root, (void (*)(void *))root->super.destroy);

  talloc_free(tmp);

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
    PyObject *tmp = PyLong_FromUnsignedLong(root->start);
    PyList_Append(list, tmp);
    Py_DECREF(tmp);

    tmp= PyLong_FromUnsignedLong(-1);
    PyList_Append(list,tmp);
    Py_DECREF(tmp);

    return list;
  };

  if(Find_Property(&root, &p, NAMEOF(root), element)) {
    PyObject *list = PyList_New(0);
    PyObject *tmp;
    int size;
     
    if(!p->size) {
      size = *(int *)((char *)(root->struct_p) + p->size_p);
    } else 
      size=p->size;

    tmp = PyLong_FromUnsignedLong(root->start + p->item);
    PyList_Append(list, tmp);
    Py_DECREF(tmp);

    tmp = PyLong_FromUnsignedLong(size);
    PyList_Append(list, tmp);
    Py_DECREF(tmp);

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
  
  root = PyCObject_AsVoidPtr(result);
  if(!root) 
    return PyErr_Format(PyExc_RuntimeError, "node is not valid");

  e=talloc_strdup(NULL, element);
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
      talloc_reference(python_talloc_context,root);

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
	/** We are about to return another reference to python.  When
	    python frees the reference we will call talloc free by
	    ourselves, so we must make sure that no one will try to
	    free this from under us.
	*/
	talloc_reference(python_talloc_context,node);
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
      PyObject *tmp=PyString_FromString(p->name);
      PyList_Append(pylist, tmp);
      Py_DECREF(tmp);
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

PyMODINIT_FUNC init_dissect(void) {
  // This is a talloc context which is used to own any objects passed
  // to python. This is better than assigning them to the null context
  // because talloc_reference works.
  python_talloc_context = talloc_strdup(NULL,"Python Owns this");

  (void) Py_InitModule("_dissect", DissectMethods);
  network_structs_init();
}
