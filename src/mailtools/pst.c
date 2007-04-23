/** This is a python binding to libpst.
    
This was developed in order to incorporate libpst into PyFlag
(http://www.pyflag.net/).

There are a number of problems with incorporating this library. The
first is the huge number of fields available in each message. We wish
to make many of them accessible through python too. This is solved by
using macros to dump them into a python dict.

The second problem is that libpst is full of memory leaks so
incorporating into a long lived process like pyflag can be tricky. To
solve this problem we use talloc to convert the library to use the
talloc context as a global context. Each malloc is converted into a
talloc function with the global context, which is set upon entry to
the c layer. */
   
#include "talloc.h"
#include <Python.h>
#include "libpst.h"
#include "structmember.h"
#include "timeconv.h"
#include "time.h"

void *g_context;

void *xmalloc(size_t size) {
  return talloc_size(g_context, size);
};

typedef struct {
  PyObject_HEAD
  pst_file *pst;
  pst_item *item;
  pst_desc_ll *ptr;
} PstItem;

PyObject *PstItem_str(PstItem *self, PyObject *args) {
  PyObject *result=NULL;

  if(self->item->type == PST_TYPE_FOLDER || self->item->folder) {
    result = PyString_FromFormat("%s", self->item->file_as);
  } else if(self->item->type == PST_TYPE_NOTE && self->item->email) {
    result = PyString_FromFormat("%s", self->item->email->subject->subj);
    
  } else if(self->item->type == PST_TYPE_APPOINTMENT && self->item->email) {
    result = PyString_FromFormat("%s", self->item->email->subject->subj);
  } else if(self->item->type == PST_TYPE_CONTACT && self->item->contact) {
    result = PyString_FromFormat("%s", self->item->contact->fullname);
  } else
    result = PyString_FromFormat("(%d)", self->ptr->id);

  return result;
};

PyObject *PstItem_repr(PstItem *self, PyObject *args) {
  PyObject *result=NULL;

  if(self->item->type == PST_TYPE_FOLDER || self->item->folder) {
    result = PyString_FromFormat("(%d) Folder: %s", self->ptr->id,
				 self->item->file_as);
  } else if(self->item->type == PST_TYPE_NOTE && self->item->email) {
    result = PyString_FromFormat("(%d) Email. Subject: %s" ,self->ptr->id,
				 self->item->email->subject->subj);
    
  } else if(self->item->type == PST_TYPE_APPOINTMENT && self->item->email) {
    result = PyString_FromFormat("(%d) Calendar: %s" ,self->ptr->id,
				 self->item->email->subject->subj);
  } else if(self->item->type == PST_TYPE_CONTACT && self->item->contact) {
    result = PyString_FromFormat("(%d) Contact: %s" ,self->ptr->id,
				 self->item->contact->fullname);
  } else
    result = PyString_FromFormat("(%d) Unknown", self->ptr->id);

  return result;
};

/** A helper function to set an item in the dict */
PyObject *set_item(PyObject *dict, char *name, char *format, void *value) {
  if(value) {
    PyObject *tmp;
    int tmp2;

    tmp = PyString_FromFormat(format, value);
    tmp2 = PyDict_SetItemString(dict, name, tmp);
    Py_DECREF(tmp);
    if(tmp2 <0) return NULL;
  };		
					       
  return dict;
};

#define SET_ITEM(dict, name, format, value)		\
  if(set_item(dict, name, format, value)==0) goto error;

#define SET_TIME(dict, name, value)					\
  if(value) {								\
    time_t t = fileTimeToUnixTime(value,NULL);				\
    if(set_item(dict, name, "%d", (char *)t)==0) goto error;		\
    if(set_item(dict, name "_str", "%s", ctime(&t))==0) goto error;	\
  };

// Return a dict of properties:
PyObject *PstItem_Properties(PstItem *self, PyObject *args) {
  PyObject *result = PyDict_New();
  if(!result) return NULL;

  // All items have these common things:
  SET_ITEM(result, "Type", "%s" , self->item->ascii_type);
  SET_TIME(result, "create_date", self->item->create_date);
  SET_TIME(result, "modify_date", self->item->modify_date);

  // FOLDERS
  if(self->item->type == PST_TYPE_FOLDER && self->item->folder) {
#define SET_ITEM_S(value) SET_ITEM(result, #value, "%s", self->item->value)
    SET_ITEM_S(file_as);
    SET_ITEM_S(comment);
    SET_ITEM(result, "Count", "%d", (char *)self->item->folder->email_count);

    // CONTACTS:
  } else if(self->item->type == PST_TYPE_CONTACT && self->item->contact) {
#define SET_CONTACT(value)	 SET_ITEM(result, #value, "%s", self->item->contact->value)
    SET_CONTACT(fullname);
    SET_CONTACT(access_method);
    SET_CONTACT(account_name);
    SET_CONTACT(address1);
    SET_CONTACT(address1_desc);
    SET_CONTACT(address1_transport);
    SET_CONTACT(address2);
    SET_CONTACT(address2_desc);
    SET_CONTACT(address2_transport);
    SET_CONTACT(address3);
    SET_CONTACT(address3_desc);
    SET_CONTACT(address3_transport);
    SET_CONTACT(assistant_name);
    SET_CONTACT(assistant_phone);
    SET_CONTACT(billing_information);
    SET_TIME(result, "birthday", self->item->contact->birthday);
    SET_CONTACT(business_address);
    SET_CONTACT(business_city);
    SET_CONTACT(business_country);
    SET_CONTACT(business_fax);
    SET_CONTACT(business_homepage);
    SET_CONTACT(business_phone);
    SET_CONTACT(business_phone2);
    SET_CONTACT(business_po_box);
    SET_CONTACT(business_postal_code);
    SET_CONTACT(business_state);
    SET_CONTACT(business_street);
    SET_CONTACT(callback_phone);
    SET_CONTACT(car_phone);
    SET_CONTACT(company_main_phone);
    SET_CONTACT(company_name);
    SET_CONTACT(computer_name);
    SET_CONTACT(customer_id);
    SET_CONTACT(def_postal_address);
    SET_CONTACT(department);
    SET_CONTACT(display_name_prefix);
    SET_CONTACT(first_name);
    SET_CONTACT(followup);
    SET_CONTACT(free_busy_address);
    SET_CONTACT(ftp_site);
    SET_CONTACT(fullname);
    SET_CONTACT(gov_id);
    SET_CONTACT(hobbies);
    SET_CONTACT(home_address);
    SET_CONTACT(home_city);
    SET_CONTACT(home_country);
    SET_CONTACT(home_fax);
    SET_CONTACT(home_phone);
    SET_CONTACT(home_phone2);
    SET_CONTACT(home_po_box);
    SET_CONTACT(home_postal_code);
    SET_CONTACT(home_state);
    SET_CONTACT(home_street);
    SET_CONTACT(initials);
    SET_CONTACT(isdn_phone);
    SET_CONTACT(job_title);
    SET_CONTACT(keyword);
    SET_CONTACT(language);
    SET_CONTACT(location);
    SET_CONTACT(manager_name);
    SET_CONTACT(middle_name);
    SET_CONTACT(mileage);
    SET_CONTACT(mobile_phone);
    SET_CONTACT(nickname);
    SET_CONTACT(office_loc);
    SET_CONTACT(org_id);
    SET_CONTACT(other_address);
    SET_CONTACT(other_city);
    SET_CONTACT(other_country);
    SET_CONTACT(other_phone);
    SET_CONTACT(other_po_box);
    SET_CONTACT(other_postal_code);
    SET_CONTACT(other_state);
    SET_CONTACT(other_street);
    SET_CONTACT(pager_phone);
    SET_CONTACT(personal_homepage);
    SET_CONTACT(pref_name);
    SET_CONTACT(primary_fax);
    SET_CONTACT(primary_phone);
    SET_CONTACT(profession);
    SET_CONTACT(radio_phone);
    SET_CONTACT(spouse_name);
    SET_CONTACT(suffix);
    SET_CONTACT(surname);
    SET_CONTACT(telex);
    SET_CONTACT(transmittable_display_name);
    SET_CONTACT(ttytdd_phone);
    SET_TIME(result, "wedding_anniversary", self->item->contact->wedding_anniversary);

    // TASKS
  } else if(self->item->type == PST_TYPE_NOTE && self->item->email) {
    struct _pst_item_attach *attachment=self->item->attach;

#define SET_EMAIL(value)	 SET_ITEM(result, #value, "%s", self->item->email->value)
    SET_TIME(result, "arrival_date", self->item->email->arrival_date);
    SET_EMAIL(body);
    SET_EMAIL(cc_address);
    SET_EMAIL(common_name);
    SET_EMAIL(header);
    SET_EMAIL(htmlbody);
    SET_EMAIL(in_reply_to);
    SET_EMAIL(messageid);
    SET_EMAIL(outlook_recipient);
    SET_EMAIL(outlook_recipient2);
    SET_EMAIL(outlook_sender);
    SET_EMAIL(outlook_sender_name);
    SET_EMAIL(outlook_sender2);
    SET_EMAIL(proc_subject);
    SET_EMAIL(recip_access);
    SET_EMAIL(recip_address);
    SET_EMAIL(recip2_access);
    SET_EMAIL(recip2_address);
    SET_EMAIL(reply_to);
    SET_EMAIL(return_path_address);
    SET_EMAIL(sender_access);
    SET_EMAIL(sender_address);
    SET_EMAIL(sender2_access);
    SET_EMAIL(sender2_address);
    SET_EMAIL(sentto_address);
    SET_ITEM(result, "Subject", "%s", self->item->email->subject->subj);
    SET_TIME(result, "sent_date", self->item->email->sent_date);

    
    if(attachment) {
      PyObject *attach_list = PyList_New(0);
      
      /** With emails we need to pass back the attachments.
	  Each attachment is represented as a dict.
      */
      for(;attachment;attachment=attachment->next) {
	PyObject *attach_dict = PyDict_New();
	unsigned char *buff = NULL;
	int size;

	PyObject *body;

	if(attachment->data) {
	  body = PyString_FromStringAndSize(attachment->data, attachment->size);
	} else {
	  size = pst_attach_to_mem(self->pst, attachment, &buff);
	  body = PyString_FromStringAndSize(buff, size);

	  if(buff) talloc_free(buff);
	};
	SET_ITEM(attach_dict, "filename1", "%s", attachment->filename1);
	SET_ITEM(attach_dict, "filename2", "%s", attachment->filename2);
	SET_ITEM(attach_dict, "mime", "%s", attachment->mimetype);

	PyDict_SetItemString(attach_dict, "body", body);
	Py_DECREF(body);

	PyList_Append(attach_list, attach_dict);
	Py_DECREF(attach_dict);
      };

      PyDict_SetItemString(result, "_attachments", attach_list);
      Py_DECREF(attach_list);
    };

    // Appointments
  } else if(self->item->type == PST_TYPE_APPOINTMENT && self->item->appointment) {
    SET_ITEM(result, "Subject", "%s", self->item->email->subject->subj);
    SET_TIME(result, "sent_date", self->item->email->sent_date);    
    SET_TIME(result, "start", self->item->appointment->start);
    SET_TIME(result, "end", self->item->appointment->end);

    // Others
  } else if(self->item->type == PST_TYPE_OTHER && self->item->email) {
    SET_EMAIL(proc_subject);    
  };

  return result;

 error:
  Py_DECREF(result);
  return NULL;
};

#if 0
/** This uses the standard python email package to produce a proper
    rfc2822 message 
*/
PyObject *PstItem_as_email(PstItem *self, PyObject *args) {
  PyObject *email_module;
  PyObject *email;
  PyObject *headers;
  struct pst_item_attach *attach;

  if(self->item->type!=PST_TYPE_NOTE || !self->item->email)
    return PyErr_Format(PyExc_RuntimeError, "This item is not an email");

  email_module = PyImport_ImportModule("email.Parser");
  if(!email_module) return NULL;

  email = PyObject_CallMethod(email_module, "Parser", NULL);
  if(!email) goto error;

  headers = PyObject_CallMethod(email, "parsestr", "si",
				(char *)self->item->email->header, 1);
  if(!headers) goto error;

  attach = self->item->attach;
  // Now we need to put the attachments in there if possible:
  if(attach) {
    PyObject *part;
    PyObject *iterator = PyObject_CallMethod(headers, "get_payload", NULL);
    if(!iterator) goto error;
    
    if(!PyIter_Check(iterator)) {
      PyErr_Format(PyExc_RuntimeError, "get_payload did not return a generator?");
      Py_DECREF(iterator);
      goto error;
    };

    while(1) {
      part = PyIter_Next(iterator);
      if(!part) break;

    };

    Py_DECREF(iterator);
  };

  Py_DECREF(email_module);

  return email;

 error:
  Py_DECREF(email_module);
  return NULL;
};
#endif

PyObject *PstItem_get_id(PstItem *self, PyObject *args) {
  return PyInt_FromLong(self->ptr->id);
};

static PyMethodDef PstItem_methods[] = {
  {"get_id", (PyCFunction)PstItem_get_id, METH_VARARGS,
   "Get the id of this item - this can be used with PstFile to retrive this item again"},
  /*  {"email", (PyCFunction)PstItem_as_email, METH_VARARGS,
      "Returns an email object from this item"},*/
  {"properties", (PyCFunction)PstItem_Properties, METH_VARARGS,
   "Returns a dict of properties of this item"},
  { NULL }
};

static PyTypeObject PstItemType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "pst.PstItem",             /* tp_name */
    sizeof(PstItem),           /* tp_basicsize */
    0,                         /* tp_itemsize */
    0,                         /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    (reprfunc)PstItem_repr,    /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    (reprfunc)PstItem_str,     /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    "Pst Item Object",         /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    PstItem_methods,           /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                         /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

typedef struct {
  PyObject_HEAD
  void *context;
  pst_file pst;
  // That is the root item
  PstItem *root;
} PstFile;

static void PstFile_dealloc(PstFile *self) {
  // Close the pst file.
  pst_close(&self->pst);

  // Free all memory associated with it
  //talloc_free(self->context);
  self->ob_type->tp_free((PyObject*)self);
};

static int PstFile_init(PstFile *self, PyObject *args) {
  char *filename;

  if(!PyArg_ParseTuple(args, "s", &filename))
    return -1;

  // All libpst allocations occur with this context:
  self->context = talloc_named_const(NULL, 0, "main context");
  g_context = self->context;

  // Try to open the file:
  if(pst_open(&self->pst, filename, "r") < 0) {
    PyErr_Format(PyExc_IOError, "Unable to open %s" , filename);
    return -1;
  };

  //Load index:
  if(pst_load_index(&self->pst) < 0) {
    PyErr_Format(PyExc_IOError, "Unable to read indexes");
    return -1;
  };

  // Load extended attributes:
  if(pst_load_extended_attributes(&self->pst) < 0) {
    PyErr_Format(PyExc_IOError, "Unable to read extended attributes");
    return -1;
  } else {
    self->root = PyObject_New(PstItem, &PstItemType);
    self->root->pst = &self->pst;
    self->root->item = _pst_parse_item(&self->pst, self->pst.d_head);
    self->root->ptr = pst_getTopOfFolders(&self->pst, self->root->item);
  };

  return 0;
};

static PyObject *PstFile_get_item_by_id(PstFile *self, PyObject *args) {
  struct _pst_desc_tree *ptr;
  int item_id;
  PstItem *item;

  if(!PyArg_ParseTuple(args, "l", &item_id))
    return NULL;

  ptr = _pst_getDptr(&self->pst, item_id);

  if(!ptr)
    return PyErr_Format(PyExc_RuntimeError, "Unable to find Item");

  item = PyObject_New(PstItem, &PstItemType);
  if(item) {
    item->ptr = ptr;
    item->pst = &self->pst;
    item->item = _pst_parse_item(&self->pst, ptr);
  };

  return (PyObject *)item;
};

static PyObject *PstFile_listitems(PstFile *self, PyObject *args) {
  PyObject *result;
  struct _pst_desc_tree *ptr;
  PstItem *item=self->root;

  if(!PyArg_ParseTuple(args, "|O", &item))
    return NULL;

  if((PyObject *)item == Py_None) {
    item = self->root;
  } else if(item->ob_type != &PstItemType) 
    return PyErr_Format(PyExc_RuntimeError, "Expected a PstType object - try calling listitems with no args");

  ptr = item->ptr->child;
  result = PyList_New(0);
  
  while(ptr) {
    // Create the items and return them:
    PstItem *new_item = PyObject_New(PstItem, &PstItemType);

    if(!new_item) 
      goto error;

    new_item->pst = &self->pst;
    new_item->item = _pst_parse_item(&self->pst, ptr);
    new_item->ptr = ptr;

    PyList_Append(result, (PyObject *)new_item);

    ptr = ptr->next;
  };
  
  return result;

 error:
  Py_DECREF(result);
  return NULL;
};

static PyMethodDef PstFile_methods[] = {
  {"get_item", (PyCFunction)PstFile_get_item_by_id, METH_VARARGS,
   "Gets the specified item by id"},
  {"listitems", (PyCFunction)PstFile_listitems, METH_VARARGS,
   "return a tuple of lists of tuples (dirs, nondirs) of all the items in this folder. Takes a single item ID "},
  { NULL }
};

static PyTypeObject PstFileType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "pst.PstFile",             /* tp_name */
    sizeof(PstFile),          /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)PstFile_dealloc, /* tp_dealloc */
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
    "Pst File Object",         /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    PstFile_methods,          /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)PstFile_init, /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

static PyMethodDef PstMethods[] = {
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initpst(void) {

    PyObject *m;
#ifdef __DEBUG_V_
    talloc_enable_leak_report_full();
#endif

    m = Py_InitModule("pst", PstMethods);

    PstFileType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&PstFileType) < 0)
        return;

    Py_INCREF(&PstFileType);

    PstItemType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&PstItemType) < 0)
        return;

    Py_INCREF(&PstItemType);

    PyModule_AddObject(m, "PstFile", (PyObject *)&PstFileType);
}
