/** This is the client end of the remote implementation. This is a
    python module which can be used to read remote devices. 

    The way you use this is:

    import remote

    r = remote.Login("192.168.1.1", port=3533);
    r.read_random(0,100)

*/
#include "remote.h"
#include <Python.h>
#include "structmember.h"

typedef struct {
  PyObject_HEAD
  int fd;
  RC4 rc4;
  uint64_t offset;
  StringIO queue;
} remote;

static void remote_dealloc(remote *self) {
  DEBUG("Closing connection %p\n", self);
  if(self->rc4)
    talloc_free(self->rc4);
  close(self->fd);
  self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
remote_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  struct remote *self;

  DEBUG("Calling new method\n");

  self = (struct remote *)type->tp_alloc(type, 0);
  return (PyObject *)self;
}

static int remote_init(remote *self, PyObject *args, PyObject *kwds) {
  char *keywords[] = { "host","device","port", "offset", NULL};
  int port=3533;
  char *host=NULL;
  int device_len;
  char *device=NULL;
  
  DEBUG("Initialising %p\n", self);
  DEBUG("self->fd is %u\n" , self->fd);
  self->fd = -1;
  self->rc4 = NULL;
  self->offset = 0;
  
  if(!PyArg_ParseTupleAndKeywords(args, kwds, "ss#|HK", keywords, &host, 
				  &device, &device_len,
				  &port, &self->offset)) {
    return -1;
  };

  /** Try to connect */
  {
    struct sockaddr_in addr,serv_addr;
    uint32_t host_ip;
    struct hostent *h;

    h=gethostbyname(host);
    if(!h) {
      PyErr_Format(PyExc_IOError, "Cant resolve name %s", host);
      return -1;
    };

    host_ip = *(uint32_t *)(h->h_addr_list[0]);

    memset(&(addr),0, sizeof(struct sockaddr_in));
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    addr.sin_addr.s_addr = host_ip;  
    
    self->fd = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(self->fd < 0) {
      PyErr_Format(PyExc_IOError,"Unable to get socket");
      return -1;
    };

    //Make a copy of the address structure because we might trash it
    memcpy(&(serv_addr), &(addr), sizeof(addr));
    
    //Try to connect to our target now:
    if(connect(self->fd,(struct sockaddr *)&(serv_addr),
	       sizeof(serv_addr)) == -1) {
      PyErr_Format(PyExc_IOError, "cant connect to %s\n", host);
      goto error;
    };
  };

  // Perform key exchange:
  {
    unsigned char key[16];
    char challenge[SIZEOF_CHALLENGE];
    uint32_t len = device_len;
    uint32_t version = REMOTE_VERSION;
    
    ecc_init();
    ecc_make_key((char *)key, challenge);
    
    self->rc4 = CONSTRUCT(RC4, RC4, Con, NULL, key, sizeof(key));
    self->queue = CONSTRUCT(StringIO, StringIO, Con, self->rc4);

    // Write the challenge:
    if(send(self->fd, challenge, sizeof(challenge), 
	    MSG_NOSIGNAL)< sizeof(challenge)) {
      goto write_error;
    };

    version = htonl(version);
    queue_for_sending(self->queue, (unsigned char *)&version, sizeof(version), self->rc4);
    len = htonl(len);
    queue_for_sending(self->queue, (unsigned char *)&len, sizeof(len), self->rc4);
    queue_for_sending(self->queue, (unsigned char *)device, device_len, self->rc4);

    if(!write_to_network(self->fd, self->queue)) goto write_error;
  };

  DEBUG("Logon complete\n");
  return 0;

 write_error:
  PyErr_Format(PyExc_IOError, "Unable to write to network.");
 error:
  return -1;
};


static PyObject *remote_read_random(remote *self, PyObject *args) {
  uint32_t len;
  uint64_t offs;
  PyObject *result;
  int length;

  if(!PyArg_ParseTuple(args, "lL", &len, &offs)) 
    return NULL;

  // Add the default offset from our constructor
  offs = offs + self->offset;

  //  DEBUG("Want to read %u from %llu\n", len, offs);

  // Issue the request to the remote end:
  {
    uint64_t offset = htonll(offs);
    uint32_t length = htonl(len);
    
    queue_for_sending(self->queue, (unsigned char *)&offset, sizeof(offset), self->rc4);
    queue_for_sending(self->queue, (unsigned char *)&length, sizeof(length), self->rc4);

    if(!write_to_network(self->fd, self->queue))
      goto write_error;
  };
  
  // Now read the data
  {
    unsigned char *buffer;
    uint32_t i;

    // Read the actual length
    if(!read_from_network(self->fd, &length, sizeof(length), self->rc4))
      goto read_error;

    length=ntohl(length);

    //    DEBUG("Will need to read %u\n", length);

    // Allocate some space for the request:
    result = PyString_FromStringAndSize(NULL, length);
    if(!result) return NULL;

    // This gets a reference to the internal string representation:
    buffer = PyString_AsString(result);

    if(!read_from_network(self->fd, buffer, length, self->rc4))
      goto read_error;
  };
  
  //  DEBUG("Read %u bytes\n", length);

  return result;

 read_error:
  Py_DECREF(result);
  return PyErr_Format(PyExc_IOError, "Unable to read from network.");

 write_error:
  Py_DECREF(result);
  return PyErr_Format(PyExc_IOError, "Unable to write to network.");
};

static PyMemberDef remote_members[] = {
  /*    {"size", T_ULONG, offsetof(remote, size), 0,
	"remote size"}, */
    {NULL}  /* Sentinel */
};

static PyMethodDef remote_methods[] = {
    {"read_random", (PyCFunction)remote_read_random, METH_VARARGS,
     "read data from given offset" },
    {NULL}  /* Sentinel */
};

static PyTypeObject remoteType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "remote.remote",       /* tp_name */
    sizeof(remote),          /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)remote_dealloc, /* tp_dealloc */
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
    "Remote connection to a pyflag servlet. usage remote.remote('host','device') ",         /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    remote_methods,          /* tp_methods */
    remote_members,          /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)remote_init,   /* tp_init */
    0,                         /* tp_alloc */
    remote_new,                         /* tp_new */
};

static PyMethodDef RemoteMethods[] = {
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initremote(void) {
    PyObject *m;

    m = Py_InitModule("remote", RemoteMethods);

    /* setup skfs type */
    remoteType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&remoteType) < 0)
        return;

    Py_INCREF(&remoteType);
    PyModule_AddObject(m, "remote", (PyObject *)&remoteType);
}
