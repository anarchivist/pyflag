"""  This file implements a memory store for python objects.

A memory store is a single semi/persistant storage for object
collections which ensure that memory resources are not exhausted. We
store a maximum number of objects, for a maximum length of time. When
objects expire they are deleted.

Objects are taken and returned to the store by their clients. Doing
this will refresh their age. This ensures that frequently used objects
remain young and therefore do not perish.

The store is also thread safe as a single thread is allowed to access
the store at any one time.
"""

import thread,time,re
import pyflag.pyflaglog as pyflaglog

class Store:
    """ Stores objects for a length of time.

    Objects may expire due to their age, or the maximum size of the
    store.

    Note: It is imperative that objects have no other references or
    deletion of objects from the store will not cause their
    destruction. Therefore, objects may only exist in the store or out
    of store (in the client) - never in both places.
    """
    def __init__(self, max_size=300, age=1800):
        """ max_size is the maximum number of objects in the store, age is their maximum age.
        """
        self.max_size = max_size
        self.max_age = age
        self.mutex = thread.allocate_lock()

        ## creation_times is an array of (time, key, object). The time
        ## is ordered in oldest first and newest last time order.
        self.creation_times = []
        self.id = 0

    def flush(self):
        self.mutex.acquire()
        self.creation_times = []
        self.mutex.release()
        
    def put(self,object, prefix='', key=None):
        """ Stores an object in the Store.  Returns the key for the
        object. If key is already supplied we use that instead - Note
        that we do not check that it doesnt already exist.
        """
        self.mutex.acquire()
        try:

            ## Ensure that we have enough space:
            self.check_full()

            ## Push the item in:
            now = time.time()
            if not key:
                key = "%s%s" % (prefix,self.id)
                
            self.creation_times.append([now,key, object])
            self.id+=1

        finally:
            self.mutex.release()

        pyflaglog.log(pyflaglog.VERBOSE_DEBUG,
                      "Stored key %s: %s" % (key,
                                             ("%r" % (object,))[:100]))
        return key

    def get(self, key):
        """ Retrieve the key from the store """
        self.mutex.acquire()

        try:
            ## Find and remove the object from the store
            i=0
            for t, k, obj in self.creation_times:
                if k==key:
                    ## Remove the object from the store:
                    t, k, obj = self.creation_times.pop(i)

                    ## Reinsert it into the cache at the most recent
                    ## time:
                    self.creation_times.append([time.time(), k, obj])
                    
                    self.check_full()
                    pyflaglog.log(pyflaglog.VERBOSE_DEBUG,
                                  "Got key %s: %s" % (key,
                                                      ("%r" % (obj,))[:100]))
                    return obj
                i+=1

            ## If we are here we could not find the key:
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Key %s not found" % (key))
            raise KeyError("Key not found %s" % key)

        finally:
            self.mutex.release()
        
    def check_full(self):
        """ Checks to ensure the Store is not full """
        ## Check to see if we store too many objects - remove oldest
        ## objects first:
        while len(self.creation_times)>self.max_size:
            t, key, o = self.creation_times.pop(0)
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Removed object %r because store is full" % (o,))

        ## Now ensure that objects are not too old:
        now = time.time()
        try:
            while 1:
                t,key,o = self.creation_times[0]
                if t+self.max_age < now:
                    self.creation_times.pop(0)
                    pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Removed object %r because it is too old" % (o,))
                else:
                    break
        except IndexError:
            pass

    def expire(self, regex):
        """ Automatially expire all objects with keys matching the regex """
        self.mutex.acquire()

        try:
            tmp = []
            for x in self.creation_times:
                if not re.search(regex, x[1]):
                    tmp.append(x)
            self.creation_times = tmp
        finally:
            self.mutex.release()

    def __iter__(self):
        for t, k, obj in self.creation_times:
            yield obj

## Store unit tests:
import unittest
import random, time

class StoreTests(unittest.TestCase):
    """ Store tests """
    def test01StoreExpiration(self):
        """ Testing store removes objects when full """
        s = Store(max_size = 5)
        keys = []
        for i in range(0,100):
            keys.append(s.put(i))

        self.assertRaises(KeyError, lambda : s.get(keys[0]))

        ## This should not raise
        s.get(keys[-1])

    def test02StoreRefresh(self):
        """ Test that store keeps recently gotten objects fresh """
        s = Store(max_size = 5)
        keys = []
        for i in range(0,5):
            keys.append(s.put(i))

        ## This should not raise because keys[0] should be refreshed
        ## each time its gotten
        for i in range(0,1000):
            s.get(keys[0])
            s.put(i)

    def test03Expire(self):
        """ Tests the expire mechanism """
        s = Store(max_size = 100)
        for i in range(0,5):
            s.put(i, key="test%s" % i)

        for i in range(0,5):
            s.put(i, key="tests%s" % i)

        s.expire("test\d+")
        ## Should have 5 "testsxxx" left
        self.assertEqual(len(s.creation_times),5)
