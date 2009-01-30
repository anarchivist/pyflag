# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Copyright (C) 2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""
import sys, StringIO
sys.path.append(".")
sys.path.append("..")

from vtypes import xpsp2types as types
from forensics.win32.overlay import xpsp2overlays
from forensics.object import *
from forensics.x86 import x86_native_types
import forensics.registry as MemoryRegistry
import struct
import forensics.addrspace as addrspace

class Curry:
    """ This class makes a curried object available for simple inlined functions.

    A curried object represents a function which has some of its
    arguements pre-determined. For example imagine there is a
    function:

    def foo(a=a,b=b):
        pass

    curry=Curry(foo,a=1)   returns a function pointer.

    curry(3) is the same as calling foo(a=1,b=3).
    For more information see the Oreilly Python Cookbook.
    """
    def __init__(self,function,*args,**kwargs):
        """ Initialised the curry object with the correct function."""
        self.fun=function
        self.pending = args[:]
        self.kwargs = kwargs.copy()

    def __call__(self,*args,**kwargs):
        if kwargs and self.kwargs:
            kw=self.kwargs.copy()
            kw.update(kwargs)
        else:
            kw = kwargs or self.kwargs
            
        return self.fun(*(self.pending+args), **kw)

import sys
import traceback
import cStringIO

def get_bt_string(e=None):    
    return ''.join(traceback.format_stack()[:-3])

class NoneObject(object):
    """ A magical object which is like None but swallows bad
    dereferences, __getattribute__, iterators etc to return itself.

    Instantiate with the reason for the error.
    """
    def __init__(self, reason, strict=False):
        self.reason = reason
        self.strict = strict
        if strict:
            self.bt = get_bt_string()

    def __str__(self):
        ## If we are strict we blow up here
        if self.strict:
            result = "Error: %s\n%s" % (self.reason, self.bt)
            print result
            sys.exit(0)
        else:
            return "Error: %s" % (self.reason)

    ## Behave like an empty set
    def __iter__(self):
        return self

    def next(self):
        raise StopIteration()

    def __getattribute__(self,attr):
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            return self

    def __bool__(self):
        return False

    def __nonzero__(self):
        return False

    def __eq__(self, other):
        return False

    ## Make us subscriptable obj[j]
    def __getitem__(self, item):
        return self

    def __add__(self, x):
        return self

    def __sub__(self, x):
        return self

    def __int__(self):
        return -1

    def __call__(self, *arg, **kwargs):
        return self
        
class InvalidType(Exception):
    def __init__(self, typename=None):
        self.typename = typename

    def __str__(self):
	return str(self.typename)

class InvalidMember(Exception):
    def __init__(self, typename=None, membername=None):
        self.typename = typename
	self.membername = membername

    def __str__(self):
        return str(self.typename) + ":" + str(self.membername)

def NewObject(theType, offset, vm, parent=None, profile=None, name=None, **kwargs):
    """ A function which instantiates the object named in theType (as
    a string) from the type in profile passing optional args of
    kwargs.
    """
    if name==None: name=theType

    offset = int(offset)
    
    ## If we cant instantiate the object here, we just error out:
    if not vm.is_valid_address(offset):
        return NoneObject("Invalid Address 0x%08X, instantiating %s from %s"\
                          % (offset, name, parent), strict=profile.strict)

    if theType in profile.types:
        result = profile.types[theType](offset=offset, vm=vm, name=name,
                                        parent=parent, profile=profile)
        return result
    

    # Need to check for any derived object types that may be 
    # found in the global memory registry.
    try:
        if theType:
            if MemoryRegistry.OBJECT_CLASSES.objects.has_key(theType):
                return MemoryRegistry.OBJECT_CLASSES[theType](
                    theType,
                    offset,
                    vm = vm, parent=parent, profile=profile, name=name,
                    **kwargs)
    except AttributeError:
        pass

class Object(object):        
    def __init__(self, theType, offset, vm, parent=None, profile=None, name=None):
        self.vm = vm
	self.members = {}
	self.parent = parent
	self.extra_members = {}
	self.profile = profile
	self.offset = offset
        self.name = name
        self.theType = theType

    def __add__(self, other):
        return other + self.v()

    def __mul__(self, other):
        return other * self.v()

    def __sub__(self, other):
        return -other + self.v()

    def __neg__(self):
        return -self.v()
    
    def __eq__(self, other):
        if isinstance(other, Object):
	   return (self.__class__ == other.__class__) and (self.offset == other.offset)
	else:
	   return NotImplemented

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.name) ^ hash(self.offset)

    def has_member(self, memname):
        return False

    def m(self, memname):
        return self.get_member(memname)

    def get_member(self, memname):
        raise AttributeError("No member %s" % memname)

    def get_member_offset(self, memname, relative=False):
        return self.offset

    def is_null(self):
        return False

    def is_valid(self):
        return self.vm.is_valid_address(self.offset)

    def dereference(self):
        return NoneObject("Cant derenference %s" % self.name, self.profile.strict)

    def dereference_as(self, derefType):
        return NewObject(derefType, self.v(), \
                         self.vm, parent=self ,profile=self.profile)

    def cast(self, castString):
        return Object(castString, self.offset, self.vm, None, self.profile)

    def v(self):
        return self.value()

    def value(self):
        """ Do the actual reading and decoding of this member
        """
        return NoneObject("No value for %s" % self.name, self.profile.strict)

    def get_member_names(self):
        return False

    def get_bytes(self,amount=None):
        if amount == None:
            amount = self.size()

        return self.vm.read(self.offset, amount)

    def get_values(self):
        value_dict = {}
        for k in self.get_member_names():
            value_dict[k] = self.m(k).v()
        return value_dict

    def __str__(self):
        return "[%s %s] @ 0x%08X" % (self.__class__.__name__, self.name or '',
                                     self.offset)

class VType:
    """ This is a proxy class for members in the struct.

    We use proxy classes to fill in members in the struct so we dont
    need to dereference them until we want to.
    """
    def __init__(self, profile, size, hasMembers=False, hasValue=False):
        self.profile = profile
        self.hasMembers=hasMembers
        self.hasValue=hasValue
        self.size = size
    
    def cdecl(self):
        return "VType"

class NativeType(Object):
    def __init__(self, theType, offset, vm, parent=None, profile=None,
                 format_string=None, name=None, **args):
        Object.__init__(self, theType, offset, vm, parent=parent,
                        profile=profile, name=name)
        self.format_string = format_string

    def size(self):
        return struct.calcsize(self.format_string)

    def value(self):
        (val, ) = struct.unpack(self.format_string, \
                                self.vm.read(self.offset, self.size()))
        return val

    def cdecl(self):
        return self.name

    def __int__(self):
        return self.v()

    def __eq__(self, other):
        return self.v() == other

    def __hex__(self):
        return hex(self.v())

    def __str__(self):
        return " [%s]: %s" % (self.theType, self.v())

    def __and__(self, other):
        return int(self) & other

    def __mod__(self, other):
        return int(self) % other

class Void(NativeType):
    def __init__(self, theType, offset, vm, parent=None, profile=None,
                 format_string=None, **args):
        NativeType.__init__(self, theType, offset, vm, parent=None, profile=None)
        self.format_string = "=L"

    def cdecl(self):
        return "0x%08X" % self.v()
    
    def __str__(self):
        return "Void (0x0%08X)" % self.v()

    def dereference_as(self, derefType):
        return NewObject(derefType, self.v(), \
                         self.vm, parent=self,profile=self.profile)

class Pointer(NativeType):
    def __init__(self, theType, offset, vm, parent=None, profile=None, target=None, name=None):
        NativeType.__init__(self, theType, offset = offset, vm=vm, name=name,
                            parent=parent, profile=profile)
        
        self.target = target
        self.format_string = "=L"

    def is_valid(self):
        """ Returns if what we are pointing to is valid """
        return self.vm.is_valid_address(self.v())

    def dereference(self):
        offset = self.v()
        if self.vm.is_valid_address(offset):
            result = self.target(offset=offset, vm=self.vm, parent=self.parent,
                                 profile=self.profile, name=self.name)
            return result
        else:
            return NoneObject("Pointer %s invalid" % self.name, self.profile.strict)

    def cdecl(self):
        return "Pointer %s" % self.v()

    def __repr__(self):
        return "<pointer to [%s ]>" % (self.v())

    def __str__(self):
        return "<%s pointer to [0x%08X]>" % (self.dereference().__class__.__name__, self.v())

    def __int__(self):
        return self.v()

    def __getattribute__(self, attr):
        try:
            return super(Pointer,self).__getattribute__(attr)
        except AttributeError:
            ## We just dereference ourself
            result = self.dereference()

            #if isinstance(result, CType):
            #    return result.m(attr)
            return result.__getattribute__(attr)

class CTypeMember:
    """ A placeholder for a type in a struct.

    We use this intermediate placeholder so we dont need to
    instantiate theType right away. This is done on demand.
    """
    def __init__(self, name, offset, theType):
        self.name = name
        self.offset = offset
        self.type = theType
        
class XXCType(VType):
    def __init__(self, profile, name, size, members, isStruct):
        VType.__init__(self, profile, size, True, False)
        self.name = name
        self.members = members
        self.isStruct = isStruct

    def add_member(self, name, member):
        self.members[member.name] = member

    def set_members(self, members):
        self.members = members

    def get_member_names(self):
        return self.members.keys()

    def get_member_type(self, memname):
        return self.members[memname].type

    def get_member_offset(self, memname):
        return self.members[memname].offset

    def get_member(self, memname):
        return self.members[memname]

    def is_struct(self):
        return self.isStruct

    def cdecl(self):
        if self.isStruct:
            return "struct %s" % self.name
        else:
            return "union %s" % self.name

class Array(Object):
    """ An array of objects of the same size """
    def __init__(self, targetType, offset, vm, parent=None,
                 profile=None, count=1, name=None, target=None):
        ## Instantiate the first object on the offset:
        Object.__init__(self, targetType, offset, vm,
                        parent=parent, profile=profile,
                        name=name)
        try:
            count = count(parent)
        except TypeError,e:
            pass
        
        self.count = int(count)

        self.position = 0
        self.original_offset = offset
        self.target = target
        self.current = self.target(offset=offset, vm=vm, parent=self,
                                       profile=profile, name= name)
        
    def __iter__(self):
        self.position = 0
        return self

    def size(self):
        return self.count * self.current.size()

    def next(self):
        if self.position >= self.count:
            raise StopIteration()

        offset = self.original_offset + self.position * self.current.size()
        self.position += 1

        ## Instantiate the target here:
        if self.vm.is_valid_address(offset):
            return self.target(offset = offset, vm=self.vm,
                               profile=self.profile, parent=self,
                               name="%s %s" % (self.name, self.position))
        else:
            return NoneObject("Array %s, Invalid position %s" % (self.name, self.position),
                              self.profile.strict)
        
    def __str__(self):
        return "Array (len=%s of %s)\n" % (self.count, self.current.name)

    def __repr__(self):
        result = [ x.__str__() for x in self ]
        return "<Array %s >" % (",".join(result))

    def __eq__(self, other):
        if self.count != len(other):
            return False
        
        for i in range(self.count):
            if not self[i]==other[i]:
                return False

        return True
    
    def __getitem__(self, pos):        
        ## Check if the offset is valid
        offset = self.original_offset + \
                 pos * self.current.size()
        if pos <= self.count and self.vm.is_valid_address(offset):
            return self.target(offset = offset,
                               vm=self.vm, parent=self,
                               profile=self.profile)
        else:
            return NoneObject("Array %s invalid member %s" % (self.name, pos),
                              self.profile.strict)
        
class CType(Object):
    """ A CType is an object which represents a c struct """
    def __init__(self, theType, offset, vm, parent=None, profile=None, members=None, name=None, size=0):
        """ This must be instantiated with a dict of members. The keys
        are the offsets, the values are Curried Object classes that
        will be instanitated when accessed.
        """
        if not members: raise RuntimeError()
        
        Object.__init__(self, theType, offset, vm, parent=parent, profile=profile, name=name)
        self.members = members
        self.offset = offset
        self.struct_size = size

    def size(self):
        return self.struct_size

    def __str__(self):
        return "[%s %s] @ 0x%08X" % (self.__class__.__name__, self.name or '', 
                                     self.offset)
    def __repr__(self):
        result = ''
        for k,v in self.members.items():
            result += " %s -\n %s\n" % ( k, self.m(k))

        return result

    def value(self):
        """ When a struct is evaluated we just return our offset.
        """
        return self.offset

    def m(self, attr):
        try:
            offset, cls = self.members[attr]
        except KeyError:
            raise AttributeError("Struct %s has no member %s" % (self.name, attr))

        try:
            ## If offset is specified as a callable its an absolute
            ## offset
            offset = int(offset(self))
        except TypeError:
            ## Otherwise its relative to the start of our struct
            offset = int(offset) + int(self.offset)

        result = cls(offset = offset, vm=self.vm,
                     profile=self.profile, parent=self, name=attr)

        return result

    def __getattribute__(self,attr):
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            pass

        try:
            return object.__getattribute__(self, "_"+attr)(attr)
        except: pass
        
        return self.m(attr)
    
## Profiles are the interface for creating/interpreting
## objects

class Profile:
    """ A profile is a collection of types relating to a certain
    system. We parse the abstract_types and join them with
    native_types to make everything work together.
    """
    def __init__(self, native_types=x86_native_types, abstract_types=types,
                 overlay=xpsp2overlays, strict=False):
        self.types = {}
        self.strict = strict
        
        # Load the native types
        for nt, value in native_types.items():
            if type(value)==list:
                self.types[nt] = Curry(NativeType, nt, format_string=value[1])

        self.import_typeset(abstract_types, overlay)

        # Load the abstract data types
    def import_typeset(self, abstract_types, overlay={}):
        for name, value in abstract_types.items():
           self.import_type(name, abstract_types, overlay)
	
    def import_type(self, ctype, typeDict, overlay):
        """ Parses the abstract_types by converting their string
        representations to class instances.
        """
        self.types[ctype] = self.convert_members(ctype, typeDict, overlay)

    def add_types(self, addDict):
        self.import_typeset(addDict)
        
    def list_to_type(self, name, typeList, typeDict=None):
        """ Parses a specification list and returns a VType object.

        This function is a bit complex because we support lots of
        different list types for backwards compatibility.
        """
        ## This supports plugin memory objects:
        #if typeList[0] in MemoryRegistry.OBJECT_CLASSES.objects:
        #    print "Using plugin for %s" % 

        try:
            args = typeList[1]

            if type(args)==dict:
                ## We have a list of the form [ ClassName, dict(.. args ..) ]
                return Curry(NewObject, theType=typeList[0], name=name,
                             **args)
        except (TypeError,IndexError),e:
            pass

        ## This is of the form [ 'void' ]
        if typeList[0] == 'void':
            return Curry(Void, Void, name=name)

        ## This is of the form [ 'pointer' , [ 'foobar' ]]
        if typeList[0] == 'pointer':
            return Curry(Pointer, Pointer,
                         name = name,
                         target=self.list_to_type(name, typeList[1], typeDict))

        ## This is an array: [ 'array', count, ['foobar'] ]
        if typeList[0] == 'array':
            return Curry(Array, Array,
                         name = name, count=typeList[1],
                         target=self.list_to_type(name, typeList[2], typeDict))

        ## This is a list which refers to a type which is already defined
        if typeList[0] in self.types:
            return Curry(self.types[typeList[0]], name=name)

        ## Does it refer to a type which will be defined in future? in
        ## this case we just curry the NewObject function to provide
        ## it on demand. This allows us to define structures
        ## recursively.
        ##if typeList[0] in typeDict:
        if 1:
            try:
                args = typeList[1]
            except IndexError: args = {}
            
            obj_name = typeList[0]
            return Curry(NewObject, obj_name, name=name, **args)

        ## If we get here we have no idea what this list is
        #raise RuntimeError("Error in parsing list %s" % (typeList))
        print "Warning - Unable to find a type for %s, assuming int" % typeList[0]
        return Curry(self.types['int'], name=name)

    def get_obj_offset(self, name, member):
        """ Returns a members offset within the struct """
        tmp = self.types[name](name,None, profile=self)
        offset, cls = tmp.members[member]
        
        return offset

    def apply_overlay(self, type_member, overlay):
        """ Update the overlay with the missing information from type.

        Basically if overlay has None in any alot it gets applied from vtype.
        """
        if not overlay: return type_member

        if type(type_member)==dict:
            for k,v in type_member.items():
                if k not in overlay:
                    overlay[k] = v
                else:
                    overlay[k] = self.apply_overlay(v, overlay[k])
                    
        elif type(overlay)==list:
            if len(overlay)!=len(type_member): return overlay
            
            for i in range(len(overlay)):
                if overlay[i]==None:
                    overlay[i] = type_member[i]
                else:
                    overlay[i] = self.apply_overlay(type_member[i], overlay[i])

        return overlay
        
    def convert_members(self, cname, typeDict, overlay):
        """ Convert the member named by cname from the c description
        provided by typeDict into a list of members that can be used
        for later parsing.

        cname is the name of the struct.
        
        We expect typeDict[cname] to be a list of the following format

        [ Size of struct, members_dict ]

        members_dict is a dict of all members (fields) in this
        struct. The key is the member name, and the value is a list of
        this form:

        [ offset_from_start_of_struct, specification_list ]

        The specification list has the form specified by self.list_to_type() above.

        We return a list of CTypeMember objects. 
        """
        ctype = self.apply_overlay(typeDict[cname], overlay.get(cname))
        members = {}
        size = ctype[0]
        for k,v in ctype[1].items():
            members[k] = (v[0], self.list_to_type(k, v[1], typeDict))

        ## Allow the plugins to over ride the class constructor here
        if MemoryRegistry.OBJECT_CLASSES and \
               cname in MemoryRegistry.OBJECT_CLASSES.objects:
            cls = MemoryRegistry.OBJECT_CLASSES[cname]
        else:
            cls = CType
        
        return Curry(cls, cls, members=members, size=size)

class BufferAddressSpace(addrspace.FileAddressSpace):
    def __init__(self, buff):
        self.fname = "Buffer"
        self.fhandle = StringIO.StringIO(buff)
        self.fsize = len(buff)

if __name__=='__main__':
    ## If called directly we run unit tests on this stuff
    import unittest

    class ObjectTests(unittest.TestCase):
        """ Tests the object implementation. """

        def make_object(self, obj, offset, type, data):
            address_space = BufferAddressSpace(data)
            profile = Profile(abstract_types=type)
            o = NewObject(obj, offset, address_space, profile=profile)
            
            return o
        
        def test01SimpleStructHandling(self):
            """ Test simple struct handling """
            mytype = {
                "HEADER": [ 0x20,
                            { 'MAGIC': [ 0x00, ['array', 3, ['char'] ]],
                              'Size': [ 0x04, ['unsigned int']],
                              'Count': [ 0x08, ['unsigned short int']],
                              }],
                }

            test_data = "ABAD\x06\x00\x00\x00\x02\x00\xff\xff"

            o = self.make_object('HEADER', 0, mytype, test_data)
            ## Can we decode ints?
            self.assertEqual(o.Size.v(), 6)
            self.assertEqual(int(o.Size), 6)
            self.assertEqual(o.Size + 6, 12)
            self.assertEqual(o.Size - 3, 3)
            self.assertEqual(o.Size + o.Count, 8)
            
            ## This demonstrates how array members print out
            print o.MAGIC[0], o.MAGIC[1]

            ## test comparison of array members
            self.assertEqual(o.MAGIC[0], 'A')
            self.assertEqual(o.MAGIC[0], o.MAGIC[2])
            self.assertEqual(o.MAGIC, ['A','B','A'])
            self.assertEqual(o.MAGIC, 'ABA')
            
            ## Iteration over arrays:
            tmp = 'ABA'
            count = 0
            for t in o.MAGIC:
                self.assertEqual(t,tmp[count])
                count+=1

        def test02Links(self):
            """ Tests intrastruct links, pointers etc """
            mytype = {
                '_LIST_ENTRY' : [ 0x8, { \
                      'Flink' : [ 0x0, ['pointer', ['_LIST_ENTRY']]], \
                      'Blink' : [ 0x4, ['pointer', ['_LIST_ENTRY']]], \
                      } ],
                '_HANDLE_TABLE' : [ 0x44, { \
                      'TableCode' : [ 0x0, ['unsigned long']], \
                      'UniqueProcessId' : [ 0x8, ['pointer', ['void']]], \
                      'HandleTableList' : [ 0x1c, ['_LIST_ENTRY']], \
                      'HandleCount' : [ 0x3c, ['long']], \
                      } ],
                }

            test_data = '\x01\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\\x00\x00\x00\\\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

            o = self.make_object('_HANDLE_TABLE', 0, mytype, test_data)

            self.assertEqual(o.TableCode, 1)
            self.assertEqual(o.UniqueProcessId, 0x1c)
            self.assertEqual(o.UniqueProcessId.dereference(), 0x5c)
            self.assertEqual(o.UniqueProcessId.dereference_as("unsigned int"), 0x5c)

            n = o.HandleTableList.next
            self.assertEqual(n.TableCode, 3)
            self.assertEqual(n.HandleCount, 5)

            ## Make sure next.prev == o
            self.assertEqual(n.HandleTableList.prev, o)
            self.assertEqual(n.HandleTableList.prev.TableCode, 1)
            
    suite = unittest.makeSuite(ObjectTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
