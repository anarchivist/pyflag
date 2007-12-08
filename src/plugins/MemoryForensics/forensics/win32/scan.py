# Volatility
# Copyright (C) 2007 Volatile Systems.
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

# Source code in this file was inspired by the work of Andreas Schuster and ptfinder

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems.
"""

from forensics.object import *
from forensics.win32.datetime import *
import os
from struct import unpack
from forensics.win32.info import *
from forensics.win32.tasks import *
from forensics.win32.network import *

class Scan:
   def __init__(self,addr_space,beg,end,collect=False):
      self.beg = beg
      self.end = end
      self.addr_space = addr_space
      self.scanobjects = []
      self.collect = collect

   def add_object(self,scanobject):
      self.scanobjects.append(scanobject) 

   def scan(self):
       offset = self.beg
       while offset <= self.end:
          for object in self.scanobjects:
             object.check_addr(offset)
	     if object.cnt >= object.limit:
                if self.collect == False:
                    object.matches.append(offset)
                    cnt = len(object.matches)
                    object.dump(offset,cnt,object)
		elif self.collect == True:
                    object.matches.append(offset)
          offset+=8

class ScanObject:
   def __init__(self, addr_space,types,fast=True):
       self.checks = []
       self.cnt = 0
       self.addr_space = addr_space
       self.types = types
       self.matches = []
       self.limit = 0
       self.fast = fast

       if fast == True:
           try:
               self.fast_address_space = FileAddressSpace(self.addr_space.fname,fast=True)
           except:
               op.error("Unable to open fast address space %s" % (self.addr_space.fname))

   def set_limit(self, limit):
       self.limit = limit

   def get_matches(self):
       return self.matches

   def add_check(self,func):
       self.checks.append(func)

   def check_addr(self,address):
       self.cnt = 0
       for func in self.checks:
           val = func(address,self)
           if self.fast ==0:
               if val == True:
                   self.cnt = self.cnt+1
           else:
               if val == False:
                   break
               else:
                   self.cnt = self.cnt+1
	          
   def set_dump(self,func):
       self.dump=func

   def set_header(self,header):
       self.hdr=header

   def set_fast_beg(self,offset):
       self.fast_address_space.fast_fhandle.seek(offset)


def format_time(time):
    ts=strftime("%a %b %d %H:%M:%S %Y",
                    gmtime(time))
    return ts

def check_dispatch_header(address,object):

    if object.fast == True:
        data = object.addr_space.fread(8)
        (type,size) = unpack('HH',data[:4])
	if(size == 0x1b and type == 0x03):
            return True
        return False
    else:
        Type =  read_obj(object.addr_space, object.types, ['_EPROCESS', 'Pcb', 'Header','Type'], address)

        Size =  read_obj(object.addr_space, object.types, ['_EPROCESS', 'Pcb', 'Header','Size'], address)

        if Type == None or Size == None:
           return False 

        if(Size == 0x1b and Type == 0x03):
           return True
        return False

def check_dtb(address, object):
    DirectoryTableBase = process_dtb(object.addr_space, object.types, address)
    if DirectoryTableBase == 0:
       return False
    return True

def check_dtb_aligned(address, object):
    # on pae systems this will not be page aligned
    DirectoryTableBase = process_dtb(object.addr_space, object.types, address)
    if (DirectoryTableBase % 0x1000 != 0):
       return False
    return True

def check_thread_list(address, object):
    kernel = 0x80000000;

    thread_list_head_flink =  read_obj(object.addr_space, object.types,
                   ['_EPROCESS', 'ThreadListHead', 'Flink'], address)

    if thread_list_head_flink < kernel:
        return False
 
    thread_list_head_blink =  read_obj(object.addr_space, object.types,
                   ['_EPROCESS', 'ThreadListHead', 'Blink'], address)

    if thread_list_head_blink < kernel:
        return False
    
    return True

def check_synchronization(address, object):

    Type =  read_obj(object.addr_space, object.types, ['_EPROCESS', 'WorkingSetLock','Event', 'Header','Type'], address)

    Size =  read_obj(object.addr_space, object.types, ['_EPROCESS', 'WorkingSetLock','Event','Header','Size'], address)

    if Type == None or Size == None:
        return False
    
    if(Size != 0x4 and Type != 0x1):
        return False

    Type =  read_obj(object.addr_space, object.types, ['_EPROCESS', 'AddressCreationLock','Event', 'Header','Type'], address)

    Size =  read_obj(object.addr_space, object.types, ['_EPROCESS', 'AddressCreationLock','Event','Header','Size'], address)

    if Type == None or Size == None:
        return False

    if(Size != 0x04 and Type != 0x01):
        return False

    return True

def eprocess_dump(address, cnt, object):
   UniqueProcessId = process_pid(object.addr_space, object.types, address)
   ImageFileName = process_imagename(object.addr_space, object.types, address)
   DirectoryTableBase = process_dtb(object.addr_space, object.types, address)
   CreateTime = process_create_time(object.addr_space, object.types, address)
   ExitTime = process_exit_time(object.addr_space, object.types, address)

   if CreateTime == 0:
      CreateTime = ""
   else:
      CreateTime = format_time(CreateTime)

   if ExitTime == 0:
      ExitTime = ""
   else:
      ExitTime = format_time(ExitTime)


   print "%4d %6d %24s %24s 0x%0.8x 0x%0.8x %-16s"%(cnt,UniqueProcessId,CreateTime,ExitTime,address,DirectoryTableBase,ImageFileName)

def ps_scan(addr_space, types, filename, beg, end, slow):
    
    if slow == False:
        eprocess_object = ScanObject(addr_space,types)
        eprocess_object.set_fast_beg(beg)
    else:
        eprocess_object = ScanObject(addr_space,types,fast=False)

    eprocess_object.add_check(check_dispatch_header)
    eprocess_object.add_check(check_dtb)
    eprocess_object.add_check(check_thread_list)
    eprocess_object.add_check(check_synchronization)
    eprocess_object.set_dump(eprocess_dump)
    eprocess_object.set_limit(4)


    object_header = \
    "No.  PID    Time created             Time exited              Offset     PDB        Remarks\n"+ \
    "---- ------ ------------------------ ------------------------ ---------- ---------- ----------------\n";

    eprocess_object.set_header(object_header)

    end = end - obj_size(types,'_EPROCESS')
    process_scan = Scan(addr_space,beg,end,False)
    process_scan.add_object(eprocess_object)

    print object_header
    process_scan.scan()
  

def check_thread_thread_process(address,object):

    kernel = 0x8000000
    UniqueProcess =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Cid', 'UniqueProcess'], address)
   
    ThreadsProcess = read_obj(object.addr_space, object.types,
                    ['_ETHREAD', 'ThreadsProcess'], address)

    if UniqueProcess != 0 and ThreadsProcess < kernel:
        return False
    
    return True


def check_thread_start_address(address, object):
    UniqueProcess =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Cid', 'UniqueProcess'], address)
    StartAddress = read_obj(object.addr_space, object.types,
                    ['_ETHREAD', 'StartAddress'], address)

    if StartAddress == 0 and UniqueProcess != 0:
        return False

    return True


def check_thread_dispatch_header(address,object):

    if object.fast == True:
        data = object.addr_space.fread(8)
        (type,size) = unpack('HH',data[:4])
        if(size == 0x70 and type == 0x06):
            return True
        return False
    else:

        Type =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Tcb', 'Header','Type'], address)

        Size =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Tcb', 'Header','Size'], address)

        if Type == None or Size == None:
           return False 
        if(Size == 0x70 and Type == 0x06):
           return True
        return False

def check_thread_notification_timer(address, object):

    Type =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Tcb', 'Timer','Header','Type'], address)

    Size =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Tcb', 'Timer','Header','Size'], address)

    if Type == None or Size == None:
        return False

    if(Size != 0xa and Type != 0x8):
        return False

    return True


def check_thread_semaphores(address, object):

    UniqueProcess =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Cid', 'UniqueProcess'], address)

    Type =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Tcb', 'SuspendSemaphore','Header','Type'], address)

    Size =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Tcb', 'SuspendSemaphore','Header','Size'], address)

    if Type == None or Size == None:
        return False

    if(Size != 0x5 and Type != 0x5):
        return False

    Type =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'LpcReplySemaphore','Header','Type'], address)

    Size =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'LpcReplySemaphore','Header','Size'], address)

    if Type == None or Size == None:
        return False

    if((Size != 0x5 and Type != 0x5) and UniqueProcess != 0):
        return False
   
    return True


def ethread_dump(address, cnt, object):
    UniqueProcess =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Cid', 'UniqueProcess'], address)
    UniqueThread =  read_obj(object.addr_space, object.types, ['_ETHREAD', 'Cid', 'UniqueThread'], address)


    print "%4d %6d %6d 0x%0.8x"%(cnt,UniqueProcess,UniqueThread,address)


def thrd_scan(addr_space, types, filename,beg,end,slow):

    if slow == False:
        ethread_object = ScanObject(addr_space,types)
        ethread_object.set_fast_beg(beg)
    else:
        ethread_object = ScanObject(addr_space,types,fast=False)

    ethread_object.add_check(check_thread_dispatch_header)
    ethread_object.add_check(check_thread_thread_process)
    ethread_object.add_check(check_thread_start_address)
    ethread_object.add_check(check_thread_notification_timer)
    ethread_object.add_check(check_thread_semaphores)
    ethread_object.set_dump(ethread_dump)
    ethread_object.set_limit(5)

    object_header = \
    "No.  PID    TID    Offset    \n"+ \
    "---- ------ ------ ----------\n";

    end = end - obj_size(types,'_ETHREAD')
    thread_scan = Scan(addr_space,beg,end,False)
    thread_scan.add_object(ethread_object)
    print object_header
    thread_scan.scan()


def check_socket_poolindex(address,object):

    pool_header_addr = address

    pool_hdr_val     = read_obj(object.addr_space, object.types,
                        ['_POOL_HEADER', 'Ulong1'], pool_header_addr)

    PoolIndex = (pool_hdr_val) & 0xFFFF
    PoolIndex = (PoolIndex & 0xFE00) >> 9 

    if PoolIndex == 0:
        return True

    return False


def check_socket_pooltype(address,object):

    pool_header_addr = address

    pool_hdr_val = read_obj(object.addr_space, object.types,
                        ['_POOL_HEADER', 'Ulong1'], pool_header_addr)

    PoolType = (pool_hdr_val >> 16) & 0xFFFF
    PoolType = (PoolType & 0xFE00) >> 9 
  

    if ((PoolType == 0) or ((PoolType % 2) == 1)):
       return True

    return False


def check_socket_blocksize(address,object):

    pool_header_addr = address

    pool_hdr_val     = read_obj(object.addr_space, object.types,
                        ['_POOL_HEADER', 'Ulong1'], pool_header_addr)
    BlockSize = (pool_hdr_val >> 16) & 0x1FF

    pool_size = BlockSize * 0x8
  
    if pool_size == 0x170:
       return True

    return False

def check_socket_create_time(address, object):

    address = address + obj_size(object.types,'_POOL_HEADER')

    time = socket_create_time(object.addr_space, object.types, address)
    if time > 0:
       return True
    return False

def check_socket_pooltag(address,object):

    if object.fast == True:
        data = object.addr_space.fread(8)
        (PoolTag, ) = unpack('L',data[4:8])

	if(PoolTag == 0x41504354):
            return True
        return False

    else:
    
        pool_tag_addr = address

        PoolTag = read_obj(object.addr_space, object.types,
                        ['_POOL_HEADER', 'PoolTag'], pool_tag_addr)

        if PoolTag == None:
            return False

        if PoolTag == 0x41504354:
            print "Match 0x%x"%address
            return True

        return False

def socket_dump(address, cnt, object):

    address = address + obj_size(object.types,'_POOL_HEADER')

    pid = socket_pid(object.addr_space, object.types, address)
    proto = socket_protocol(object.addr_space, object.types, address)
    port = socket_local_port(object.addr_space, object.types, address)
    time = socket_create_time(object.addr_space, object.types, address)
  
    try:
        print "%-6d %-6d %-6d %-26s 0x%0.8x"%(pid,port,proto,format_time(time),address)
    except:
        return

def socket_scan(addr_space, types, filename, beg, end, slow):

    if slow == False:
        socket_object = ScanObject(addr_space,types)
        socket_object.set_fast_beg(beg)
    else:
        socket_object = ScanObject(addr_space,fast=False)

    socket_object.add_check(check_socket_pooltag)
    socket_object.add_check(check_socket_blocksize)
    socket_object.add_check(check_socket_pooltype)
    socket_object.add_check(check_socket_poolindex)
    socket_object.add_check(check_socket_create_time)
    socket_object.set_dump(socket_dump)
    socket_object.set_limit(5)

    object_header = \
    "PID    Port   Proto  Create Time                Offset \n"+ \
    "------ ------ ------ -------------------------- ----------\n";

    socket_object.set_header(object_header)

    end = end - (obj_size(types,'_POOL_HEADER') + 0x170)
    socket_scan = Scan(addr_space,beg,end,False)
    socket_scan.add_object(socket_object)
    print object_header
    socket_scan.scan()


def check_connection_poolprevioussize(address,object):

    pool_header_addr = address

    pool_hdr_val     = read_obj(object.addr_space, object.types,
                        ['_POOL_HEADER', 'Ulong1'], pool_header_addr)
    PreviousSize = (pool_hdr_val) & 0x1FF 
 
    return False


def check_connection_poolindex(address,object):
   
    pool_header_addr = address

    pool_hdr_val     = read_obj(object.addr_space, object.types,
                        ['_POOL_HEADER', 'Ulong1'], pool_header_addr)

    PoolIndex = (pool_hdr_val) & 0xFFFF
    PoolIndex = (PoolIndex & 0xFE00) >> 9 


    if PoolIndex == 0:
        return True

    return False


def check_connection_pooltype(address,object):

    pool_header_addr = address

    pool_hdr_val = read_obj(object.addr_space, object.types,
                        ['_POOL_HEADER', 'Ulong1'], pool_header_addr)

    PoolType = (pool_hdr_val >> 16) & 0xFFFF
    PoolType = (PoolType & 0xFE00) >> 9 
  
    if ((PoolType == 0) or ((PoolType % 2) == 1)):
       return True

    return False


def check_connection_blocksize(address,object):

    pool_header_addr = address

    pool_hdr_val = read_obj(object.addr_space, object.types,
                        ['_POOL_HEADER', 'Ulong1'], pool_header_addr)
    BlockSize = (pool_hdr_val >> 16) & 0x1FF
    
    pool_size = BlockSize * 0x8
 
    if pool_size == 0x198:
       return True

    return False

def check_connection_pooltag(address,object):

    if object.fast == True:
        data = object.addr_space.fread(8)
        (PoolTag, ) = unpack('L',data[4:8])

	if(PoolTag == 0x54504354):
            return True
        return False

    else:
    
        pool_tag_addr = address

        PoolTag = read_obj(object.addr_space, object.types,
                        ['_POOL_HEADER', 'PoolTag'], pool_tag_addr)

        if PoolTag == None:
            return False

        if PoolTag == 0x54504354:
            return True

        return False

def connection_dump(address, cnt, object):

    address = address + obj_size(object.types,'_POOL_HEADER')

    pid     = connection_pid(object.addr_space, object.types, address)
    lport   = connection_lport(object.addr_space, object.types, address)
    laddr   = connection_laddr(object.addr_space, object.types, address)
    rport   = connection_rport(object.addr_space, object.types, address)
    raddr   = connection_raddr(object.addr_space, object.types, address)

    local = "%s:%d"%(laddr,lport)
    remote = "%s:%d"%(raddr,rport)

    print "%-25s %-25s %-6d"%(local,remote,pid)


def conn_scan(addr_space, types, filename, beg, end, slow):

    if slow == False:
        connection_object = ScanObject(addr_space,types)
        connection_object.set_fast_beg(beg)
    else:
        connection_object = ScanObject(addr_space,fast=False)

    connection_object.add_check(check_connection_pooltag)
    connection_object.add_check(check_connection_blocksize)
    connection_object.add_check(check_connection_pooltype)
    connection_object.add_check(check_socket_poolindex)

    connection_object.set_dump(connection_dump)
    connection_object.set_limit(4)


    object_header = \
    "Local Address             Remote Address            Pid   \n"+ \
    "------------------------- ------------------------- ------ \n";
 
    connection_object.set_header(object_header)

    end = end - (obj_size(types,'_POOL_HEADER') + 0x198)
    socket_scan = Scan(addr_space,beg,end,False)
    socket_scan.add_object(connection_object)
    print object_header
    socket_scan.scan()
