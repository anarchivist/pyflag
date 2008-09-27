# Volatility
# Copyright (C) 2007,2008 Volatile Systems
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

# Source code in this file was inspired by the work of Andreas Schuster 
# and ptfinder

# Source for the check_ip_checksum based on work from George V. Neville-Neil
# Copyright (c) 2005, Neville-Neil Consulting
# 
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# Neither the name of Neville-Neil Consulting nor the names of its 
# contributors may be used to endorse or promote products derived from 
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems.
"""

from forensics.object import *
from forensics.linux.tasks import task_state_string
import os
from struct import unpack
from forensics.x86 import *
from socket import ntohs, inet_ntoa
import socket
import re
from vutils import *


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
   def __init__(self, addr_space,types,fast=True,outfile=None):
       self.checks = []
       self.cnt = 0
       self.addr_space = addr_space
       self.types = types
       self.matches = []
       self.limit = 0
       self.fast = fast
       self.outfile = outfile

       if fast == True:
           try:
               self.fast_address_space = FileAddressSpace(self.addr_space.fname,fast=True)
           except:
               print "Unable to open fast address space %s"%(self.addr_space.fname)
	       return

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

def format_dot_time(time):
    ts=strftime("%H:%M:%S\\n%Y-%m-%d",
                    gmtime(time))
    return ts

# Check for characters other than printable ASCII
_unexpected_char_pat = re.compile(r"[^\040-\176]")

def check_comm(address, object):
    string = read_string(object.addr_space, object.types, \
        ['task_struct', 'comm'], address, 256)

    if (string.find('\0') == -1):
        return False
    
    (string, none) = string.split('\0', 1)
    
    if len(string) > 16:
        return False

    if len(string) == 0:
        return False

    m = _unexpected_char_pat.search(string)
    if m:
        return False

    return True

def check_pid(address, object):

    pid =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'pid'], address)
   
    if pid < 0:
        return False

    return True

def check_state(address, object):

    state =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'state'], address)

    if address == 0x660bc0:
        print "STATE %d"%state

    if state == 0:
        return True

    return False


def check_kernel_pointers(address, object):

    kernel = 0xC0000000;

    thread_info =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'thread_info'], address)

    if thread_info < kernel:
        return False
 
    parent =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'parent'], address)

    if parent < kernel:
        return False

    group_leader =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'group_leader'], address)

    if group_leader < kernel:
        return False

    group_info =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'group_info'], address)

    if group_info < kernel:
        return False

    user =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'user'], address)

    if user < kernel:
        return False

    signal =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'signal'], address)
    if signal < kernel:
        return False    

    sighand =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'sighand'], address)
    if sighand < kernel:
        return False
    
    cpuset =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'cpuset'], address)
    if cpuset < kernel:
        return False

    delays =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'delays'], address)
    if delays < kernel:
        return False

    return True

def check_sleep_type(address, object):

    (offset, current_type) = get_obj_offset(object.types,['task_struct', 'sleep_type'])
    sleep_type = object.addr_space.read_long(address+offset)
    if sleep_type == 0 or sleep_type == 1 or sleep_type == 2 or sleep_type == 3:
        return True

    return False

def task_dump(address, cnt, object):

   task_pid =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'pid'], address)
   task_uid =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'uid'], address)
   task_state =  read_obj(object.addr_space, object.types,
                   ['task_struct', 'state'], address)
   ts_string = task_state_string(task_state)
   
   comm = read_null_string(object.addr_space, object.types,\
                ['task_struct', 'comm'], address)

   defaults = {0:-1,1:-1,2:-1,3:"UN",4:"UNKNOWN"}

   PrintWithDefaults("%-5d %-5d 0x%0.8x %-3s %s", \
                                                   (task_pid,
                                                   task_uid,
                                                   address,
                                                   ts_string,
                                                   comm),defaults)


def task_scan(addr_space, types, filename, beg, end, slow):
    
    task_object = ScanObject(addr_space,types,fast=False)
    task_object.add_check(check_sleep_type)
    task_object.add_check(check_kernel_pointers)
    task_object.add_check(check_pid)
    task_object.add_check(check_comm)
    task_object.set_dump(task_dump)
    task_object.set_limit(4)

    object_header = \
        "%-5s %-5s %-10s %-3s %s"%("PID","UID","TASK","ST","COMM")

    task_object.set_header(object_header)

    end = end - obj_size(types,'task_struct')
    task_scan = Scan(addr_space,beg,end,False)
    task_scan.add_object(task_object)

    print object_header
    task_scan.scan()
  
def check_ip_checksum(address, object):
    """Check the IP checksum
       Based on code by George V. Neville-Neil
    """

    #find the bytes in the header
    #for now assume no options since we use that as a constraint
    IP_Header = object.addr_space.read(address,20)
        
    total = 0
    bytes = IP_Header
    if len(bytes) % 2 == 1:
        bytes += "\0"
    for i in range(len(bytes)/2):
        total += (struct.unpack("!H", bytes[2*i:2*i+2])[0])
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16

    if total == 65535: 
        return True
    return False


def pkt_dump(address, cnt, object):
   src = object.addr_space.read(address+12, 4)
   dst = object.addr_space.read(address+16, 4)
   (src, ) = struct.unpack('=I', src)
   (dst, ) = struct.unpack('=I', dst)
   src = socket.inet_ntoa(struct.pack("I", src))
   dst = socket.inet_ntoa(struct.pack("I", dst))

   string = object.addr_space.read(address+9, 1)
   (byte, ) =  struct.unpack('c', string)
   if byte =="\x06":
       proto = "TCP"
   elif byte == "\x11":
       proto = "UDP"
   else:
       proto ="UNK"

   source_port = object.addr_space.read(address+20, 2)
   (src_pt, ) = struct.unpack('=H', source_port)
   sport = ntohs(src_pt) 

   destination_port = object.addr_space.read(address+22, 2)    
   (dst_pt, ) = struct.unpack('=H', destination_port)
   dport = ntohs(dst_pt) 

   source = "%s:%d"%(src,sport)
   destination = "%s:%d"%(dst,dport)
   print "0x%0.8x %-25s %-25s %-4s"%(address,source,destination,proto)

def check_IPv4(address, object):
    string = object.addr_space.read(address, 1)
    (byte, ) =  struct.unpack('c', string)
    if byte =="\x45":
        return True
    return False

def check_Proto(address, object):
    string = object.addr_space.read(address+9, 1)
    (byte, ) =  struct.unpack('c', string)
    if byte =="\x06" or byte == "\x11":
        return True
    return False

def pkt_scan(addr_space, types, filename, beg, end, slow):
    
    pkt_object = ScanObject(addr_space,types,fast=False)
    pkt_object.add_check(check_IPv4)
    pkt_object.add_check(check_Proto)
    pkt_object.add_check(check_ip_checksum) 
    pkt_object.set_dump(pkt_dump)
    pkt_object.set_limit(3)

    object_header = "%-10s %-25s %-25s %-4s"%("ADDRESS","SOURCE","DESTINATION","PROTO")

    pkt_object.set_header(object_header)

    end = end - 24
    pkt_scan = Scan(addr_space,beg,end,False)
    pkt_scan.add_object(pkt_object)

    print object_header
    pkt_scan.scan()

def pcap_dump(address, cnt, object):

    ofilename = object.outfile
    try:
        ohandle=open(ofilename,'awb')
    except IOError:
        print "Error opening file [%s]"% (ofilename)
        return   

    total_length = object.addr_space.read(address+2, 2)
    (total_length, ) = struct.unpack('=H', total_length)

    # Include the Ethernet Hdr
    total_length += 14

    record_header = "\x00\x00\x00\x00\x00\x00\x00\x00"
    record_header+= struct.pack('L', total_length) + struct.pack('L', total_length)
    ohandle.write("%s"%record_header) 
 
    data = object.addr_space.read(address-14,total_length)
   
    ohandle.write("%s"%data) 
    ohandle.close()   


def pktdmp_scan(addr_space, types, filename, beg, end, slow, ofilename):
    
    pkt_object = ScanObject(addr_space,types,fast=False,outfile=ofilename)
    pkt_object.add_check(check_IPv4)
    pkt_object.add_check(check_Proto)
    pkt_object.add_check(check_ip_checksum) 
    pkt_object.set_dump(pcap_dump)
    pkt_object.set_limit(3)

    end = end - 24
    pkt_scan = Scan(addr_space,beg,end,False)
    pkt_scan.add_object(pkt_object)

    try:
        ohandle=open(ofilename,'wb')
    except IOError:
        print "Error opening file [%s]"% (ofilename)
        return
    
    # Write header to file
    header = "\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    header+= "\xFF\xFF\x00\x00\x01\x00\x00\x00"

    ohandle.write("%s"%header)
    
    ohandle.close()

    pkt_scan.scan()