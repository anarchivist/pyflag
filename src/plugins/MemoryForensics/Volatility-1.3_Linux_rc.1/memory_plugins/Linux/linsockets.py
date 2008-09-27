# Volatility
# Copyright (C) 2008 Volatile Systems
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

from forensics.object2 import *
from forensics.object import *
from forensics.linked_list import *
from forensics.linux.tasks import *
from vutils import *
from stat import S_ISSOCK
from socket import ntohs, inet_ntoa
import socket

sockTypes = \
          {1:'SOCK_STREAM',\
           2:'SOCK_DGRAM',\
           3:'SOCK_RAW',\
           4:'SOCK_RDM',\
           5:'SOCK_SEQPACKET',\
           6:'SOCK_DCCP',\
           10:'SOCK_PACKET'}

PFAMILIES = \
          {0:'PF_UNSPEC',\
          1:'PF_LOCAL',\
          2:'PF_INET',\
          3:'PF_AX25',\
          4:'PF_IPX',\
          5:'PF_APPLETALK',\
          6:'PF_NETROM',\
          7:'PF_BRIDGE',\
          8:'PF_ATMPVC',\
          9:'PF_X25',\
          10:'PF_INET6',\
          11:'PF_ROSE',\
          12:'PF_DECnet',\
          13:'PF_NETBEUI',\
          14:'PF_SECURITY',\
          15:'PF_KEY',\
          16:'PF_NETLINK',\
          17:'PF_PACKET',\
          18:'PF_ASH',\
          19:'PF_ECONET',\
          20:'PF_ATMSVC',\
          22:'PF_SNA',\
          23:'PF_IRDA',\
          24:'PF_PPPOX',\
          25:'PF_WANPIPE',\
          31:'PF_BLUETOOTH',\
          32:'PF_MAX'}



class linsockets(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = forensics.commands.command.meta_info 
    meta_info['author'] = 'AAron Walters'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 AAron Walters'
    meta_info['contact'] = 'awalters@volatilesystems.com'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'https://www.volatilesystems.com/default/volatility'
    meta_info['os'] = 'Linux'
    meta_info['version'] = '1.0'
      
    # This module extends the standard parser. This is accomplished by 
    # overriding the forensics.commands.command.parse() method. The 
    # overriding method begins by calling the base class method directly
    # then it further populates the OptionParser instance.

    def parser(self):

        forensics.commands.command.parser(self)

        self.op.add_option('-p', '--profile',
            help='Profile for object definitions',
            action='store', type='string', dest='profile')

        self.op.add_option('-s', '--systemmap',
            help='System Map for symbols',
            action='store', type='string', dest='systemmap')

    # We need to override the forensics.commands.command.help() method to
    # change the user help message.  This function returns a string that 
    # will be displayed when a user lists available plugins.

    def help(self):
        return  "Print open sockets"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def execute(self):
        op = self.op
        opts = self.opts

	(profile, addr_space, symtab, types) = linux_load_and_identify_image( \
            self.op, self.opts)

        theProfile = Profile(abstract_types=profile)

        task_list = process_list(addr_space,theProfile.abstract_types, symtab,theProfile)

        for task in task_list:
            comm = read_null_string(addr_space, theProfile.abstract_types,\
                ['task_struct', 'comm'], task.offset)
            process_id = task.pid
            processor = task_cpu(task.thread_info.cpu)

            print "PID: %-5ld  TASK: 0x%x  CPU: %-2s  COMMAND: \"%s\""%(task.pid,task.offset,processor,comm)

            print "%-4s %-10s %-10s %-22s %-7s %-21s %-21s"%('FD','SOCKET','SOCK','FAMILY:TYPE','PROTO', 'SOURCE-PORT', 'DESTINATION-PORT')

            fds = task_fds(task,addr_space, theProfile.abstract_types, symtab, theProfile)
            num_sockets = 0
            for fd, filep, dentry, inode in fds:
               
                socketaddr = self.inode2socketaddr(inode,theProfile)
                if (not socketaddr): continue
                num_sockets += 1
                
                socket = Object('socket', socketaddr, addr_space, \
                     None, theProfile) 
                sock_addr = socket.m('sk').v()
                sock = socket.sk
                skc_prot = sock.get_deep_member(['__sk_common', 'skc_prot']).v()
                skc_family = sock.get_deep_member(['__sk_common', 'skc_family']).v()

                proto_name = ""
                proto_name = read_null_string(addr_space, theProfile.abstract_types,['proto', 'name'], skc_prot)
                sktype = sock.sk_type

                src_and_dst = ""
                src_string = ""
                dst_string =""
                if (PFAMILIES[skc_family] == "PF_INET" or PFAMILIES[skc_family] == "PF_INET6"):
                    sock = Object('inet_sock', sock_addr, addr_space, None, theProfile)
                    src_val = sock.m('rcv_saddr').v()
                    sport = ntohs(sock.m('sport').v())
                    dst_val = sock.m('daddr').v()
                    dport = ntohs(sock.m('dport').v())
                    src_string = self.formatIPv4(src_val,sport)
                    dst_string = self.formatIPv4(dst_val,dport)

                family_type = "%s:%s"%(PFAMILIES[skc_family],sockTypes[sktype])
                print "%-4d 0x%0.8x 0x%0.8x %-22s %-7s %-21s %-21s" % \
		    (fd, socketaddr, sock_addr,family_type, proto_name,\
		    src_string, dst_string)

            if not num_sockets:
                print "No open sockets"
            print

    def inode2socketaddr(self, inode, theProfile):
        imode = inode.m('i_mode').v()
        if (not S_ISSOCK(imode)):
            return None
        else:
            return inode.offset - theProfile.cstructs['socket'].size

    def formatIPv4(self, ip, port, printstar=True):
        if (printstar and port == 0):
            return ("%s:*" %(self.ntodots(ip)))
        else:
            return ("%s:%d" %(self.ntodots(ip), port))

    def ntodots(self, n, printzeroes=True):
        if (n == 0):
            if (printzeroes):
                return "0.0.0.0"
            else:
                return "*"
        return socket.inet_ntoa(struct.pack("I", n))
