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
from forensics.linux.files import file_pathname
from vutils import *
from stat import S_ISSOCK,S_ISBLK,S_ISDIR,S_ISCHR,S_ISLNK,S_ISFIFO,S_ISREG

class linfiles(forensics.commands.command):

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
        return  "Print open file descriptors"

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

            print "%-4s %-10s %-10s %-10s %-4s %s"%('FD','FILE','DENTRY','INODE', 'TYPE', 'PATH')

            fds = task_fds(task,addr_space, theProfile.abstract_types, symtab, theProfile)
            if not len(fds):
                print "No open files"
                print
                continue

            for fd, filep, dentry, inode in fds:
              
	        pathname = ""
                fileinfo = Object('file', filep, addr_space, \
                    None, theProfile)

                pathname = file_pathname(fileinfo, addr_space, theProfile)

                inode = Object('inode', inode.offset, addr_space, \
		                    None, theProfile)
                type_str = self.inode_type(inode, symtab, addr_space)

                # If it is a pipe then we ignore           
                #if type_str == "PIPE":
                #    pathname = ""     
                
                print "%-4d 0x%0.8x 0x%0.8x 0x%0.8x %-4s %s"%(fd,filep,dentry.offset,inode.offset,type_str, pathname)
            print

    def inode_type(self, inode, symtab, addr_space):
         imode = inode.m('i_mode').v()

         type = "UNKN"

         if S_ISREG(imode):
             type = "REG"
         elif S_ISLNK(imode):
             type = "LNK"
         elif S_ISCHR(imode):
             type = "CHR"
         elif S_ISBLK(imode):
             type = "BLK"
         elif S_ISDIR(imode):
             type = "DIR"
         elif S_ISSOCK(imode):
             type = "SOCK"
         elif S_ISFIFO(imode):
             type = "FIFO"
             if symtab.lookup("rdwr_pipe_fops"):
                 i_fop_offset = inode.get_member_offset('i_fop')
                 if i_fop_offset > 0:
           
                     i_fop = inode.get_member('i_fop').v()

                     if i_fop == symtab.lookup("rdwr_pipe_fops"):
                         type = "PIPE"         
         return type



