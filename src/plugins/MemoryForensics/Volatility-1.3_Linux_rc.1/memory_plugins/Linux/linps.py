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

PAGESIZE = 0x1000

class linps(forensics.commands.command):

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
        return  "Print Linux process state information"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def execute(self):

	(profile, addr_space, symtab, types) = linux_load_and_identify_image( \
            self.op, self.opts)

        theProfile = Profile(abstract_types=profile)

        task_start_vaddr = symtab.lookup('init_tasks')

        print "    PID   PPID    UID CPU    TASK    ST     VSZ    RSS COMM"

        task_list = process_list(addr_space,theProfile.abstract_types, symtab,theProfile)

        for task in task_list:
            comm = read_null_string(addr_space, theProfile.abstract_types,\
                ['task_struct', 'comm'], task.offset)

            parent = task.m('parent').v()
            parent_pid = task_to_pid(task_list,parent)
            
            processor = task_cpu(task.thread_info.cpu)

            task_state = task_state_string(task.state)        

            rss = task_rss(task)

            if rss:
                rss = (rss * PAGESIZE)/1024

            total_vm = task_total_vm(task)

            if total_vm:
                total_vm = (total_vm * PAGESIZE)/1024 

            defaults = {0:-1,1:-1,2:-1,3:"-",4:-1,5:"UN",6:-1,7:-1,8:"UNKNOWN"}

            PrintWithDefaults("  %5ld  %5ld  %5ld  %2s  %x %3s %7ld %6ld %s", \
                                                   (task.pid,
                                                   parent_pid,
						   task.uid,
                                                   processor,
                                                   task.offset,
                                                   task_state,
                                                   total_vm,
                                                   rss,
                                                   comm),defaults)
