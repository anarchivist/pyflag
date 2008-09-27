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

class linmemdmp(forensics.commands.command):

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

        self.op.add_option('-o', '--offset',
            help='task_struct offset (in hex)',
            action='store', type='string', dest='offset')

        self.op.add_option('-P', '--pid',
            help='Dump the address space for this Pid',
            action='store', type='int', dest='pid')


    # We need to override the forensics.commands.command.help() method to
    # change the user help message.  This function returns a string that 
    # will be displayed when a user lists available plugins.

    def help(self):
        return  "Dump the addressable memory of a task"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def execute(self):

        op = self.op
        opts = self.opts

        if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
            op.error("File is required")
        else:
            filename = opts.filename 

	(profile, addr_space, symtab, types) = linux_load_and_identify_image( \
            self.op, self.opts)

        theProfile = Profile(abstract_types=profile)

        if not opts.offset is None:
 
            try:
                offset = int(opts.offset, 16)
            except:
                op.error("task_struct offset must be a hexidecimal number.")
 
            try:
                flat_address_space = FileAddressSpace(filename)
            except:
                op.error("Unable to open image file %s" %(filename))


            task = Object('task_struct', offset, flat_address_space, \
                None, theProfile)

            print task

            mm_addr = task.m('mm').v()

            ofilename = opts.offset + ".dmp"

        else:
            if opts.pid == None:
                op.error("Please specify pid or offset: linmemdmp -p <PID> -o <offset>")
    
            task_list = process_list(addr_space,theProfile.abstract_types, symtab,theProfile)
            task = pid_to_task(task_list, opts.pid)

            if len(task) == 0:
                print "Error process [%d] not found"%self.opts.pid
	        return

            if len(task) > 1:
                print "Multiple processes [%d] found. Please specify offset."%self.opts.pid 
                return

            task = task[0]

            mm_addr = task.m('mm').v()

            ofilename = str(opts.pid) + ".dmp"

        if not addr_space.is_valid_address(mm_addr):
            print "Unable to rebuild address space [0x%x]"% (mm_addr)
	    return

        mm = Object('mm_struct', mm_addr, addr_space, \
                None, theProfile)

        pgd = mm.pgd.v()

        process_address_space = task_create_addr_space(addr_space, (pgd - 0xc0000000))
        entries = process_address_space.get_available_pages()

        # Check to make sure file can open
	try:
            ohandle=open(ofilename,'wb')
        except IOError:
	    print "Error opening file [%s]"% (ofilename)
	    return

        for entry in entries:
            data = process_address_space.read(entry[0],entry[1])
            ohandle.write("%s"%data)

        ohandle.close()
