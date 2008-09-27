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

class linstrings(forensics.commands.command):

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

        self.op.add_option('-S', '--strings', 
            help='(required) File of form <offset>:<string>',
            action='store', type='string', dest='stringfile')

    # We need to override the forensics.commands.command.help() method to
    # change the user help message.  This function returns a string that 
    # will be displayed when a user lists available plugins.

    def help(self):
        return  "Match physical offsets to virtual addresses (may take a while, VERY verbose)"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def execute(self):
        op = self.op
        opts = self.opts

        reverse_map = {}

        if (opts.stringfile is None) or (not os.path.isfile(opts.stringfile)) :
            op.error("String file is required")
        else:
            stringfile = opts.stringfile

        try:
            strings = open(stringfile, "r")
        except:
            op.error("Invalid or inaccessible file %s" % stringfile)

	(profile, addr_space, symtab, types) = linux_load_and_identify_image( \
            self.op, self.opts)

        theProfile = Profile(abstract_types=profile)

        task_list = process_list(addr_space,theProfile.abstract_types, symtab,theProfile)

        for task in task_list:
            process_id = task.pid
            
            mm_addr = task.m('mm').v()
            if not addr_space.is_valid_address(mm_addr):
               continue

            mm = Object('mm_struct', mm_addr, addr_space, \
                None, theProfile)

            pgd = mm.pgd.v()

            process_address_space = task_create_addr_space(addr_space, (pgd - 0xc0000000)) 
            vpage = 0
	    try:
	        while vpage < 0xC0000000:
                    physpage = process_address_space.vtop(vpage)

                    if not physpage is None:
                        if not reverse_map.has_key(physpage):
                            reverse_map[physpage] = [False]

                        if not reverse_map[physpage][0]:
                            reverse_map[physpage].append((process_id, vpage))
                    vpage += 0x1000
            except:
                continue

        for stringLine in strings:
            try:
                (offsetString, string) = stringLine.split(None,1)
            except:
                continue
            try:
                offset = int(offsetString,16)
            except:
                print "String file format invalid."
            if reverse_map.has_key(offset & 0xFFFFF000):
                self.print_string(offset, reverse_map[offset & 0xFFFFF000][1:], string)

    def print_string(self, offset, pidlist, string):
        print "%d " % (offset),

        print "[%s:%x" % (pidlist[0][0], pidlist[0][1] | (offset & 0xFFF)),
    
        for i in pidlist[1:]:
             print " %s:%x" % (i[0], (i[1] | (offset & 0xFFF))),

        print "] %s" % string,
