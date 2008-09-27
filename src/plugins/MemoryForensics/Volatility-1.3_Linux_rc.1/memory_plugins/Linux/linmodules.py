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
from vutils import *

class linmodules(forensics.commands.command):

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
        return  "Print loaded kernel modules"

    # Finally we override the forensics.commands.command.execute() method
    # which provides the plugins core functionality. Command line options
    # are accessed as attributes of self.opts. For example, the options 
    # provided by the standard parse would would provide the following
    # attributes: self.opts.filename, self.opts.base, self.opts.type.

    def execute(self):

	(profile, addr_space, symtab, types) = linux_load_and_identify_image( \
            self.op, self.opts)

        theProfile = Profile(abstract_types=profile)

        modules_vaddr = symtab.lookup("modules")
        if modules_vaddr == None:
            return []

        module_head = Object('list_head', modules_vaddr, addr_space, \
                        None, theProfile)

        modlist = []
        list_do_pointer(module_head, ['module'], ['list', 'next'], modlist.append, theProfile)

        print "%-10s %-10s %s"%('MODULE','SIZE','NAME')

        for module in modlist:

            name = read_null_string(addr_space, theProfile.abstract_types,\
                ['module', 'name'], module.offset)

            print "0x%0.8x 0x%0.8x %s"%(module.offset,module.core_size,name)
            



        
        




