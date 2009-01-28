# Volatility
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

from forensics.object2 import *
import forensics.win32.meta_info as meta_info
from forensics.win32.scan2 import scan_addr_space
from forensics.win32.hive2 import PoolScanHiveFast2
from forensics.win32.hive2 import hive_fname
from forensics.win32.regtypes import regtypes
from vutils import *
from struct import unpack

class hivescan(forensics.commands.command):
    # Declare meta information associated with this plugin
    
    meta_info = forensics.commands.command.meta_info 
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def help(self):
        return  "Scan for _CMHIVE objects (registry hives)"
    
    def execute(self):
        # In general it's not recommended to update the global types on the fly,
        # but I'm special and I know what I'm doing ;)
        types.update(regtypes)

        op = self.op
        opts = self.opts

        if (opts.filename is None) or (not os.path.isfile(opts.filename)):
            op.error("File is required")
        else:
            filename = opts.filename

        try:
            flat_address_space = FileAddressSpace(filename,fast=True)
        except:
            op.error("Unable to open image file %s" % (filename))

        meta_info.set_datatypes(types)

        # Determine the applicable address space (ie hiber, crash)
        search_address_space = find_addr_space(flat_address_space, types)

        # Find a dtb value
        if opts.base is None:
            sysdtb = get_dtb(search_address_space, types)
        else:
            try:
                sysdtb = int(opts.base, 16)
            except:
                op.error("Directory table base must be a hexidecimal number.")
        meta_info.set_dtb(sysdtb)

        # Set the kernel address space
        kaddr_space = load_pae_address_space(filename, sysdtb)
        if kaddr_space is None:
             kaddr_space = load_nopae_address_space(filename, sysdtb)
        meta_info.set_kas(kaddr_space)

        print "%-15s %-15s" % ("Offset", "(hex)")
        scanners = [PoolScanHiveFast2(search_address_space)]
        objs = scan_addr_space(search_address_space, scanners)
