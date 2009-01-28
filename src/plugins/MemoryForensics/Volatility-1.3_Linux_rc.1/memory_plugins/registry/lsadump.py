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

from forensics.win32.regtypes import regtypes
from forensics.win32.rawreg import get_root, open_key, subkeys, values, value_data
from forensics.win32.lsasecrets import get_memory_secrets
from forensics.object2 import *
from vutils import *

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def hd(src, length=16):
    N=0; result=''
    while src:
        s,src = src[:length],src[length:]
        hexa = ' '.join(["%02X"%ord(x) for x in s])
        s = s.translate(FILTER)
        result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
        N+=length
    return result

class lsadump(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = forensics.commands.command.meta_info 
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def parser(self):
        forensics.commands.command.parser(self)
        self.op.add_option('-y', '--sys-offset', help='SYSTEM hive offset (virtual)',
            action='store', type='int', dest='syshive')
        self.op.add_option('-s', '--sec-offset', help='SECURITY hive offset (virtual)',
            action='store', type='int', dest='sechive')

    def help(self):
        return  "Dump (decrypted) LSA secrets from the registry"
    
    def execute(self):
	(addr_space, symtab, types) = load_and_identify_image(self.op,
            self.opts)

        # In general it's not recommended to update the global types on the fly,
        # but I'm special and I know what I'm doing ;)
        types.update(regtypes)

        if not self.opts.syshive or not self.opts.sechive:
            op.error("Both SYSTEM and SECURITY offsets must be provided")
        
        secrets = get_memory_secrets(addr_space, types, self.opts.syshive, self.opts.sechive, Profile())
        if not secrets:
            print "Error: unable to read LSA secrets from registry"
            sys.exit(1)

        for k in secrets:
            print k
            print hd(secrets[k])
