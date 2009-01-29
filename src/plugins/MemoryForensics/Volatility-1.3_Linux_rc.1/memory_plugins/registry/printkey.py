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

from forensics.win32.datetime import windows_to_unix_time
from forensics.win32.hive2 import HiveAddressSpace
from forensics.win32.rawreg import get_root, open_key, subkeys, values, value_data
from forensics.object2 import *
from vutils import *

from time import ctime

def vol(k):
    return bool(k.offset & 0x80000000)

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

class printkey(forensics.commands.command):

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
        self.op.add_option('-o', '--hive-offset', help='Hive offset (virtual)',
            action='store', type='int', dest='hive')

    def help(self):
        return  "Print a registry key, and its subkeys and values"
    
    def execute(self):
	(addr_space, symtab, types) = load_and_identify_image(self.op,
            self.opts)

        profile = Profile()
        if not self.opts.hive:
            op.error("No hive offset provided!")
        
        if len(self.args) == 1 and '\\' in self.args[0]:
            self.args = self.args[0].split('\\')
        
        hive = HiveAddressSpace(addr_space, profile, self.opts.hive)
        root = get_root(hive, profile)
        if not root:
            print "Unable to find root key. Is the hive offset correct?"
            return
        
        key = open_key(root, self.args)
        print "Key name:", key.Name,
        print "(Volatile)" if vol(key) else "(Stable)"
        print "Last updated: %s" % key.LastWriteTime
        print
        print "Subkeys:"
        for s in subkeys(key):
            print "  ", s.Name, "(Volatile)" if vol(s) else "(Stable)"
        print
        print "Values:"
        for v in values(key):
            tp,dat = value_data(v)
            if tp == 'REG_BINARY': dat = "\n" + hd(dat, length=16)
            print "%-9s %-10s : %s %s" % (tp, v.Name, dat, "(Volatile)" if vol(v) else "(Stable)")
