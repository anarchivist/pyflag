# Volatility
# Copyright (C) 2007 Volatile Systems
#
# Original Source:
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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

import optparse

from vtypes import xpsp2types as types
from vsyms import *
from forensics.win32.tasks import find_dtb

from forensics.addrspace import *
from forensics.x86 import *


###################################
#  Helper functions
###################################
def get_standard_parser(cmdname):
    """
    Function generates a parser with common options for all tools.
    """
    op = optparse.OptionParser(usage='%s [options] (see --help)' % (cmdname))
    op.add_option('-f', '--file', help='(required) XP SP2 Image file',
                  action='store',
                  type='string', dest='filename')
    op.add_option('-b', '--base',
                  help='(optional, otherwise best guess is made) Physical offset (in hex) of directory table base',
                  action='store', type='string', dest='base')
    op.add_option('-t', '--type',
                  help='(optional, default="auto") Identify the image type (pae, nopae, auto)',
                  action='store', type='string', dest='type')    
    return op


def guess_dtb(filename, op):
    """
    Function performs a linear scan in search of a potential valid XP SP2 DTB
    """    
    try:
	flat_address_space = FileAddressSpace(filename)
    except:
        op.error("Unable to open image file %s" % (filename))

    dtb = find_dtb(flat_address_space, types)
        
    return dtb


def load_file_address_space(op, opts):
    """
    Function checks the parsed options for a valid image and returns
    the flat (physical) file address space object.
    """

    filename = None
    
    if opts.filename is None:
        op.error("Image file required")
    else:
        filename = opts.filename

    try:
	addr_space = FileAddressSpace(filename)
    except:
        op.error("Invalid image file %s" % (filename))

    return addr_space


def load_pae_address_space(filename, dtb):
    try:
        physAS = FileAddressSpace(filename)
        addr_space = IA32PagedMemoryPae(physAS, dtb)
        
	if not addr_space.is_valid_address(pae_syms.lookup('PsLoadedModuleList')):
            addr_space = None
    except:
        addr_space = None

    return addr_space


def load_nopae_address_space(filename, dtb):
    try:
        physAS = FileAddressSpace(filename)
	addr_space = IA32PagedMemory(physAS, dtb)

        if not addr_space.is_valid_address(nopae_syms.lookup('PsLoadedModuleList')):
            addr_space = None
    except:
        addr_space = None
        
    return addr_space


def load_and_identify_image(op, opts, verbose=False):
    """
    Function checks the parsed options for a valid image and DTB and returns
    (address space, symbol table, types) tuple for that image.
    """
    dtb = None
    filename = None
    addr_space = None
    symtab = None

    if opts.filename is None:
        op.error("Image file required")
    else:
        filename = opts.filename


    if not opts.base is None:
        try:
            dtb = int(opts.base, 16)
        except:
            op.error("Directory table base must be a hexidecimal number.")

    if not opts.type is None:
        if opts.type == 'nopae':
            symtab = nopae_syms
        elif opts.type == 'pae':
            symtab = pae_syms
        elif opts.type != 'auto':
            op.error("-t option must be 'pae', 'nopae', or 'auto'")            

    if dtb is None:
        dtb = guess_dtb(filename, op)

        if dtb is None and not verbose:
            op.error("Unable to locate valid DTB in image.")

    if symtab == nopae_syms:
        addr_space = load_nopae_address_space(filename, dtb)
    elif symtab == pae_syms:
        addr_space = load_pae_address_space(filename, dtb)

    else:
        addr_space = load_pae_address_space(filename, dtb)
        if not addr_space is None:
            symtab = pae_syms
            
        else:
            addr_space = load_nopae_address_space(filename, dtb)
            if not addr_space is None:
                symtab = nopae_syms

    if addr_space is None or symtab is None:
        if verbose:
            print "%25s %s" % ("Image Name:", filename)
            print "%25s %s" % ("Image Type:", "UNKNOWN")
        else:
            op.error("Unable to load image. Possible causes: invalid dtb, wrong image type, unsupported image type.")

    elif verbose:
        print "%25s %s" % ("Image Name:", filename)
        print "%25s %s" % ("Image Type:", "XP SP2")
        if symtab == pae_syms:
            print "%25s %s" % ("VM Type:", "pae")
        else:
            print "%25s %s" % ("VM Type:", "nopae")            
        print "%25s 0x%x" % ("DTB:", dtb)        

    return (addr_space, symtab, types)
            
