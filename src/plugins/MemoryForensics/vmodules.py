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

import sys
import os


from vutils import *
from forensics.win32.datetime import *
from forensics.win32.tasks import *
from forensics.win32.network import *
from forensics.win32.handles import *
from forensics.win32.modules import *
from forensics.win32.vad import *
from forensics.win32.scan import *

class VolatoolsModule:
    def __init__(self, cmd_name, cmd_desc, cmd_execute):
        self.cmd_name = cmd_name
        self.cmd_desc = cmd_desc
        self.cmd_execute = cmd_execute


    def desc(self):
        return self.cmd_desc

    def execute(self, module, args):
        self.cmd_execute(module, args)


###################################
#  identify
###################################
def get_image_info(cmdname, argv):
    """
    Function provides as many characteristics as can be identified for given image.
    """
    op = get_standard_parser(cmdname)
    
    opts, args = op.parse_args(argv)

    if not opts.base is None:
        print "Ignoring option -b"
        opts.base = None

    if not opts.type is None:
        print "Ignoring option -t"
        opts.type = None

    (addr_space, symtab, types) = load_and_identify_image(op, opts, True)

    if not addr_space is None and not symtab is None:
        KUSER_SHARED_DATA = 0x7ffe0000        

        if not addr_space.is_valid_address(KUSER_SHARED_DATA):
            print "%25s UNAVAILABLE" % ("Datetime:")
            return
    
    
        time = windows_to_unix_time(local_time(addr_space, types, KUSER_SHARED_DATA))
        ts = format_time(time)

        print "%25s %s"% ("Datetime:", ts)

    

###################################
#  Datetime
###################################
def format_time(time):
    ts=strftime("%a %b %d %H:%M:%S %Y",
                gmtime(time))
    return ts
    
def get_datetime(cmdname, argv):
    """
    Function prints a formatted string of the image local time.
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    KUSER_SHARED_DATA = 0x7ffe0000        

    if not addr_space.is_valid_address(KUSER_SHARED_DATA):
        print "ERROR: KUSER_SHARED_DATA Invalid: Try a different Page Directory Base"
        return
 
    
    time = windows_to_unix_time(local_time(addr_space, types, KUSER_SHARED_DATA))
    ts = format_time(time)

    print "Image local date and time: %s"%ts    


###################################
#  modules list
###################################
def get_modules(cmdname, argv):
    """
    Function prints a formatted table of module information
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
    

    all_modules = modules_list(addr_space, types, symtab)

    print "%-50s %-12s"%('Name','Base')

    for module in all_modules:
        if not addr_space.is_valid_address(module):
            continue
        module_name = module_imagename(addr_space, types, module)
        if module_name is None:
            module_name = "UNKNOWN"

        module_base = module_baseaddr(addr_space, types, module)
        if module_base is None:
            module_base = "UNKNOWN"
        else:
            module_base = "0x%-10x" % module_base

        print "%-50s  %s" % (module_name, module_base)
    
###################################
#  pslist - process list
###################################
def get_pslist(cmdname, argv):
    """
    Function prints a formatted table of process information for image
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    all_tasks = process_list(addr_space, types, symtab)

    print "%-20s %-6s %-6s %-6s %-6s %-6s"%('Name','Pid','PPid','Thds','Hnds','Time')

    for task in all_tasks:
        if not addr_space.is_valid_address(task):
            continue

        image_file_name = process_imagename(addr_space, types, task)
        if image_file_name is None:
            image_file_name = "UNKNOWN"

        process_id      = process_pid(addr_space, types, task)
        if process_id is None:
            process_id = -1

        active_threads  = process_num_active_threads(addr_space, types, task)
        if active_threads is None:
            active_threads = -1

        inherited_from  = process_inherited_from(addr_space, types,task)
        if inherited_from is None:
            inherited_from = -1

        handle_count    = process_handle_count(addr_space, types, task)
        if handle_count is None:
            handle_count = -1

        create_time     = process_create_time(addr_space, types, task)
        if create_time is None:
            create_time = "UNKNOWN"
        else:
            create_time = format_time(create_time)            

        print "%-20s %-6d %-6d %-6d %-6d %-26s" % (image_file_name,
                                                   process_id,
                                                   inherited_from,
                                                   active_threads,
                                                   handle_count,
                                                   create_time)

###################################
#  dlllist - DLL list
###################################
def get_dlllist(cmdname, argv):
    """
    Function prints a list of dlls loaded in each process
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
    
    # get list of windows processes
    all_tasks = process_list(addr_space, types, symtab)        

    star_line = '*'*72
    
    for task in all_tasks:

        if not addr_space.is_valid_address(task):
            continue

        print "%s"%star_line
        
        image_file_name = process_imagename(addr_space, types, task)

        process_id = process_pid(addr_space, types, task)

        
        print "%s pid: %d"%(image_file_name, process_id)
        
        process_address_space = process_addr_space(addr_space, types, task, opts.filename)
        if process_address_space is None:
            print "Error obtaining address space for process [%d]" % (process_id)
            continue
                            

        peb = process_peb(addr_space, types, task)

        if not process_address_space.is_valid_address(peb):
            print "Unable to read PEB for task."
            continue

        command_line = process_command_line(process_address_space, types, peb)

        if command_line is None:
            command_line = "UNKNOWN"

        print "Command line : %s" % (command_line)
        
        print
        
        modules = process_ldrs(process_address_space, types, peb)

        if len(modules) > 0:
            print "%-12s %-12s %s"%('Base','Size','Path')
        
        for module in modules:
            if not process_address_space.is_valid_address(module):
	        continue
            path = module_path(process_address_space, types, module)
            if path is None:
                path = "%-10s  " % ('UNKNOWN')
                
            base = module_base(process_address_space, types, module)
            if base is None:
                base = "%-10s  " % ('UNKNOWN')
            else:
                base = "0x%-10x" % (base)
                
	    size = module_size(process_address_space, types, module)
            if size is None:
                size = "%-10s  " % ('UNKNOWN')
            else:
                size = "0x%-10x" % (size)
                
            print "%s %s %s"%(base,size,path)            
            
        print


###################################
#  connections - List open connections
###################################
def get_connections(cmdname, argv):
    """
    Function prints a list of open connections
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    star_line = '*'*72

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
    
    connections = tcb_connections(addr_space, types, symtab)

    if len(connections) > 0:
        print "%-25s %-25s %-6s"%('Local Address','Remote Address','Pid')

    for connection in connections:
        
	if not addr_space.is_valid_address(connection):
	    continue

        pid     = connection_pid(addr_space, types, connection)
        lport   = connection_lport(addr_space, types, connection)
        laddr   = connection_laddr(addr_space, types, connection)
	rport   = connection_rport(addr_space, types, connection)
	raddr   = connection_raddr(addr_space, types, connection)

        local = "%s:%d"%(laddr,lport)
	remote = "%s:%d"%(raddr,rport)

        print "%-25s %-25s %-6d"%(local,remote,pid)

###################################
#  sockets - List open sockets
###################################
def get_sockets(cmdname, argv):
    """
    Function prints a list of open sockets.
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
    
    sockets = open_sockets(addr_space, types, symtab)

    if len(sockets) > 0:
        print "%-6s %-6s %-6s %-26s"%('Pid','Port','Proto','Create Time')

    for socket in sockets:

        if not addr_space.is_valid_address(socket):
	    continue

        pid   = socket_pid(addr_space, types, socket)
        proto = socket_protocol(addr_space, types, socket)
        port  = socket_local_port(addr_space, types, socket)
        time  = socket_create_time(addr_space, types, socket)
        
        print "%-6d %-6d %-6d %-26s"%(pid,port,proto,format_time(time))


###################################
#  files - List open files
###################################
def print_entry_file(addr_space, types, entry):

    if not addr_space.is_valid_address(entry):
    	return

    obj = handle_entry_object(addr_space, types, entry)
    
    if addr_space.is_valid_address(obj):
        if is_object_file(addr_space, types, obj):
            file = object_data(addr_space, types, obj)
            fname = file_name(addr_space, types, file)
            if fname != "":
                print "%-6s %-40s"%("File",fname)

def get_open_files(cmdname, argv):
    """
    Function prints a list of open files for each process.
    """
    op = get_standard_parser(cmdname)
    opts, args = op.parse_args(argv)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
    
    htables = handle_tables(addr_space, types, symtab)

    star_line = '*'*72

    for table in htables:
        print "%s"%star_line

        process_id = handle_process_id(addr_space, types, table)
	if process_id == None:
	    continue

        print "Pid: %-6d"%(process_id)
        
        table_code = handle_table_code(addr_space, types, table)

        if table_code == 0:
	    continue


        table_levels = handle_table_levels(addr_space, types, table)

        if table_levels == 0:
            num_entries = handle_num_entries(addr_space, types, table)

	    for counter in range(0, 0x200):
                entry = handle_table_L1_entry(addr_space, types, table, counter)
		if entry != None and entry !=0:
                    print_entry_file(addr_space, types, entry)                
                        
        elif table_levels == 1:
            for i in range(0, 0x200):
                L1_entry = handle_table_L1_entry(addr_space, types, table, i)
                if not L1_entry is None:
                    L1_table = handle_entry_object(addr_space, types, L1_entry)

                    for j in range(0, 0x200):
                        L2_entry = handle_table_L2_entry(addr_space, types, table, L1_table, j)
                        if not L2_entry is None:
                            print_entry_file(addr_space, types, L2_entry)

        elif table_levels == 2:
            for i in range(0, 0x200):
                L1_entry = handle_table_L1_entry(addr_space, types, table, i)
                if not L1_entry is None:
                    L1_table = handle_entry_object(addr_space, types, L1_entry)

                    for j in range(0, 0x200):
                        L2_entry = handle_table_L2_entry(addr_space, types, table, L1_table, j)
                        if not L2_entry is None:
                            L2_table = handle_entry_object(addr_space, types, L2_entry)
                            
                            for k in range(0, 0x200):
                                L3_entry = handle_table_L3_entry(addr_space, types, table, L2_table, j)
                                if not L3_entry is None:                  
                                    print_entry_file(addr_space, types, L3_entry)                            


###################################
#  strings - identify pid(s) associated with a string
###################################
def print_string(offset, pidlist, string):
    print "%d " % (offset),

    print "[%s:%x" % (pidlist[0][0], pidlist[0][1] | (offset & 0xFFF)),
    
    for i in pidlist[1:]:
        print " %s:%x" % (i[0], (i[1] | (offset & 0xFFF))),

    print "] %s" % string,
    
def get_strings(cmdname, argv):
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--strings', help='(required) File of form <offset>:<string>',
                  action='store', type='string', dest='stringfile')
    opts, args = op.parse_args(argv)

    if opts.stringfile is None:
        op.error("String file (-s) required")

    try:
        strings = open(opts.stringfile, "r")
    except:
        op.error("Invalid or inaccessible file %s" % opts.stringfile)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    all_tasks = process_list(addr_space, types, symtab)

    # dict of form phys_page -> [isKernel, (pid1, vaddr1), (pid2, vaddr2) ...]
    # where isKernel is True or False. if isKernel is true, list is of all kernel addresses
    # ASSUMPTION: no pages mapped in kernel and userland
    reverse_map = {}


    vpage = 0
    while vpage < 0xFFFFFFFF:
        kpage = addr_space.vtop(vpage)
        if not kpage is None:
            if not reverse_map.has_key(kpage):
                reverse_map[kpage] = [True]
            reverse_map[kpage].append(('kernel', vpage))
        vpage += 0x1000

    for task in all_tasks:
        process_id = process_pid(addr_space, types, task)
        process_address_space = process_addr_space(addr_space, types, task, opts.filename)
        vpage = 0
        while vpage < 0xFFFFFFFF:
            physpage = process_address_space.vtop(vpage)
            if not physpage is None:
                if not reverse_map.has_key(physpage):
                    reverse_map[physpage] = [False]

                if not reverse_map[physpage][0]:
                    reverse_map[physpage].append((process_id, vpage))
            vpage += 0x1000


    for stringLine in strings:
        (offsetString, string) = stringLine.split(':', 1)
        try:
            offset = int(offsetString)
        except:
            op.error("String file format invalid.")
        if reverse_map.has_key(offset & 0xFFFFF000):
            print_string(offset, reverse_map[offset & 0xFFFFF000][1:], string)


###################################
#  vadinfo - Dump the VAD to file
###################################

def vadinfo(cmdname, argv):
    """
    This function dumps the vad information
    """
    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
                  help='EPROCESS Offset (in hex) in physcial address space',
                  action='store', type='string', dest='offset')

    op.add_option('-p', '--pid',
                  help='Dump the VAD of the process with this Pid',
                  action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)

    if opts.filename is None:
        op.error("vadinfo -f <filename:required>")
    else:
        filename = opts.filename    

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    if not opts.offset is None:
 
        try:
	    offset = int(opts.offset, 16)
        except:
            op.error("EPROCESS offset must be a hexidecimal number.")
        
        try:
	    flat_address_space = FileAddressSpace(filename)
        except:
            op.error("Unable to open image file %s" %(filename))

        directory_table_base = process_dtb(flat_address_space, types, offset)

        process_address_space = create_addr_space(addr_space,types, \
                            directory_table_base, filename)

        image_file_name = process_imagename(flat_address_space, types, offset)
        process_id = process_pid(flat_address_space, types, offset)

        if process_address_space is None:
            print "Error obtaining address space for process [%d]" % (process_id)
	    return

        VadRoot = process_vadroot(flat_address_space, types, offset)

        if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
            print "VadRoot is not valid"
	    return

        vad_info(process_address_space, types, VadRoot)

    else:

        all_tasks = process_list(addr_space, types, symtab)

        if not opts.pid == None:
            all_tasks = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
            if len(all_tasks) == 0:
                print "Error process [%d] not found"%opts.pid

        star_line = '*'*72

        for task in all_tasks:

            print "%s"%star_line        

            directory_table_base = process_dtb(addr_space, types, task)
   
            process_id = process_pid(addr_space, types, task)

            process_address_space = create_addr_space(addr_space,types, \
                            directory_table_base, filename)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
	        continue

            image_file_name = process_imagename(process_address_space, types, task)
    

            print "Pid: %-6d"%(process_id)

            VadRoot = process_vadroot(process_address_space, types, task)

            if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
                print "VadRoot is not valid"
	        continue

            vad_info(process_address_space, types, VadRoot)


def vaddump(cmdname, argv):
    """
    This function dumps the vad information
    """
    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
                 help='EPROCESS Offset (in hex)',
                  action='store', type='string', dest='offset')
    op.add_option('-d', '--directory',
                  help='Output directory',
                  action='store', type='string', dest='dir')
    op.add_option('-p', '--pid',
                  help='Dump the VAD of the process with this Pid',
                  action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)

    if opts.filename is None:
        op.error("vaddump -f <filename:required>")
    else:
        filename = opts.filename    

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
    
    if not opts.offset is None:
 
        try:
	    offset = int(opts.offset, 16)
        except:
            op.error("EPROCESS offset must be a hexidecimal number.")

        try:
            flat_address_space = FileAddressSpace(filename)
        except:
            op.error("Unable to open image file %s" %(filename))

        directory_table_base = process_dtb(flat_address_space, types, offset)

        process_address_space = create_addr_space(addr_space,types, \
                            directory_table_base, filename)

        image_file_name = process_imagename(flat_address_space, types, offset)
        process_id = process_pid(flat_address_space, types, offset)

        if process_address_space is None:
            print "Error obtaining address space for process [%d]" % (process_id)
	    return

        VadRoot = process_vadroot(flat_address_space, types, offset)

        if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
            print "VadRoot is not valid"
	    return

        vad_dump(process_address_space, types, VadRoot, image_file_name, offset, opts.dir)

    else:
        all_tasks = process_list(addr_space, types, symtab)

        if not opts.pid == None:
            all_tasks = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
            if len(all_tasks) == 0:
                print "Error process [%d] not found"%opts.pid
            
        star_line = '*'*72

        for task in all_tasks:

            print "%s"%star_line        

            directory_table_base = process_dtb(addr_space, types, task)
    
            process_address_space = create_addr_space(addr_space,types, \
                            directory_table_base, filename)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
	        continue

            image_file_name = process_imagename(process_address_space, types, task)
    
            process_id = process_pid(process_address_space, types, task)

            print "Pid: %-6d"%(process_id)

            VadRoot = process_vadroot(process_address_space, types, task)

            if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
                print "VadRoot is not valid"
	        continue

            offset = process_address_space.vtop(task)

            vad_dump(process_address_space, types, VadRoot, image_file_name, offset, opts.dir)
      

###################################
#  vadwalk - Print the VadTree
###################################

def vadwalk(cmdname, argv):
    """
    This function dumps the vad information
    """
    op = get_standard_parser(cmdname)

    op.add_option('-o', '--offset',
                  help='EPROCESS Offset (in hex)',
                  action='store', type='string', dest='offset')

    op.add_option('-e', '--tree',
                  help='print VAD tree in tree format',
	          action='store_true',dest='tree', default=False)

    op.add_option('-l', '--table',
                  help='print VAD tree in table format',
                  action='store_true',dest='table', default=False)

    op.add_option('-d', '--dot',
                  help='print VAD tree in Dotfile format',
		  action='store_true',dest='dot', default=False)

    op.add_option('-p', '--pid',
                  help='Dump the VAD of the process with this Pid',
                  action='store', type='int', dest='pid')

    opts, args = op.parse_args(argv)  


    if opts.filename is None:
        op.error("vadwalk -f <filename:required> [options]")
    else:
        filename = opts.filename    

    tree = opts.tree
    table = opts.table
    dot = opts.dot

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    if opts.tree == False and opts.dot == False:
        opts.table = True

    if not opts.offset is None:
 
        try:
            offset = int(opts.offset, 16)
        except:
            op.error("EPROCESS offset must be a hexidecimal number.")
 
        try:
            flat_address_space = FileAddressSpace(filename)
        except:
            op.error("Unable to open image file %s" %(filename))


        directory_table_base = process_dtb(flat_address_space, types, offset)

        process_address_space = create_addr_space(addr_space,types, \
                            directory_table_base, filename)

        image_file_name = process_imagename(flat_address_space, types, offset)
        process_id = process_pid(flat_address_space, types, offset)

        if process_address_space is None:
            print "Error obtaining address space for process [%d]" % (process_id)
	    return

        VadRoot = process_vadroot(flat_address_space, types, offset)

        if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
            print "VadRoot is not valid"
	    return

        if(opts.table == True):
        
            print "Address  Parent   Left     Right    Start    End      Tag  Flags"
            traverse_vad(None, addr_space, types, VadRoot, print_vad_table, None, None, 0, None)

        elif (opts.tree == True):

            traverse_vad(None, addr_space, types, VadRoot, print_vad_tree, None, None, 0, None)

        elif (opts.dot == True):
            print "digraph processtree {"
	    print "graph [rankdir = \"TB\"];"
            traverse_vad(None, addr_space, types, VadRoot, print_vad_dot_prefix, print_vad_dot_infix, None, 0, None) 
            print "}"

        else:
            op.error("Output type required!")

    else:
        all_tasks = process_list(addr_space, types, symtab)

        if not opts.pid == None:
            all_tasks = process_find_pid(addr_space,types, symtab, all_tasks, opts.pid)
            if len(all_tasks) == 0:
                print "Error process [%d] not found"%opts.pid

        star_line = '*'*72

        for task in all_tasks:

            print "%s"%star_line        

            directory_table_base = process_dtb(addr_space, types, task)
   
            process_id = process_pid(addr_space, types, task)

            process_address_space = create_addr_space(addr_space,types, \
                            directory_table_base, filename)

            if process_address_space is None:
                print "Error obtaining address space for process [%d]" % (process_id)
	        continue

            image_file_name = process_imagename(process_address_space, types, task)

            print "Pid: %-6d"%(process_id)

            VadRoot = process_vadroot(process_address_space, types, task)

            if VadRoot == None or not process_address_space.is_valid_address(VadRoot):
                print "VadRoot is not valid"
	        continue

            offset = process_address_space.vtop(task)

            if(opts.table == True):
        
                print "Address  Parent   Left     Right    Start    End      Tag  Flags"
                traverse_vad(None, addr_space, types, VadRoot, print_vad_table, None, None, 0, None)

            elif (opts.tree == True):

                traverse_vad(None, addr_space, types, VadRoot, print_vad_tree, None, None, 0, None)

            elif (opts.dot == True):
                print "digraph processtree {"
	        print "graph [rankdir = \"TB\"];"
                traverse_vad(None, addr_space, types, VadRoot, print_vad_dot_prefix, print_vad_dot_infix, None, 0, None) 
                print "}"

            else:
                op.error("Output type required!")


###################################
#  psscan - Scan for EPROCESS objects
###################################

def psscan(cmdname, argv):
    """
    This module scans for EPROCESS objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)

    opts, args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
	    start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexidecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
	    end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexidecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"%(filesize))

    else:
        end = filesize

    try:
        if slow == False:
	    print "Fast"
            flat_address_space = FileAddressSpace(filename,fast=True)
	else:
	    flat_address_space = FileAddressSpace(filename,fast=False)
    except:
        op.error("Unable to open image file %s" % (filename))
    
    ps_scan(flat_address_space, types, filename, start, end, slow) 

###################################
#  thrdscan - Scan for ETHREAD objects
###################################

def thrdscan(cmdname, argv):
    """
    This module scans for ETHREAD objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)

    opts, args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
	    start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexidecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
	    end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexidecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"% (filesize) )

    else:
        end = filesize

    try:

        if slow == False:
            flat_address_space = FileAddressSpace(filename,fast=True)
        else:
            flat_address_space = FileAddressSpace(filename,fast=False)

    except:
        op.error("Unable to open image file %s" % (filename))
    
    thrd_scan(flat_address_space, types, filename, start, end, slow) 


###################################
#  sockscan - Scan for socket objects
###################################

def sockscan(cmdname, argv):
    """
    This module scans for socket objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)


    opts, args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexidecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexidecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"%(filesize))

    else:
        end = filesize

    try:

        if slow == False:
            flat_address_space = FileAddressSpace(filename,fast=True)
        else:
            flat_address_space = FileAddressSpace(filename,fast=False)

    except:
        op.error("Unable to open image file %s" % (filename))
    
    socket_scan(flat_address_space, types, filename, start, end, slow) 

###################################
#  connscan - Scan for connection objects
###################################

def connscan(cmdname, argv):
    """
    This module scans for connection objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)

    opts, args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexidecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexidecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"%(filesize))

    else:
        end = filesize

    try:

        if slow == False:
            flat_address_space = FileAddressSpace(filename,fast=True)
        else:
            flat_address_space = FileAddressSpace(filename,fast=False)

    except:
        op.error("Unable to open image file %s" % (filename))
    
    conn_scan(flat_address_space, types, filename, start, end, slow) 
