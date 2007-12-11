""" This module uses volatility from
http://www.volatilesystems.com/VolatileWeb/ to implement a memory
forensic capability in pyflag
"""

import pyflag.FileSystem as FileSystem
import pyflag.FlagFramework as FlagFramework
import pyflag.pyflaglog as pyflaglog
from pyflag.FileSystem import FileSystem, DBFS, File
import pyflag.DB as DB
import pyflag.IO as IO
from pyflag.TableObj import StringType, TimestampType, InodeType, FilenameType, IntegerType

## FIXME: Conditionally import these in case Volatility is not installed
## FIXME2: Remove wildcard imports to more specific imports.
from forensics.win32.datetime import *
from forensics.win32.tasks import *
from forensics.win32.network import *
from forensics.win32.handles import *
from forensics.win32.modules import *
from forensics.win32.vad import *
from forensics.win32.scan import *
from forensics.x86 import *

from vtypes import xpsp2types as types
from vsyms import *

class MemoryForensicEventHandler(FlagFramework.EventHandler):
    """ Create specialised tables to store memory related things """
    def create(self, case_dbh, case):
        """ This is run when a new case is created """
        case_dbh.execute("""CREATE TABLE if not exists `tasks` (
        `iosource` VARCHAR(250),
        `image_file_name` VARCHAR(250),
        `pid` INT not null,
        `offset` BIGINT NOT NULL,
        `active_threads` INT not null,
        `inherited_from` INT not null,
        `handle_count` INT not null,
        `create_time` TIMESTAMP
        )""")

class IOSourceAddressSpace(FileAddressSpace):
    def __init__(self, fd):
        self.fname = fd.name
        self.name = fd.name
        self.fhandle = fd
        self.fsize = fd.size
        self.fast_fhandle = fd

BLOCKSIZE = 1024 * 1024 * 10

def find_dtb(addr_space, types):
    """
    Find the Idle dtb (DTB Feeling lucky)
    """
    offset = 0
    while 1:
        data = addr_space.fread(BLOCKSIZE)
        found = 0
        if not data:
	    break

        while 1:
            found = data.find("\x03\x00\x1b\x00", found+1)
            if found >= 0:
                print "Found at %s" % (offset+found)
                (type,size) = unpack('HH',data[found:found+4])
                if process_imagename(addr_space,types,offset+found).find('Idle') != -1:
                    return process_dtb(addr_space, types, offset+found)

            else:
                break
            
        offset+=len(data)

    return None

def load_and_identify_image(fd, dtb=None, type=nopae_syms):
    flat_address_space = IOSourceAddressSpace(fd)
    
    if not dtb:
        dtb = find_dtb(flat_address_space, types)

    try:
        addr_space = IA32PagedMemory(flat_address_space, dtb)
        if not addr_space.is_valid_address(type.lookup('PsLoadedModuleList')):
            raise IOError("Invalid image file")
    ## FIXME: More specific except clauses
    except:
        raise
        addr_space = None
        
    return (addr_space, type, types)
            
class Memory(DBFS):
    """ Class to load a memory image into the VFS """
    name = "Memory"

    def load(self, mount_point, iosource_name, scanners = None, directory=None):
        ## Ensure that mount point is normalised:
        mount_point = os.path.normpath(mount_point)
        DBFS.load(self, mount_point, iosource_name)
        
        # open the iosource
        iosrc = IO.open(self.case, iosource_name)

        ## Get a db handle
        dbh = DB.DBO(self.case)
        dbh.mass_insert_start('tasks')
        
        (addr_space, symtab, types) = load_and_identify_image(iosrc)
        ## process_list should probably be a generator here (or not,
        ## the list is unlikely to be that big)
        for task in process_list(addr_space, types, symtab):
            ## Skip invalid tasks (This should probably be done in
            ## process_list itself so it doesnt yield rubbish)
            if not addr_space.is_valid_address(task): continue

            task_info = {
                'iosource':        iosource_name,
                'image_file_name': process_imagename(addr_space, types, task) or "UNKNOWN",
                'pid':             process_pid(addr_space, types, task) or -1,
                'offset':          task,
                'active_threads':  process_num_active_threads(addr_space, types, task) or -1,
                'inherited_from':  process_inherited_from(addr_space, types,task) or -1,
                'handle_count':    process_handle_count(addr_space, types, task) or -1,
                'create_time':     process_create_time(addr_space, types, task) or 0,
                }

            ## Put the data in the db
            dbh.mass_insert(**task_info)

            ## Create some VFS nodes:
            new_inode = "I%s|N%s" % (iosource_name, task)
            inode_id = self.VFSCreate(None, new_inode,
                                      "%s/%s/exe" % (mount_point, task_info['pid']),
                                      _mtime = task_info['create_time'],
                                      link = task_info['image_file_name'],
                                      _fast = True)

            ## Try to read the PEB:
            peb = process_peb(addr_space, types, task)
            process_address_space = process_addr_space(addr_space, types, task, None)
            command_line = process_command_line(process_address_space, types, peb)
            if command_line:
                dbh.insert('xattr',
                           inode_id=inode_id,
                           property = "command_line",
                           value = command_line)

            if peb:
                modules = process_ldrs(process_address_space, types, peb)
                for module in modules:
                    if not process_address_space.is_valid_address(module): continue
                    path = module_path(process_address_space, types, module)
                    base = module_base(process_address_space, types, module) or 0
                    size = module_size(process_address_space, types, module)

                    self.VFSCreate(None, None,
                                   "%s/%s/Modules/Base 0x%X" % ( mount_point,
                                                                 task_info['pid'],
                                                                 base),
                                   _mtime = task_info['create_time'],
                                   link = path,
                                   size = size,
                                   _fast = True)
            
class MemoryFile(File):
    """ A VFS driver for processes """
    specifier = 'N'

    def read(self, length=None):
        return ''

import pyflag.tests

## Unit test
class MemoryFS(pyflag.tests.ScannerTest):
    """ Test Memory Forensic Analysis """
    test_case = "Memory"
    test_file = "xp-laptop-2005-06-25.img"
    subsystem = "Advanced"
    fstype = "Memory"
    mount_point = "proc"
    
