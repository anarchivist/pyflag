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

## Volatility is now included in the PyFlag source tree to avoid versioning problems.
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

PROTOCOL_ENUM = { 6: "TCP",
                  17: "UDP",
                  }

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

        case_dbh.execute("""CREATE TABLE if not exists `open_files` (
        `iosource` VARCHAR(250),
        `pid` INT not null,
        `filename` VARCHAR(512)
        )""")

        case_dbh.execute("""CREATE TABLE if not exists `modules` (
        `pid` INT not null,
        `iosource` VARCHAR(250),
        `path` VARCHAR(512),
        `base` BIGINT not null,
        `size` INT not null
        )""")

        case_dbh.execute("""CREATE TABLE if not exists `mconnections` (
        `pid` int not null,
        `iosource` VARCHAR(250),
        `lport` int not null,
        `laddr` int not null,
        `rport` int not null,
        `raddr` int not null)""")

        case_dbh.execute("""CREATE TABLE if not exists `sockets` (
        `pid` int not null,
        `iosource` VARCHAR(250),
        `proto`  int not null,
        `port` int not null,
        `create_time` TIMESTAMP)""")
        
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
                #print "Found at %s" % (offset+found)
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

    def process_entry_file(self, dbh, addr_space, types, entry, pid):
        if not addr_space.is_valid_address(entry):
            return

        obj = handle_entry_object(addr_space, types, entry)

        if addr_space.is_valid_address(obj):
            if is_object_file(addr_space, types, obj):
                file = object_data(addr_space, types, obj)
                fname = file_name(addr_space, types, file)
                if fname != "":
                    dbh.insert("open_files",
                               iosource = self.iosource_name,
                               pid = pid,
                               filename = fname,
                               _fast = True)

    def load_open_files(self, dbh, addr_space, types, symtab):
        for table in handle_tables(addr_space, types, symtab):
            process_id = handle_process_id(addr_space, types, table)
            if process_id == None:
                continue

            table_code = handle_table_code(addr_space, types, table)
            if table_code == 0:
                continue

            table_levels = handle_table_levels(addr_space, types, table)

            if table_levels == 0:
                num_entries = handle_num_entries(addr_space, types, table)

                for counter in range(0, 0x200):
                    entry = handle_table_L1_entry(addr_space, types, table, counter)
                    if entry != None and entry !=0:
                        self.process_entry_file(dbh, addr_space, types, entry, process_id)

            elif table_levels == 1:
                for i in range(0, 0x200):
                    L1_entry = handle_table_L1_entry(addr_space, types, table, i)
                    if not L1_entry is None:
                        L1_table = handle_entry_object(addr_space, types, L1_entry)

                        for j in range(0, 0x200):
                            L2_entry = handle_table_L2_entry(addr_space, types, table, L1_table, j)
                            if not L2_entry is None:
                                self.process_entry_file(dbh, addr_space, types, L2_entry, process_id)

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
                                        self.process_entry_file(dbh, addr_space, types, L3_entry, process_id)



    def load(self, mount_point, iosource_name, scanners = None, directory=None):
        ## Ensure that mount point is normalised:
        self.iosource_name = iosource_name
        mount_point = os.path.normpath(mount_point)
        self.mount_point = mount_point
        
        DBFS.load(self, mount_point, iosource_name)
        
        # open the iosource
        iosrc = IO.open(self.case, iosource_name)

        ## Get a db handle
        dbh = DB.DBO(self.case)
        dbh.mass_insert_start('tasks')
        
        (addr_space, symtab, types) = load_and_identify_image(iosrc)
        self.load_open_files(dbh, addr_space, types, symtab)

        ## process_list should probably be a generator here (or not,
        ## the list is unlikely to be that big)
        for task in process_list(addr_space, types, symtab):
            ## Skip invalid tasks (This should probably be done in
            ## process_list itself so it doesnt yield rubbish)
            if not addr_space.is_valid_address(task): continue
            pid = process_pid(addr_space, types, task) or -1
            create_time = process_create_time(addr_space, types, task)

            task_info = {
                'iosource':        iosource_name,
                'image_file_name': process_imagename(addr_space, types, task) or "UNKNOWN",
                'pid':             pid,
                'offset':          task,
                'active_threads':  process_num_active_threads(addr_space, types, task) or -1,
                'inherited_from':  process_inherited_from(addr_space, types,task) or -1,
                'handle_count':    process_handle_count(addr_space, types, task) or -1,
                '_create_time':    "from_unixtime('%s')" % create_time
                }

            ## Put the data in the db
            dbh.mass_insert(**task_info)

            ## Create some VFS nodes:
            new_inode = "I%s|N%s" % (iosource_name, task)
            inode_id = self.VFSCreate(None, new_inode,
                                      "%s/%s/exe" % (mount_point, task_info['pid']),
                                      mtime = create_time,
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
                           value = command_line,
                           _fast = True)

            if peb:
                modules = process_ldrs(process_address_space, types, peb)
                for module in modules:
                    if not process_address_space.is_valid_address(module): continue
                    path = module_path(process_address_space, types, module)
                    base = module_base(process_address_space, types, module) or 0
                    size = module_size(process_address_space, types, module)

                    dbh.insert("modules", iosource = iosource_name,
                               pid = pid,
                               path = path,
                               base = base,
                               _fast = True
                               )

                    self.VFSCreate(None, None,
                                   "%s/%s/Modules/Base 0x%X" % ( mount_point,
                                                                 task_info['pid'],
                                                                 base),
                                   mtime = create_time,
                                   link = path,
                                   size = size,
                                   _fast = True)
                    
        ## Now look for the connections:
        for connection in tcb_connections(addr_space, types, symtab):
            if not addr_space.is_valid_address(connection):
                continue

            dbh.insert("mconnections",
                       pid = connection_pid(addr_space, types, connection),
                       lport   = connection_lport(addr_space, types, connection),
                       laddr   = connection_laddr(addr_space, types, connection),
                       rport   = connection_rport(addr_space, types, connection),
                       raddr   = connection_raddr(addr_space, types, connection),
                       iosource = iosource_name,
                       _fast = True)

        ## Now do the sockets:
        for socket in open_sockets(addr_space, types, symtab):
            if not addr_space.is_valid_address(connection):
                continue

            dbh.insert("sockets",
                       pid   = socket_pid(addr_space, types, socket),
                       proto = socket_protocol(addr_space, types, socket),
                       port  = socket_local_port(addr_space, types, socket),
                       _create_time  = "from_unixtime('%s')" % socket_create_time(addr_space, types, socket),
                       iosource = iosource_name
                       )
        
class MemoryFile(File):
    """ A VFS driver for processes """
    specifier = 'N'

    def read(self, length=None):
        return ''


## Show some stats:
import pyflag.Stats as Stats
class MemroyProcessStats(Stats.Handler):
    name = "Processes"

    def render_tree(self, branch, query, condition='1'):
        dbh = DB.DBO(self.case)
        ## Top level view - we only show the File Types stats branch
        ## if we have any types there.
        if not branch[0]:
            dbh.execute("select count(*) as a from tasks where %s" % condition)
            row = dbh.fetch()
            if row['a']>0:
                yield (self.name, self.name, 'branch')
        elif branch[0] != self.name:
            return
        elif len(branch)==1:
            dbh.execute("select image_file_name from tasks group by image_file_name order by image_file_name")
            for row in dbh:
                t = row['image_file_name'][:20]
                yield (row['image_file_name'].replace("/","__"), t, 'leaf')
        elif len(branch)==2:
            dbh.execute("select pid from tasks where image_file_name=%r order by pid", branch[1])
            for row in dbh:
                pid = row['pid'].__str__()
                yield (pid, pid, 'leaf')
        else:
            for x in self.chain_tree(MemroyPidStats,
                                     [MemroyPidStats.name, branch[2]] + branch[3:],
                                     query):
                yield x
                
    def render_pane(self, branch, query, result, condition='1'):
        ## We may only draw on the pane that belongs to us:
        if branch[0] != self.name:
            return

        if len(branch)==1:
            result.heading("Show executables found in memory")
            result.text("This statistic show the executables found in memory")
        else:
            t = branch[1].replace("__",'/')
            result.table(
                elements = [ StringType(column = 'iosource', name='IOSource'),
                             IntegerType(column = 'pid', name='PID'),
                             TimestampType('Time Created','create_time')],
                table = 'tasks',
                where = 'image_file_name = %r and %s' % (t, condition),
                case = self.case,
                )

            
class MemoryModulesStats(Stats.Handler):
    name = "Modules"

    def render_tree(self, branch, query, condition='1'):
        dbh = DB.DBO(self.case)
        ## Top level view - we only show the File Types stats branch
        ## if we have any types there.
        if not branch[0]:
            dbh.execute("select count(*) as a from modules where %s" % condition)
            row = dbh.fetch()
            if row['a']>0:
                yield (self.name, self.name, 'branch')
        elif branch[0] != self.name:
            return
        elif len(branch)==1:
            dbh.execute("select path from modules where %s " % condition)
            for row in dbh:
                t = os.path.basename(row['path'].replace('\\','/'))
                yield (t, t, 'leaf')
        
    def render_pane(self, branch, query, result, condition='1'):
        ## We may only draw on the pane that belongs to us:
        if branch[0] != self.name:
            return

        if len(branch)>=1:
            result.table(
                elements = [ StringType(column = 'iosource', name='IOSource'),
                             IntegerType(column = 'pid', name='PID'),
                             StringType(column = 'path', name="Path"),
                             ## Render base address in Hex:
                             IntegerType(column = "base", name="Base",
                                         callback = lambda x: "0x%08X" % x),
                             IntegerType(column = "size", name="Size")],
                table = 'modules',
                where = condition,
                case = self.case,
                )

class MemoryFilesStats(Stats.Handler):
    name = "Open Files"

    def render_tree(self, branch, query, condition='1'):
        dbh = DB.DBO(self.case)
        ## Top level view - we only show the File Types stats branch
        ## if we have any types there.
        if not branch[0]:
            dbh.execute("select count(*) as a from open_files where %s" % condition)
            row = dbh.fetch()
            if row['a']>0:
                yield (self.name, self.name, 'branch')
        elif branch[0] != self.name:
            return
        elif len(branch)==1:
            dbh.execute("select filename from open_files where %s " % condition)
            for row in dbh:
                t = os.path.basename(row['filename'].replace('\\','/'))
                if len(t) > 20: t = t[:10] + ' ... ' + t[-10:]
                yield (t, t, 'leaf')
        
    def render_pane(self, branch, query, result, condition='1'):
        ## We may only draw on the pane that belongs to us:
        if branch[0] != self.name:
            return

        if len(branch)==1:
            result.heading("Show executables found in memory")
            result.text("This statistic show the executables found in memory")
        else:
            t = branch[1].replace("__",'/')
            result.table(
                elements = [ StringType(column = 'iosource', name='IOSource'),
                             IntegerType(column = 'filename', name='File Name'),
                             IntegerType(column = 'pid', name='Process ID')],
                table = 'open_files',
                where = condition,
                case = self.case,
                )

class MemorySocketStats(Stats.Handler):
    name = "Open Sockets"

    def render_tree(self, branch, query, condition='1'):
        dbh = DB.DBO(self.case)
        ## Top level view - we only show the File Types stats branch
        ## if we have any types there.
        if not branch[0]:
            dbh.execute("select count(*) as a from sockets where %s" % condition)
            row = dbh.fetch()
            if row['a']>0:
                yield (self.name, self.name, 'branch')
        elif branch[0] != self.name:
            return
        elif len(branch)==1:
            dbh.execute("select proto from sockets where %s group by proto " % condition)
            for row in dbh:
                t = PROTOCOL_ENUM.get(row['proto'], row['proto'])
                yield (row['proto'].__str__(), t, 'leaf')
        elif len(branch)==2:
            dbh.execute("select port from sockets where proto='%s' and %s group by port" %
                        (branch[1],condition))
            for row in dbh:
                t = row['port'].__str__()
                yield (t, t, 'leaf')

    def render_pane(self, branch, query, result, condition='1'):
        ## We may only draw on the pane that belongs to us:
        if branch[0] != self.name:
            return
        
        elements = [ StringType(column = 'iosource', name='IOSource'),
                     IntegerType(column = 'pid', name='PID'),
                     IntegerType(column = 'proto', name='Protocol'),
                     IntegerType(column = 'port', name='Port'),
                     TimestampType('Time Created','create_time')]
        
        try:
            condition += " and proto=%s" % branch[1]
            del elements[2]
        except IndexError: pass

        try:
            condition += " and port=%s" % branch[2]
            del elements[2]
        except IndexError: pass
        
        result.heading("Show sockets found in memory")
        result.text("This statistic show the sockets found in memory")
        result.table(
            elements =elements,
            table = 'sockets',
            where = condition,
            case = self.case,
            )

class MemroyPidStats(Stats.Handler):
    name = "Process IDs"
    classes = [ MemoryModulesStats, MemorySocketStats, MemoryFilesStats]
    
    def render_tree(self, branch, query, condition=''):
        dbh = DB.DBO(self.case)
        ## Top level view - we only show the File Types stats branch
        ## if we have any types there.
        if not branch[0]:
            dbh.execute("select count(*) as a from tasks")
            row = dbh.fetch()
            if row['a']>0:
                yield (self.name, self.name, 'branch')
        elif branch[0] != self.name:
            return
        elif len(branch)==1:
            dbh.execute("select pid  from tasks group by pid")
            for row in dbh:
                t = row['pid'].__str__()
                yield (t, t, 'leaf')
        else:
            for c in self.classes:
                ## Show the modules:
                for x in self.chain_tree(c, branch[2:],
                                         query, condition="pid='%s'" % branch[1]):
                    yield x

    def render_pane(self, branch, query, result):
        ## We may only draw on the pane that belongs to us:
        if branch[0] != self.name:
            return

        if len(branch)==1:
            result.heading("Show executables found in memory")
            result.text("This statistic show the executables found in memory")

        elif len(branch)==2:
            t = branch[1].replace("__",'/')
            result.table(
                elements = [ StringType(column = 'iosource', name='IOSource'),
                             IntegerType(column = 'pid', name='PID'),
                             TimestampType('Time Created','create_time')],
                table = 'tasks',
                where = 'pid = %r' % t,
                case = self.case,
                )
        else:
            for c in self.classes:
                if branch[2] == c.name:
                    self.chain_pane(c, branch[2:], query, result,
                                    condition="pid='%s'" % branch[1])


import pyflag.tests

## Unit test
class MemoryFS(pyflag.tests.ScannerTest):
    """ Test Memory Forensic Analysis """
    test_case = "Memory"
    test_file = "xp-laptop-2005-06-25.img.e01"
    subsystem = "EWF"
    fstype = "Memory"
    mount_point = "proc"
    
