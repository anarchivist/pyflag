""" This module is a an implementation of a memory forensic module
based on Volatility 1.3
"""
import pyflag.FlagFramework as FlagFramework
## A linux filesystem loader
import pyflag.FileSystem as FileSystem

from pyflag.ColumnTypes import StateType, InodeIDType, IntegerType, BigIntegerType, StringType
import os
import pyflag.IO as IO
import pyflag.DB as DB
import pyflag.Reports as Reports

## Make sure that volatility is in the system path
import sys,re
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.pyflaglog as pyflaglog

active = True

try:
    ## Include volatility in the python path here (We only support Volatility 1.3):
    volatility_path = None
    for d in os.listdir(os.path.dirname(__file__)):
        if d.startswith("Volatility-1.3"):
            volatility_path = os.path.join(os.path.dirname(__file__),d)
            
    ## We need to make sure that we get in before an older version
    if volatility_path and volatility_path not in sys.path:
        sys.path.insert(0,volatility_path)

    from vtypes import xpsp2types as types
    from vsyms import *
    #from forensics.win32.tasks import find_dtb
    #from forensics.win32.tasks import find_csdversion
    from forensics.linux.files import file_pathname
    from forensics.addrspace import *
    from forensics.x86 import *
    #from forensics.win32.crash_addrspace import *
    #from forensics.win32.hiber_addrspace import *
    from string import split
    from forensics.object2 import *
    from forensics.object import *
    from forensics.linked_list import *
    from forensics.linux.tasks import *
    from vutils import *
    from forensics.linux.info import info_systime, info_timezone,\
        info_cpus, info_system_utsname

    ## Initialise volatility's registry
    import forensics.registry as MemoryRegistry

    MemoryRegistry.Init()

    def FormatWithDefaults(format,args,defaults={}):
        argslist = list(args)
        if len(defaults) > 0:
            for index, item in enumerate(argslist):
                if item == None:
                    if index in defaults:
                        argslist[index] = defaults[index]
            args = tuple(argslist)

        output = format%args
        return output

    PAGESIZE = 0x1000

    class IOSourceAddressSpace(FileAddressSpace):
        def __init__(self, fd):
            #self.fname = fd.name
            #self.name = fd.name
            self.fhandle = fd
            self.fsize = fd.size
            self.fast_fhandle = fd

    ## Volatility comes with memory maps and profiles - we need to know
    ## where they are:
    config.add_option("memory_profile_dir", default=volatility_path + "/profiles",
                      help = "Directory that contains all volatility profiles.")

## Switch ourselves off if volatility is not there
except ImportError,e:
    active = False
    pyflaglog.log(pyflaglog.INFO, "Download and unpack Volatility1.3 in %s for memory foreniscs" % os.path.dirname(__file__))

## These are all kind of tables we need for memory forensics
class ProcessTypeSet(StateType):
    states = { "Process": 'process',
               "Module" : 'module'}

class ActivityState(StateType):
    states = {"Running": '0',
              "Interruptible": '1',
              "Uninterruptible": '2',
              "Stopped": '4',
              "Traced": '8',
              "Zombie": '16',
              "Dead": '32',
              "Noninteractive": '64'}

class MemoryOffsetType(BigIntegerType):
    """ A Column class that shows memory offsets """
    def plain_display_hook(self, value, row, result):
        offset, inode = value.split(",")
        offset = int(offset)

        ## The target Inode is the inode we are operating on:
        inodes = inode.split("|")
        last_inode = "|".join(inodes[:-1])

        ## Note that the offset is in virtual address space, we want
        ## to send the user back to the image (physical address space)
        ## so we need to convert here:
        v = get_vol_object(self.case, last_inode[1:])

        ## Physical offset:
        phy_offset = v.addr_space.vtop(offset)
        
        target = FlagFramework.query_type(family="Disk Forensics",
                                          report="ViewFile",
                                          offset=phy_offset,
                                          inode=last_inode,
                                          case=self.case,
                                          memory=last_inode[1:],
                                          mode="HexDump")
        
        result.link("0x%08X" % offset, target=target, pane='new')
    
    display_hooks = [ plain_display_hook ]

    def select(self):
        return "concat(%s, ',', inode.inode)" % (self.escape_column_name(self.column))
    
class ProcessTable(FlagFramework.CaseTable):
    """ Process Table - Stores information about running tasks """
    name = 'mem_process'
    columns = [ [ InodeIDType, {} ],
                [ IntegerType, dict(name = "Process ID", column = 'pid') ],
                [ StringType, dict(name = "Task Name", column='task_name')],
                [ ProcessTypeSet, dict(name = "Process Type", column = 'type') ],

                ## This is the offset to the relevant task_struct
                [ MemoryOffsetType, dict(name = 'Offset', column='offset') ],
                [ IntegerType, dict(name = "Parent Process", column = 'ppid') ],
                [ IntegerType, dict(name = 'User ID', column = 'uid') ],

                ## This is the running state of the process
                [ ActivityState, dict(name = 'State', column = 'state')],

                ## This is the resident size
                [ IntegerType, dict(name = 'Resident Size', column='rss')],
                [ IntegerType, dict(name = 'Virtual Size', column='vsz')],               
                ]

class FileTypeSet(StateType):
    states = { "S_IFBLK": '24576',
               "S_IFDIR": '16384',
               "S_IFLNK": '40960',
               "S_IFREG": '32768',
               "S_IFCHR": '8192',
               "S_IFIFO": '4096',
               "S_IFSOCK": '49152'}

class OpenFileTable(FlagFramework.CaseTable):
    """ Process Open files - Files currently opened by the process """
    name = "mem_open_files"
    columns = [ [ InodeIDType, {} ],
                [ IntegerType, dict(name = 'Fd', column='fd')],
                [ InodeIDType, dict(name = "Resolved File", column = 'opened_inode_id') ],
                [ MemoryOffsetType, dict(name='File Struct', column='offset_to_file')],
                [ MemoryOffsetType, dict(name='Dentry', column='offset_to_dentry')],
                [ MemoryOffsetType, dict(name='Inode Struct', column='offset_to_inode')],
                [ FileTypeSet, dict(name='File Type', column='type')],
                [ StringType, dict(name='Path',column='path')],
                ]

class SocketTypeSet(StateType):
    states = { "PF_LOCAL:SOCK_STREAM": "PF_LOCAL:SOCK_STREAM",
               }

class OpenSockets(FlagFramework.CaseTable):
    """ Open Sockets - Sockets Currently opened by the process """
    name = "mem_sockets"
    columns = [ [ InodeIDType, {} ],
                [ IntegerType, dict(name = "File Desc", column = 'fd') ],
                [ SocketTypeSet, dict(name = "Type", column = 'type')],
                [ BigIntegerType, dict(name = "Offset", column ='offset')],
                ]

class VolatilityContext:
    """ This is a cachable context which can be used for volatility
    operations"""
    
    def __init__(self, case, iosource_name, profile, map):
        ## Try to open the image
        self.iosource_name = iosource_name
        self.case = case
        self.map = map
        self.tasks = {}
        print "Opening memory image"
        path_to_profiles = "%s/%s" % (config.memory_profile_dir,
                                      profile)

        print path_to_profiles
        profile_file_name = [ m for m in os.listdir(path_to_profiles) \
                              if m.endswith(".py") ][0]

        print "Profile name %s" % profile_file_name
        self.profile = load_profile_from_file("%s/%s" % (path_to_profiles,
                                                                    profile_file_name))
        try:
            symdict = load_symboltable_from_file("%s/%s" % (path_to_profiles,
                                                                   map))
            self.symtable = SymbolTable(symdict)
        except:
            raise RuntimeError("Invalid or corrupt Symbol Table file %s/%s" % (path_to_profiles, profile_file_name))

        pgd = self.symtable.lookup('swapper_pg_dir')
        iosrc = IO.open(self.case, iosource_name)
        phyAS = IOSourceAddressSpace(iosrc)
        self.addr_space = IA32PagedMemory(phyAS, pgd - 0xc0000000)
        self.theProfile = Profile(abstract_types = self.profile)

    def get_task_from_pid(self, pid):
        try:
            return self.tasks[pid]
        except:
            self.populate_tasks()
            return self.tasks[pid]

    def populate_tasks(self):
        ## Maybe its not populated yet
        task_start_vaddr = self.symtable.lookup('init_tasks')

        print process_list
        task_list = process_list(self.addr_space,self.theProfile.abstract_types,
                                 self.symtable,
                                 self.theProfile)
            
        for task in task_list:
            self.tasks[task.pid] = task
            
import pyflag.Store as Store
VOLATILITY_CACHE = Store.Store(max_size=3)

def get_vol_object(case, iosource_name):
    key = "%s:%s" % (case, iosource_name)
    try:
        return VOLATILITY_CACHE.get(key)
    except KeyError:
        dbh = DB.DBO(case)
        dbh.execute("select * from filesystems where iosource = %r and "
                    "property='profile' limit 1", iosource_name)
        row = dbh.fetch()

        profile = row['value']
        dbh.execute("select * from filesystems where iosource = %r and "
                    "property='map' limit 1", iosource_name)
        row = dbh.fetch()

        map = row['value']

        result = VolatilityContext(case, iosource_name, profile, map)
        VOLATILITY_CACHE.put(result, key=key)
        return result

class LinuxMemory(FileSystem.DBFS):
    """ A Linux memory analysis system based on Volatility 1.3 """
    name = 'Linux Memory'
    order = 5
    parameters = ['profile', 'map']

    def load(self, mount_point, iosource_name, loading_scanners = None):
        """ Load the memory image into the VFS - based on linux
        plugins in Volatility 1.3
        """
        self.mount_point = os.path.normpath(mount_point)
        self.iosource_name = iosource_name

        FileSystem.DBFS.load(self, mount_point, iosource_name)

        ## Insert into into the filesystems table:
        dbh = DB.DBO(self.case)
        dbh.insert("filesystems",
                   iosource = iosource_name,
                   property = 'profile',
                   value = self.query['profile'],)
                   
        dbh.insert("filesystems",
                   iosource = iosource_name,
                   property = 'map',
                   value = self.query['map'],)

        v = get_vol_object(self.case, iosource_name)
        
        ## Find image tasks
        self.find_tasks(v)



    def find_open_files(self, v, task, inode_id):
        fds = task_fds(task, v.addr_space, v.theProfile.abstract_types, v.symtable, v.theProfile)
        dbh = DB.DBO(self.case)
        for fd, filep, dentry, inode in fds:
            fileinfo = Object('file', filep, v.addr_space, \
                None, v.theProfile)

            pathname = file_pathname(fileinfo, v.addr_space, v.theProfile)

            inode = Object('inode', inode.offset, v.addr_space, \
                           None, v.theProfile)

            dbh.insert('mem_open_files',
                       inode_id = inode_id,
                       fd = fd,
                       offset_to_file = filep,
                       offset_to_dentry = dentry.offset,
                       offset_to_inode = inode.offset,
                       _type = "'%s'" % inode.m('i_mode').v(),
                       path = pathname)

            ## Create VFS nodes for the open files
            self.VFSCreate(None,
                           "I%s|Vfile%s" % (self.iosource_name,
                                           task.pid),
                           "%s/proc/%s/fd/%s" % (self.mount_point,
                                                 task.pid, pathname),
                           uid = task.uid,
                           gid = task.gid,
                           )
                   
    def find_tasks(self, v):
        dbh = DB.DBO(self.case)
        v.populate_tasks()

        task_list = v.tasks.values()
        for task in task_list:
            ## Remember the task struct so we can quickly tie it to
            ## the pid
            v.tasks[task.pid] = task
            comm = read_null_string(v.addr_space, v.theProfile.abstract_types,\
                ['task_struct', 'comm'], task.offset)

            parent = task.m('parent').v()
            parent_pid = task_to_pid(task_list,parent)
            
            processor = task_cpu(task.thread_info.cpu)

            task_state = task.state

            rss = task_rss(task)

            if rss:
                rss = (rss * PAGESIZE)/1024

            total_vm = task_total_vm(task)

            if total_vm:
                total_vm = (total_vm * PAGESIZE)/1024 

                args = dict(pid = task.pid,
                            task_name = comm,
                            ppid = parent_pid,
                            uid = task.uid,
                            offset = task.offset,
                            state = task_state,
                            vsz = total_vm,
                            rss = rss,
                            )

                inode_id = self.VFSCreate(None,
                                          "I%s|Vbin%s" % (self.iosource_name,
                                                       task.pid),
                                          "%s/proc/%s/%s" % (self.mount_point,
                                                             task.pid, comm),
                                          uid = task.uid,
                                          gid = task.gid,
                                          )
                
                args['inode_id'] = inode_id
                args['task_name'] = comm
                dbh.insert('mem_process',
                           **args)

                inode = "I%s|Vmap%s" % (self.iosource_name,
                                        task.pid)

                self.VFSCreate(None,
                               inode,
                               "%s/proc/%s/maps" % (self.mount_point,
                                                    task.pid),
                               uid = task.uid,
                               gid = task.gid,
                               )

                ## Now find all our open files:
                self.find_open_files(v, task, inode_id)

    def form(self, query, result):
        ## Get a list of all the profiles
        profiles = os.listdir(config.memory_profile_dir)
        result.const_selector("Profile", 'profile', profiles, profiles)
        try:
            maps = os.listdir("%s/%s" % (config.memory_profile_dir,
                                         query['profile']))
            maps = [ m for m in maps if m.endswith(".map") ]
            result.const_selector("Symbol Map", 'map', maps, maps)
        except KeyError:
            maps = []

## The volatility file drivers 
class VolFile(FileSystem.File):
    """ A File driver for reading memory related inodes """
    specifier = 'V'

    def __init__(self, case, fd, inode):
        FileSystem.File.__init__(self, case,fd, inode)
        m = re.match(".([^0-9]+)([0-9]+)", inode)
        if not m:
            raise RuntimeError("Invalid inode %s" % inode)
        self.type = m.group(1)
        self.pid = int(m.group(2))
        self.done = False
        self.cache()

    def format_time(self, time):
        ts=strftime("%a %b %d %H:%M:%S %Y",
                        gmtime(time))
        return ts

    def explain(self, query, result):
        self.fd.explain(query,result)

        tmp = result.__class__(result)
        v=self.get_vol_object()

        # Get system time
        timespec = info_systime(v.addr_space, v.theProfile, v.symtable)
	tv_sec = timespec.tv_sec
	time = self.format_time(tv_sec)

        # Get timezone information
        sys_tz = info_timezone(v.addr_space, v.theProfile, v.symtable)
        tz_minuteswest = sys_tz.tz_minuteswest
	tz_hours = tz_minuteswest/60
	tz_dsttime = sys_tz.tz_dsttime

        # Get the number of cpus
        num_cpus = info_cpus(v.addr_space, v.theProfile, v.symtable)

        # Get utsname info
        system_utsname = info_system_utsname(v.addr_space, v.theProfile, v.symtable)
        if not system_utsname:
	    print "Cannot access uts information"
	    return

        release = read_null_string(v.addr_space, v.theProfile.abstract_types,\
                ['new_utsname', 'release'], system_utsname.offset)
        nodename = read_null_string(v.addr_space, v.theProfile.abstract_types,\
                ['new_utsname', 'nodename'], system_utsname.offset)
        sysname = read_null_string(v.addr_space, v.theProfile.abstract_types,\
                ['new_utsname', 'sysname'], system_utsname.offset)
        version = read_null_string(v.addr_space, v.theProfile.abstract_types,\
                ['new_utsname', 'version'], system_utsname.offset)
        machine = read_null_string(v.addr_space, v.theProfile.abstract_types,\
                ['new_utsname', 'machine'], system_utsname.offset)
        domainname = read_null_string(v.addr_space, v.theProfile.abstract_types,\
                ['new_utsname', 'domainname'], system_utsname.offset)

        tmp.row("CPUS",num_cpus,**{'class': 'explain'})
        tmp.row("GMTDATE",time,**{'class': 'explain'})
       	tmp.row("TIMEZONE","GMT -%d (minutes west: %d dsttime: %d)"%(tz_hours,tz_minuteswest,tz_dsttime),**{'class': 'explain'})
        tmp.row("RELEASE",release,**{'class': 'explain'})
        tmp.row("NODENAME",nodename,**{'class': 'explain'})
        tmp.row("SYSNAME",sysname,**{'class': 'explain'})
        tmp.row("VERSION",version,**{'class': 'explain'})
        tmp.row("MACHINE",machine,**{'class': 'explain'})
        tmp.row("DOMAINNAME",domainname,**{'class': 'explain'})

        result.row("Linux Memory Image", tmp,**{'class': 'explainrow'})

    def read(self, length = None):
        try:
            return FileSystem.File.read(self,length)
        except IOError:
            pass

        if not self.done:
            v=self.get_vol_object()
            self.done = True
            return self.make_map_file(v, self.pid)
        
        return ''

    def get_vol_object(self):
            assert(self.fd.inode.startswith("I"))
            iosource = self.fd.inode[1:]

            v = get_vol_object(self.case, iosource)
            return v
    
    def make_map_file(self, v, pid):
        """ Create the map file """
        result = ''
        task = v.get_task_from_pid(pid)
        if task.mm.is_valid():
            result += "%-10s %-10s %-10s %-10s %-10s"%("StartCode","EndCode","StartData","EndData","StartStack")

            start_code = task.mm.start_code
            end_code   = task.mm.end_code
            start_data = task.mm.start_data
            end_data   = task.mm.end_data
            start_stack= task.mm.start_stack

            defaults = {0:0,1:0,2:0,3:0,4:0,5:0}
            result += FormatWithDefaults("0x%0.8x 0x%0.8x 0x%0.8x 0x%0.8x 0x%0.8x\n", \
                                         (start_code,
                                          end_code,
                                          start_data,
                                          end_data,
                                          start_stack),defaults)
            map_count = task.mm.map_count
            mmap = task.mm.mmap
            if mmap == None:
                return ''

            segment_list = linked_list_collect(v.theProfile, mmap, "vm_next", 0)
            result += "%-10s %-10s %-10s %-6s %-6s\n"%("VMA","START","END","FLAGS","FILE")
            for segment in segment_list:
                filestring = ""
                file = segment.vm_file
                if file.is_valid():
                    filestring = file_pathname(file, v.addr_space, v.theProfile)

                result += "0x%0.8x 0x%0.8x 0x%0.8x %-6x %s\n"%(segment.offset,segment.vm_start,segment.vm_end,segment.vm_flags,filestring)

            return result

## Some reports
class ProcessReport(Reports.CaseTableReports):
    """ View running processes in memory """
    name = "View Processes"
    family = "Memory Forensics"
    default_table = "ProcessTable"
    columns = [ "Inode", "Process ID", "Task Name", "Offset",
               "User ID", "State"]

class OpenFileReport(ProcessReport):
    """ View all open files by processes """
    name = "View Open Files"
    default_table = "OpenFileTable"
    columns = [ "Inode", "Fd", "File Struct", "Dentry", "Inode Struct",
               "Path"]

class OpenSocketsReport(ProcessReport):
    """ View all open sockets """
    name = "View Sockets"
    default_table = "OpenSockets"
    columns = ['Inode', 'File Desc', 'Type', 'Offset']

## Unit tests:
import pyflag.tests
import pyflag.pyflagsh as pyflagsh

class VolatilityTests(pyflag.tests.ScannerTest):
    """ Volatility - Linux, Memory Forensics tests """
    test_case = "memory"
    test_file = "/response_data/challenge.mem"
    subsystem = 'Standard'
    ## We prefer to load our own fs
    fstype = ''

    def test00preLoadCase(self):
        """ Load Memory image """
        pyflag.tests.ScannerTest.test00preLoadCase(self)
        pyflagsh.shell_execv(command="execute",
                             argv=["Load Data.Load Filesystem image",'case=%s' % self.test_case,
                                   "iosource=test",
                                   "fstype=Linux Memory",
                                   "profile=2_6_18-8_1_15_el5",
                                   "map=System.map-2.6.18-8.1.15.el5.map",
                                   "mount_point=%s" % self.mount_point])
