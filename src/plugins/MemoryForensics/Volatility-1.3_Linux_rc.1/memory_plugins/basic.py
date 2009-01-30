""" These are basic modules which demonstrate how basic functionality
is now built using object2.py.  These functions are basically the same
as the built in ones.
"""
import forensics.utils as utils
from vmodules import *
from vtypes import *
from forensics.win32.tasks import pslist
from forensics.win32.network import module_versions
import forensics.commands
from forensics.object2 import Profile, NewObject, Array, Curry, Pointer

class lsof(forensics.commands.command):
    """List open files in all processes' handle table """
    def pid_generator(self, cb, addr_space, profile):
        for p in pslist(addr_space, profile):
            pid = p.UniqueProcessId.v()

            ## We only print the handles from the pid or if not provided all pids:
            if self.opts.pid == None or (pid == self.opts.pid):
                yield p, cb(p)

    def parser(self):
        forensics.commands.command.parser(self)
        self.op.add_option('-p','--pid',action='store', type='int', default=None,
                           help='Get info for this Pid')

    def render_text(self, outfd, result):
        for p, filenames in result:
            pid = p.UniqueProcessId.v()
            
            outfd.write("*" * 50 + "\n")
            outfd.write("Pid:%s\n" % pid)
            for f in filenames:
                outfd.write("%s\n" % f)

    def calculate(self):
        profile = Profile()
        addr_space = utils.load_as(self.opts)

        ## Grab all the handle tables from processes
        def files_in_pid(p):
            for f in p.handles():
                filename = f.FileName.v()
                if filename:
                    yield filename
                    
        return self.pid_generator(files_in_pid, addr_space, profile)

class lsdll(lsof):
    """List mapped dlls in all processes """
    def render_text(self, outfd, result):
        for p, modules in result:
            peb = p.Peb
            outfd.write("*" * 50 + "\n")
            outfd.write("%s pid: %s\n" % (p.ImageFileName, p.UniqueProcessId.v()))

            if not peb:
                outfd.write("Unable to read PEB for task.\n")
                continue

            ## Print out the command line:
            outfd.write("Command Line: %s\n" % peb.ProcessParameters.CommandLine)

            ## Print the version:
            outfd.write("%s\n\n" % peb.CSDVersion)
            
            outfd.write("%-12s\t%-12s\t%s\n"%('Base','Size','Path'))
            for base,size,path in modules:
                outfd.write("0x%-10X\t0x%-10X\t%s\n"%(base, size,path))

            outfd.write("\n")

    def calculate(self):
        profile = Profile()
        addr_space = utils.load_as(self.opts)

        def list_modules(p):
            peb = p.Peb
            if peb and peb.is_valid():
                ## list all the modules attached to this peb:
                for module in peb.Ldr.InLoadOrderModuleList.list_of_type(
                    "_LDR_MODULE", "InLoadOrderModuleList"):
                    yield module.BaseAddress, module.SizeOfImage, module.FullDllName

        return self.pid_generator(list_modules, addr_space, profile)

class lscon(lsof):
    """ List open connections """
    def render_text(self, outfd, result):
        outfd.write("%-25s %-25s %-6s\n"%('Local Address','Remote Address','Pid'))
        for pid, remote_ip, remote_port, local_ip, local_port in result:
            outfd.write("%-25s %-25s %-6d\n" % ( "%s:%s" % (local_ip, local_port),
                                               "%s:%s" % (remote_ip, remote_port),
                                               pid))

    def get_tcb_connections(self, base_addr, TCBTableOff, SizeOff):
        """ Follow the list of TCB Tables specified.

        The TCBTable is a hash table of lists to existing
        connections. The TCBTableOff and SizeOff are offsets relative
        to the BaseAddress of the tcpip.sys module (i.e. they are
        static module variables) to the hash table in memory.
        """
        ## We first find the size of the hash table:
        hash_table_size = NewObject('unsigned long', base_addr + SizeOff,
                                    self.addr_space,
                                    profile=self.profile).v()

        ## This is how we define a new type on the fly - We dont
        ## actually store it in the profile we only use it here.
        TCB_Table = self.profile.list_to_type(
            ## Thats the name of the type
            "TCB_Table",
            ## This is the new type:
            ## It is a pointer to an array of size hash_table_size of pointers to _TCPT_OBJECTs
            ['pointer', ['array', hash_table_size, ['pointer', ['_TCPT_OBJECT']]]])
        
        ## To actually use it we need to instantiate it directly (we
        ## never stored it in the profile so we cant use NewObject).
        ## When we instantiate it we need to provide it with the
        ## missing parameters, namely the offset and address_space.
        TCB_Table = TCB_Table(offset = base_addr + TCBTableOff,
                              profile = self.profile,
                              vm = self.addr_space,).dereference()

        ## If the pointer fails to dereference (i.e. it points
        ## somewhere invalid), we skip it:
        if not TCB_Table: return

        ## Now we just iterate over all _TCPT_OBJECT in the table and
        ## see if they follow to linked lists. We then traverse the
        ## lists:
        for i in TCB_Table:
            while i.is_valid():
                yield i.Pid.v(), i.RemoteIpAddress, i.RemotePort, i.LocalIpAddress, i.LocalPort
                i = i.Next

    def calculate(self):
        self.profile = Profile()
        self.addr_space = utils.load_as(self.opts)

        ## Find the tcpip module:
        tcpip = None
        
        for module in lsmod(self.addr_space, self.profile):
            if "tcpip" in module.FullDllName.v():
                tcpip = module.BaseAddress.v()
                break

        if not tcpip:
            print "Unable to find tcpip module"
            return

        def connection_generator():
            for offsets in module_versions.values():
                for results in self.get_tcb_connections(tcpip, offsets['TCBTableOff'][0],
                                                        offsets['SizeOff'][0]):
                    yield results

        return connection_generator()


