""" These are basic modules which demonstrate how basic functionality
is now built using object2.py.  These functions are basically the same
as the built in ones.
"""
from vutils import *
from vmodules import *
from vtypes import *
from forensics.win32.tasks import pslist
import forensics.commands
from forensics.object2 import Profile, NewObject, Array, Curry

class lsof(forensics.commands.command):
    """List open files in all processes' handle table """
    def parser(self):
        forensics.commands.command.parser(self)
        self.op.add_option('-p','--pid',action='store', type='int', default=None,
                           help='Get info for this Pid')

    def render_text(self, outfd, result):
        for pid, filenames in result:
            outfd.write("*" * 50 + "\n")
            outfd.write("Pid:%s\n" % pid)
            for f in filenames:
                outfd.write("%s\n" % f)

    def calculate(self):
        profile = Profile()
        (addr_space, self.symtab, types) = load_and_identify_image(self.op, self.opts)

        ## Grab all the handle tables from processes
        def files_in_pid(p):
            for f in p.handles():
                filename = f.FileName.v()
                if filename:
                    yield filename

        def pid_generator():
            for p in pslist(addr_space, profile):
                pid = p.UniqueProcessId.v()

                ## We only print the handles from the pid or if not provided all pids:
                if self.opts.pid == None or (pid == self.opts.pid):
                    yield pid, files_in_pid(p)

        return pid_generator()

class lsdll(lsof):
    """List mapped dlls in all processes """
    def render_text(self, outfd, result):
        for p, peb, modules in result:
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
        (addr_space, self.symtab, types) = load_and_identify_image(self.op, self.opts)

        def list_modules(peb):
            if peb and peb.is_valid():
                ## list all the modules attached to this peb:
                for module in peb.Ldr.InLoadOrderModuleList.list_of_type(
                    "_LDR_MODULE", "InLoadOrderModuleList"):
                    yield module.BaseAddress, module.SizeOfImage, module.FullDllName

        def pid_generator():
            for p in pslist(addr_space, profile):
                pid = p.UniqueProcessId.v()
                if self.opts.pid == None or (pid == self.opts.pid):
                    ## Open the Process Environment Block (PEB) if we can:
                    peb = p.Peb

                    yield p, peb, list_modules(peb) 

        return pid_generator()
