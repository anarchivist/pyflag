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

LEVEL_MASK = 0xfffffff8

class lsof(forensics.commands.command):
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

        result = {}

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
