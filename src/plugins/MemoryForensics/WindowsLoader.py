try:
    import VolatilityCommon
    import vutils, vmodules
except ImportError, e:
    active = False
    print "Unable to load Volatility"

import pyflag.FileSystem as FileSystem
import pyflag.FlagFramework as FlagFramework
import pyflag.pyflaglog as pyflaglog
import pyflag.IO as IO
import pyflag.Registry as Registry
import os, posix

class WindowsMemory(FileSystem.DBFS):
    """ Class to load a memory image into the VFS """
    name = "Windows Memory"

    def load(self, mount_point, iosource_name, scanners = None, directory=None):
        ## Ensure that mount point is normalised:
        self.iosource_name = iosource_name
        mount_point = os.path.normpath(mount_point)
        self.mount_point = mount_point
        
        FileSystem.DBFS.load(self, mount_point, iosource_name)
        
        # open the iosource
        self.iosrc = IO.open(self.case, iosource_name)

        ## Make a volatility object available FIXME allow options in
        ## here
        op = vutils.get_standard_parser("")

        ## Create an address space for the kernel
        self.kernel_VA_inode_id = self.VFSCreate(None, "I%s|A0"  % iosource_name,
                                                 "%s/mem" % self.mount_point)
        
        ## Build a fake command line
        self.filename = '%s/%s' % (self.case, iosource_name)
        self.args = ['-f', self.filename ]
        opts, args = op.parse_args(self.args)

        ## This identifies the image
        (self.addr_space, self.symtab, self.types) = vutils.load_and_identify_image(op, opts)

        for loader in Registry.FSLOADERS.classes:
            if loader.filesystem != "WindowsMemory": continue
            
            ## Instantiate them
            loader = loader()
            
            ## Ask them to load this memory image
            loader.load(self)

class AddressSpace(FileSystem.File):
    """ A VFS driver to make an address space available. We interpret
    the parameters as a pid. A pid of 0 is the kernel address space.
    """
    specifier = "A"

    def __init__(self, case, fd, inode):
        FileSystem.File.__init__(self, case, fd, inode)
        parts = inode.split('|')
        pid = int(parts[-1][1:])
        iosource_name = parts[0][1:]

        ## Make a volatility object available FIXME allow options in
        ## here
        op = vutils.get_standard_parser("")

        ## Build a fake command line
        self.filename = '%s/%s' % (case, iosource_name)
        self.args = ['-f', self.filename ]
        opts, args = op.parse_args(self.args)
        
        ## This identifies the image
        (self.addr_space, self.symtab, self.types) = vutils.load_and_identify_image(op, opts)
        self.size = 0xFFFFFFFFFFFFFFFF

        if pid > 0:
            # get list of windows processes
            all_tasks = vmodules.process_list(self.addr_space, self.types, self.symtab)        

            ## Find the task struct
            all_tasks = vmodules.process_find_pid(self.addr_space,
                                                  self.types, self.symtab,
                                                  all_tasks, pid)
            if len(all_tasks) == 0:
                print "Error process [%d] not found"%opts.pid
                return
            elif len(all_tasks)>1:
                print "Found multiple possible processes"

            task = all_tasks[0]
            ## The process address space
            process_address_space = vmodules.process_addr_space(self.addr_space,
                                                                self.types, task,
                                                                self.filename)

            self.addr_space = process_address_space

    def read(self, length=None):
        result = self.addr_space.read(self.readptr, length)
        if result == None:
            return "\x00" * length

        return result

import pyflag.tests

## Unit test
class WindowsMemoryFS(pyflag.tests.ScannerTest):
    """ Test Windows Memory Forensic Analysis """
    test_case = "Memory"
#    test_file = "xp-laptop-2005-06-25.img.e01"
#    test_file = "xp-laptop-2005-06-25.img"
#    test_file = "labdump17.E01"
    test_file = "megan.E01"
#    test_file = "megan.img"
    subsystem = "EWF"
#    subsystem = "Standard"
    fstype = "Windows Memory"
    mount_point = "proc"

    def test01memory(self):
        import forensics.win32.xpress as xpress
        print "Total time in xpress_decode %s" % xpress.TOTAL_TIME

        import forensics.win32.hiber_addrspace as hiber_addrspace
        print "Tital time spend in hiber read %s" % hiber_addrspace.TOTAL_READ_TIME
        print "Total cached blocks %s" % hiber_addrspace.TOTAL_CACHED_BLOCKS
