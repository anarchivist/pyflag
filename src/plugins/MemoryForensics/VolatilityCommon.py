import os,sys
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework

## Find and insert the volatility modules
volatility_path = None
for d in os.listdir(os.path.dirname(__file__)):
    if d.startswith("Volatility-1.3"):
        ## Check that volatility is actually in there
        path = os.path.join(os.path.dirname(__file__),d)
        if os.access(os.path.join(path,"vtypes.py"),os.F_OK):
            volatility_path = path
            break

## We need to make sure that we get in before an older version
if volatility_path and volatility_path not in sys.path:
    sys.path.insert(0,volatility_path)

import forensics.addrspace

## This is a big hack because Volatility is difficult to work with -
## we want to pass Volatility an already made address space but there
## is no way to do this. Volatility calls the FileAddressSpace in
## multiple places and actually tries to open the raw file several
## times. We would essentially need to recode all the volatility
## functions to accept a ready address space.

## But after all, this is python so we can do lots of magic. We
## basically dynamically change the FileAddressSpace definition in
## volatility itself (which normally accepts a filename) to accept an
## IOSource name, then we effectively call it with the name as an
## image name. When volatility tries to open the said filename, it
## will be transparently opening a PyFlag iosource of our choosing.
try:
    forensics.addrspace.FileAddressSpace.case
except AttributeError:
    ## Only do this if its not done already
    class IOSourceAddressSpace(forensics.addrspace.FileAddressSpace):
        case = None
        iosource = None
        def __init__(self, name, mode='rb', fast=False):
            self.case, self.iosource = name.split("/",1)
            fd = IO.open(self.case, self.iosource)
            self.fhandle = fd
            self.fsize = fd.size
            self.fast_fhandle = fd
            self.fname = name
            self.name = name

    ## Patch it in:
    forensics.addrspace.FileAddressSpace = IOSourceAddressSpace

    ## We also remove these functions because they try to open the
    ## file directly (besides we support crash dumps and hiberfiles
    ## seperately )
    import vutils
    
    def hook(x):
        return False

    vutils.is_crash_dump = hook
    vutils.is_hiberfil = hook


## Make sure we initialise Volatility plugins
import forensics.registry as MemoryRegistry

MemoryRegistry.Init()

import pyflag.tests

## Unit test
class WindowsMemoryFS(pyflag.tests.ScannerTest):
    """ Test Windows Memory Forensic Analysis """
    test_case = "Memory"
    test_file = "xp-laptop-2005-06-25.img.e01"
    subsystem = "EWF"
    fstype = "Windows Memory"
    mount_point = "proc"

## These are common column types
from pyflag.ColumnTypes import BigIntegerType

class MemoryOffset(BigIntegerType):
    inode_id_column = "Inode"
    """ A column type to link to the offset of an inode """
    def plain_display_hook(self, value, row, result):
        offset = int(value)
        inode_id = row[self.inode_id_column]

        target = FlagFramework.query_type(family="Disk Forensics",
                                          report="ViewFile",
                                          offset=value,
                                          inode_id=inode_id,
                                          case=self.case,
                                          mode="HexDump")
        
        result.link("0x%08X" % offset, target=target, pane='new')
    
    display_hooks = [ plain_display_hook ]

