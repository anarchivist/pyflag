""" This module discovers the SSDT based on moyix:

http://moyix.blogspot.com/2008/08/auditing-system-call-table.html
"""

import VolatilityCommon
import re
from VolatilityCommon import MemoryOffset
import pyflag.Registry as Registry
import pyflag.FlagFramework as FlagFramework
from pyflag.ColumnTypes import InodeIDType, IntegerType, StringType, TimestampType, BigIntegerType
import StringIO, sys, string
import pyflag.DB as DB
import pyflag.Time as Time
import forensics.registry as MemoryRegistry
import pyflag.Reports as Reports

MemoryRegistry.Init()

class WindowsSSDTTable(FlagFramework.CaseTable):
    """ The windows SSDT Table """
    name = 'windows_ssdt'
    columns = [ [ InodeIDType, {} ],
                [ MemoryOffset, dict(name = 'Base Address', column='base') ],
                [ IntegerType, dict(name = 'Index', column='index') ],
                [ StringType, dict(name = 'Function', column='function')],
                [ MemoryOffset, dict(name = 'Handler', column='handler', prebuffer='d')],
                [ StringType, dict(name = 'Module', column='module')]
                ]

class SSTD(Registry.FileSystemLoader):
    """ Finds the SSDT in a windows memory image """
    filesystem = "WindowsMemory"
    def load(self, loader):
        import vmodules

        ## This is a hack to allow us to capture the output of
        ## volatility printing. This could interfere with other
        ## threads so be careful!!!

        oldstdout = sys.stdout
        s = StringIO.StringIO()
        sys.stdout = s
        plugin = MemoryRegistry.PLUGIN_COMMANDS.commands['ssdt'](loader.args)
        plugin.execute()
        sys.stdout = oldstdout
        dbh = DB.DBO(loader.case)
        ssdt_base = 0
        for line in s.getvalue().splitlines():
            m = re.match("SSDT\[\d+\] at ([^ ]+)", line)
            if m:
                ssdt_base = int(m.group(1),16)
                continue

            m = re.match(" +Entry 0x([^:]+): +0x([^ ]+) +\(([^)]+)\) owned by (.+)", line)
            if m:
                row = dict(inode_id = loader.kernel_VA_inode_id,
                           base = ssdt_base,
                           index = int(m.group(1),16),
                           function = m.group(3),
                           handler = int(m.group(2),16),
                           module = m.group(4))

                dbh.insert("windows_ssdt", _fast = True, **row)

class SSDTPrecan(Reports.PreCannedCaseTableReoports):
    """ Display the System Service Descriptor Table (SSDT). You can then click on the function handlers to see a disassembly of each. Note also which module the handler routine resides in for an indication if something is hooking this entry. """
    hidden = True
    family = "Memory Forensics"
    description = "View SSDT"
    name = "/Memory Forensics/Windows Analysis/View SSDT"
    default_table = "WindowsSSDTTable"
    columns = [ "Inode", "Index", "Base Address",
                "Function", "Handler",
                "Module" ]
