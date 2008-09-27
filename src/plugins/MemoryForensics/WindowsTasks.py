""" This module handles loading windows tasks into the DB """

import pyflag.Registry as Registry
import pyflag.FlagFramework as FlagFramework
from pyflag.ColumnTypes import InodeIDType, IntegerType, StringType, TimestampType, BigIntegerType
import StringIO, sys, string
import pyflag.DB as DB
import pyflag.Time as Time

active = False

class WindowsTaskTable(FlagFramework.CaseTable):
    """ Windows Tasks table - lists all windows tasks """
    name = 'windows_tasks'
    columns = [ [ InodeIDType, {} ],
                [ IntegerType, dict(name = "Process ID", column = 'pid') ],
                [ StringType, dict(name = "Task Name", column='name')],
                [ StringType, dict(name = 'Command Line', column='cmdline')],
                
                ## This is the offset to the relevant task_struct
                [ IntegerType, dict(name = "Parent Process", column = 'ppid') ],
                [ IntegerType, dict(name = 'User ID', column = 'uid') ],
                [ TimestampType, dict(name = 'Started', column='time')],
                ]

class WindowsModulesTable(FlagFramework.CaseTable):
    """ Lists all the modules loaded within a process """
    name = 'windows_modules'
    columns = [ [ InodeIDType, {} ],
                [ StringType, dict(name = 'Module Path', column='path') ],
                [ BigIntegerType, dict(name = "Base Offset", column = "base") ],
                [ InodeIDType, dict(name = 'Size', column='size')],
                ]

class FindTasks(Registry.FileSystemLoader):
    """ This loader searches for all tasks in the image and populates
    their table
    """
    filesystem = "WindowsMemory"
    def load(self, loader):
        import vmodules
        dbh = DB.DBO(loader.case)

        all_tasks = vmodules.process_list(loader.addr_space, loader.types, loader.symtab)
        for task in all_tasks:
            ## Not a valid task skip it
            if not loader.addr_space.is_valid_address(task):
                continue

            row = {}

            ## The task filename
            row['name'] = vmodules.process_imagename(\
                loader.addr_space, loader.types, task)

            ## The pid
            row['pid'] = vmodules.process_pid(loader.addr_space,
                                              loader.types, task)

            ## The ppid
            row['ppid'] = vmodules.process_inherited_from(loader.addr_space,
                                                          loader.types, task)
            
            ## Create time
            row['time'] = vmodules.process_create_time(loader.addr_space,
                                                       loader.types, task)

            ## The process address space
            process_address_space = vmodules.process_addr_space(loader.addr_space,
                                                                loader.types, task,
                                                                loader.filename)

            modules = []
            if process_address_space:
                ## The process environment block
                peb = vmodules.process_peb(loader.addr_space, loader.types, task)
                if process_address_space.is_valid_address(peb):
                    row['cmdline'] = vmodules.process_command_line(\
                      process_address_space,
                      loader.types, peb) or "Unknown"
                
                    modules = vmodules.process_ldrs(process_address_space, loader.types, peb)

            ## Insert one row for the task
            new_inode = "%s/%s/%s" % (loader.mount_point, row['pid'], row['name'])
            row['inode_id'] = loader.VFSCreate(None, "A%s" % row['pid'], new_inode)
            dbh.insert('windows_tasks', _fast = True, **row)

            for module in modules:
                if not process_address_space.is_valid_address(module):
                    continue

                row2 = {'inode_id': row['inode_id'] }
                row2['path'] = vmodules.module_path(process_address_space,
                                                    loader.types, module) or "Unknown"
                row2['base'] = vmodules.module_base(process_address_space,
                                                    loader.types, module) or "Unknown"
                
                row2['size'] = vmodules.module_size(process_address_space,
                                                    loader.types, module) or -1

                dbh.insert("windows_modules", _fast=True, **row2)
