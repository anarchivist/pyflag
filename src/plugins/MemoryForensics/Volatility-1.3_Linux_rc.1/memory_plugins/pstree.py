from vutils import *
from vmodules import *
from vtypes import *
from forensics.object2 import Profile

def add_new_type(structure, field, offset, type):
    xpsp2types[structure][1][field] = [offset, [type]]

class pstree(forensics.commands.command):
    def parser(self):
        forensics.commands.command.parser(self)
        self.op.add_option('-v', '--verbose',action='store_true',
                           help='print more information')

    def execute(self):
        add_new_type('_RTL_USER_PROCESS_PARAMETERS', 'ImagePathName', 0x38, '_UNICODE_STRING')
        add_new_type('_EPROCESS','SeAuditProcessCreationInfo',0x1f4,
                     '_SE_AUDIT_PROCESS_CREATION_INFO')

        xpsp2types.update( {
            '_SE_AUDIT_PROCESS_CREATION_INFO' : [ 0x4, {
            'ImageFileName' : [ 0x0, ['pointer', ['_OBJECT_NAME_INFORMATION']]],
            } ],
                                              
            '_OBJECT_NAME_INFORMATION' : [ 0x8, {
            'Name' : [ 0x0, ['_UNICODE_STRING']],
            } ],
            } )

        ## Call our base class
        forensics.commands.command.execute(self)

    def render_text(self, outfd, data):
        outfd.write("%-20s %-6s %-6s %-6s %-6s %-6s\n" %(
            'Name','Pid','PPid','Thds','Hnds','Time'))

        def draw_branch(pad, inherited_from):
            for task, task_info in data.items():
                if task_info['inherited_from'] == inherited_from:
                    outfd.write("%s 0x%08X:%-20s %-6d %-6d %-6d %-6d %-26s\n" % (
                        "." * pad,
                        task_info['eprocess'].offset,
                        task_info['image_file_name'],
                        task_info['process_id'],
                        task_info['inherited_from'],
                        task_info['active_threads'],
                        task_info['handle_count'],
                        task_info['create_time']))

                    if self.opts.verbose:
                        try:
                            outfd.write("%s    cmd: %s\n" % (
                                ' '*pad, task_info['command_line']))
                            outfd.write("%s    path: %s\n" % (
                                ' '*pad, task_info['ImagePathName']))
                            outfd.write("%s    audit: %s\n" % (
                                ' '*pad, task_info['Audit ImageFileName']) )
                        except KeyError: pass
                        
                    draw_branch(pad + 1, task_info['process_id'])

        draw_branch(0, -1)
        
    def calculate(self):
        result = {}
        self.pids = {}
        
        self.profile = Profile()

        (addr_space, self.symtab, types) = load_and_identify_image(self.op, self.opts)

        for task in pslist(addr_space, self.profile):
            task_info = {}
            task_info['eprocess'] = task
            task_info['image_file_name'] = task.ImageFileName or 'UNKNOWN'
            task_info['process_id']      = task.UniqueProcessId or -1
            task_info['active_threads']  = task.ActiveThreads or -1
            task_info['inherited_from']  = task.InheritedFromUniqueProcessId.v() or -1
            task_info['handle_count']    = task.ObjectTable.HandleCount or -1
            task_info['create_time']     = task.CreateTime

            ## Get the Process Environment Block - Note that _EPROCESS
            ## will automatically switch to process address space by
            ## itself.
            if self.opts.verbose:
                peb = task.Peb
                if peb:
                    task_info['command_line'] = peb.ProcessParameters.CommandLine
                    task_info['ImagePathName'] = peb.ProcessParameters.ImagePathName

                task_info['Audit ImageFileName'] = task.SeAuditProcessCreationInfo.ImageFileName.Name or 'UNKNOWN'
             
            result[task] = task_info
            self.pids[task_info['process_id']] = task
            
        return result
