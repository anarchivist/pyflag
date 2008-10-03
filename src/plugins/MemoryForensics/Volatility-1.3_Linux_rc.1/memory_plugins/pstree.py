from vutils import *
from vmodules import *
from vtypes import *
from forensics.object2 import Profile, Object

def add_new_type(structure, field, offset, type):
    xpsp2types[structure][1][field] = [offset, type]

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

        data = self.calculate()
        self.render(data)

    def render(self, data):
        print "%-20s %-6s %-6s %-6s %-6s %-6s"%('Name','Pid','PPid','Thds','Hnds','Time')

        def draw_branch(pad, inherited_from):
            for task, task_info in data.items():
                if task_info['inherited_from'] == inherited_from:
                    print "%s 0x%08X:%-20s %-6d %-6d %-6d %-6d %-26s" % (
                        "." * pad,
                        task_info['eprocess'],
                        task_info['image_file_name'],
                        task_info['process_id'],
                        task_info['inherited_from'],
                        task_info['active_threads'],
                        task_info['handle_count'],
                        task_info['create_time'])

                    if self.opts.verbose:
                        try:
                            print "%s    cmd: %s" % (' '*pad, task_info['command_line'])
                            print "%s    path: %s" % (' '*pad, task_info['ImagePathName'])
                            print "%s    audit: %s" % (' '*pad, task_info['Audit ImageFileName']) 
                        except KeyError: pass
                        
                    draw_branch(pad + 1, task_info['process_id'])

        draw_branch(0, -1)
        
    def calculate(self):
        result = {}
        self.pids = {}
        (addr_space, self.symtab, types) = load_and_identify_image(self.op, self.opts)

        all_tasks = process_list(addr_space, types, self.symtab)

        for task in all_tasks:
            if not addr_space.is_valid_address(task):
                continue

            task_info = {}
            task_info['eprocess'] = task
            task_info['image_file_name'] = process_imagename(addr_space, types,
                                                             task) or 'UNKNOWN'

            task_info['process_id']      = process_pid(addr_space, types,
                                                       task) or -1

            task_info['active_threads']  = process_num_active_threads(addr_space,
                                                                      types, task) or -1

            task_info['inherited_from']  = process_inherited_from(addr_space,
                                                                  types,task) or -1

            task_info['handle_count']    = process_handle_count(addr_space, types,
                                                                task) or -1

            create_time     = process_create_time(addr_space, types,
                                                               task)
            if create_time is None:
                task_info['create_time'] = "UNKNOWN"
            else:
                task_info['create_time'] = format_time(create_time)

            self.find_command_line(addr_space,types, task, task_info)
            self.find_se_audit(addr_space, types, task, task_info)
            
            result[task] = task_info
            self.pids[task_info['process_id']] = task
            
        return result

    def find_se_audit(self, addr_space, types, task, task_info):
        ## This is an EPROCESS object
        proc = Object("_EPROCESS", task, addr_space, profile=Profile())
        
        info = Object("_SE_AUDIT_PROCESS_CREATION_INFO", proc.SeAuditProcessCreationInfo.v(),
                      addr_space, profile=Profile())

        ## This is the command line:
        task_info['Audit ImageFileName'] = read_unicode_string(
            addr_space, types,'',
            info.ImageFileName.v() ) or 'UNKNOWN'
        
    def find_command_line(self, addr_space,types, task, task_info):
        if self.opts.verbose:
            ## We need to print the command_line as well
            process_address_space = process_addr_space(addr_space, types,
                                                       task, self.opts.filename)
            if process_address_space is None:
                #print "Error obtaining address space for process [%d]" % (process_id)
                return

            peb = process_peb(addr_space, types, task)

            if not process_address_space.is_valid_address(peb):
                #print "Unable to read PEB for task."
                return

            process_parameters = read_obj(process_address_space, types,
                                          ['_PEB', 'ProcessParameters'], peb)
            if process_parameters:
                task_info['command_line'] = read_unicode_string(
                    process_address_space, types,
                    ['_RTL_USER_PROCESS_PARAMETERS', 'CommandLine'],
                    process_parameters)

                task_info['ImagePathName'] = read_unicode_string(
                    process_address_space, types,
                    ['_RTL_USER_PROCESS_PARAMETERS', 'ImagePathName'],
                    process_parameters)
