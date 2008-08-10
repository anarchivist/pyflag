""" This module implements a number of useful hexeditor commands to
use with memory images
"""
import plugins.Urwid.Hexeditor as Hexeditor
import pyflag.FlagFramework as FlagFramework
import VolatilityLinux
import struct
import pyflag.format as format
import pyflag.Registry as Registry
from plugins.FileFormats.BasicFormats import *

urwid = Hexeditor.urwid

class JumpToVA(Hexeditor.Action):
    """ Jumps to a Virtual Address """
    event = "j"
    mode = 'memory_va_jump'
    
    def __init__(self, ui):
        ## This will raise if we were not given a memory image
        self.m = ui.query['memory']
        self.case = ui.query['case']
        Hexeditor.Action.__init__(self,ui)

    def help(self):
        return 'j                        Jump to Virtual Address'

    def handle_key(self, ui ,key):
        print "Got key %s" % key
        if self.state == None:
            self.state = 'prompt'
            ## Read the current bytes off the memory image
            offset = ui.mark
            ui.fd.seek(offset)
            data = ui.fd.read(4)
            location = "0x%08X" % (struct.unpack("<I",data)[0])
            
            ui.status_bar = Hexeditor.PowerEdit("Goto Virtual Address: ", location)
            ui.status_bar.focus = True
            
        elif self.state == 'prompt':
            if key=='esc':
                ui.mode = None
                self.state = None
                ui.status_bar = urwid.Text('')
            elif key=='enter':
                ui.mode = None
                self.state = None
                offset = ui.status_bar.get_edit_text()
                ui.status_bar = urwid.Text('')
                try:
                    offset = FlagFramework.calculate_offset_suffix(offset)
                except Exception,e:
                    ui.message = "Cant parse %s as offset" % offset
                    return True

                ## Now we need to work out what the VA offset is:
                v = VolatilityLinux.get_vol_object(self.case, self.m)
                phy_offset = v.addr_space.vtop(offset)
                
                ui.set_mark(phy_offset)
            else:
            ## Pass key strokes to the text box:
                ui.status_bar.keypress( (ui.width, ), key)
                
        return True

class ListHead(SimpleStruct):
    fields = [
        [ 'next', ULONG ],
        [ 'previous', ULONG ]
        ]

## This is a map from the Volatility types to PyFlag Type classes
maps = {
    'int': "LONG",
    'unsigned long': "ULONG",
    'unsigned short': "USHORT",
    'unsigned int': "ULONG",
    'long long': 'LONGLONG',
    'unsigned long long': 'LONGLONG',
    'timespec': 'TIMESTAMP',
    'list_head': 'ListHead',
    'qstr': 'QSTR',
    'pointer': 'ULONG',
    'inode': 'InodeStruct',
    'file': 'FileStruct',
    'dentry': 'DentryStruct',
    }

inline_pointers = {
    'unsigned char': 'TERMINATED_STRING',
    }

class InodeStruct(format.DataType):
    """ An Inode Type struct which depends on the version of the kernel """
    urwid_capable = True
    volatility_object = 'inode'

    def urwid_output(self, ui, offset):
        ## Get the profile for this case:
        ctx = VolatilityLinux.get_vol_object(ui.query['case'], ui.query['memory'])

        buf = format.Buffer(fd = ui.fd)[offset:]
        result = self.render_profile(buf, ctx, self.volatility_object, ui)

        return result

    def render_list_head(self, ctx, obj, offset, ui):
        """ Render next/previous buttons for list heads.
        """
        next_va = obj['next'].get_value() - offset
        
        def next_cb(widget):
            ## This is the target in Virtual Address
            target = next_va

            ## Find the physical Address:
            ui.set_mark(ctx.addr_space.vtop(target))
            ui.reset()

        previous_va = obj['previous'].get_value() - offset
        def previous_cb(widget):
            ## This is the target in Virtual Address
            target = previous_va

            ## Find the physical Address:
            ui.set_mark(ctx.addr_space.vtop(target))
            ui.reset()

        if next_va == offset:
            return urwid.Text("List Empty")
            
        return urwid.Columns([
            urwid.AttrWrap(urwid.Button("Next (VA 0x%08X)" % next_va,
                                        on_press=next_cb),'buttn','buttnf'),
            urwid.AttrWrap(urwid.Button("Previous (VA 0x%08X)" % previous_va,
                                        on_press=next_cb),'buttn','buttnf'),
            ],2)

    def render_pointer(self, ctx, target_obj, offset, ui):
        print "Will render pointer to %s" % target_obj
        ## If this is a pointer to a volatility object we can link
        ## to it
        def next_cb(widget):
            ## Find the physical Address:
            ui.set_mark(ctx.addr_space.vtop(offset))
            ui.reset()

        if target_obj in maps:
            return urwid.AttrWrap(urwid.Button("Pointer to %s (0x%08X)" % (target_obj, offset),
                                               on_press=next_cb),'buttn','buttnf')
        elif target_obj in inline_pointers:
            ## Find out the Physical Address which is the target of this VA
            phy_offset = ctx.addr_space.vtop(offset)
            
            obj = Registry.FILEFORMATS.formats[inline_pointers[\
                target_obj]](format.Buffer(fd = ui.fd, offset = phy_offset))

            return obj.urwid_output(ui, phy_offset)

        return urwid.Text("Pointer to %s (0x%08X)" % (target_obj, offset))
    
    def render_profile(self, buf, ctx, obj, ui):
        """ Wrapper around the volatility data types to make them work
        with urwid"""
        obj = ctx.profile[obj]
        members = obj[1]
        def sort(x,y):
            if members[x][0]>members[y][0]: return 1
            else: return -1

        fields = members.keys()
        fields.sort(cmp=sort)
        offsets = []
        result = []
        max_field_width = 0
        for f in fields:
            if len(f)>max_field_width: max_field_width=len(f)
            
            output = urwid.Text("")
            try:
                offset = members[f][0]
                obj_name = maps[members[f][1][0]]
                obj = Registry.FILEFORMATS.formats[obj_name](buf[offset:])
                output = obj.urwid_output(ui, offset + buf.offset)
                offsets.append(obj.buffer.offset - ui.mark)
                
                if members[f][1][0]=='list_head':
                    output = self.render_list_head(ctx, obj,offset, ui)
                    
                elif members[f][1][0]=='pointer':
                    output = self.render_pointer(ctx, members[f][1][1][0], obj.get_value(), ui)
                    
            except KeyError:
                offsets.append(offset)

            ## Can we handle it directly?
            result.append(output)

        tmp = []
        for i in range(len(result)):
            if type(result[i])==list:
                result[i] = urwid.Pile(result[i])
                
            tmp.append(
                urwid.Columns([
                ('fixed', max_field_width + 6,
                 urwid.Text(('element', "%04X:%s" % (offsets[i],fields[i])))),
                result[i]
                ]))
            
        return tmp
    
class FileStruct(InodeStruct):
    """ A File object struct """
    volatility_object = 'file'

class DentryStruct(InodeStruct):
    """ A Dentry Struct """
    volatility_object = 'dentry'

class QSTR(InodeStruct):
    """ A Qstring """
    volatility_object = 'qstr'

class TaskStruct(InodeStruct):
    """ A Task """
    volatility_object = 'task_struct'
