""" This module implements the feature in the hex editor which prints
out the structs in the current frame.

"""
import Hexeditor
import pyflag.Registry as Registry
import pyflag.format as format
urwid = Hexeditor.urwid
import pyflag.FlagFramework as FlagFramework

## The default DataType action is to print itself as a text UI:
def urwid_output(self, ui, offset):
    return urwid.Text(('body',self.__str__()))

format.DataType.urwid_output = urwid_output

class SelectDataStruct(Hexeditor.Action):
    """ Select a Data format for examining within the Hexeditor """
    event = 'f'
    mode = 'select format'
    frame = None

    def __init__(self, ui):
        ui.selected = None
        Hexeditor.Action.__init__(self, ui)

    def handle_key(self, ui, key):
        if self.state == None:
            self.state = 'showing'
            if  not self.frame:
                self.frame = self.make_frame(ui)
                
            ui.top = self.frame
        else:
            ui.top.keypress( (ui.width, ui.height ), key)

        return True

    def draw(self, ui):
        pass
    
    def make_frame(self, ui):
        result = []
        formats = Registry.FILEFORMATS.formats.keys()
        formats.sort()
        def on_press(widget, data):
            self.ui.selected = data
            self.mode = None
            self.ui.mode = None
            self.state = None
        
        for f in formats:
            try:
                Registry.FILEFORMATS.formats[f].urwid_capable
            except: continue
            string = "%s - %s\n" %  (f,Registry.FILEFORMATS.formats[f].__doc__)
            result.append(
                urwid.AttrWrap(urwid.Button( string ,on_press, f),'buttn','buttnf')
            )

        self.listbox = urwid.ListBox(
            urwid.SimpleListWalker(
            result)
            )

        return urwid.Frame(
            urwid.AttrWrap(self.listbox, 'body')
            )    

class ParseFormat(Hexeditor.Action):
    """ Parse the data format and display the parsed output """
    event = "e"
    mode = "parse format"

    def handle_key(self, ui, key):
        if self.state == None:
            self.state = "showing"
            self.show_frame(ui)
        else:
            if key == 'q':
                self.state = None
                ui.mode = None
                ui.top = self.old_frame
            elif key==" ":
                ui.top.keypress( (ui.width, ui.height ), "page down")
            else:
                ui.top.keypress((ui.width, ui.height), key)

        return True

    def draw(self, ui):
        pass

    def show_frame(self, ui):
        try:
            ## Get the format object:
            f = Registry.FILEFORMATS.formats[ui.selected]
        except KeyError,e:
            print "Error: %s:" % e
            self.handle_key(ui,"q")
            return
        
        ## Make a buffer
        buf = format.Buffer(fd = ui.fd)
        buf = buf[ui.mark:]

        try:
            result = f(buf).urwid_output(ui, ui.mark)
        except Exception,e:
            print "Error occured %s" % e
            print FlagFramework.get_bt_string(e)
            result = [urwid.Text(('body',"Error: %s" % e)),]

        self.listbox = urwid.ListBox(
            [urwid.Text(('header',"Data type dump (%s)- press q to continue" % ui.selected)),
             urwid.Pile(result)
             ]
            )

        self.old_frame = ui.top
        ui.top = urwid.Frame(
            self.listbox
            )

    def process_mouse_event(self, width, height, event, button, col, row):
        self.ui.top.mouse_event((width, height), event, button, col, row, True)
    
