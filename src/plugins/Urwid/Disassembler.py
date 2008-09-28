""" A Module to add disassembly to the hex editor """

import Hexeditor
import pydistorm
import urwid
import bisect

class DisasseblerAction(Hexeditor.Action):
    """ Disasseble the current offset """
    event = 'd'
    mode = "disassembly"

    def help(self):
        return 'd                        Disassemble from current point'

    def disassemble(self, ui, start):
        self.start = start
        self.offsets = []
        self.mnemonics = []
        self.opcodes = []
        self.offset_ints = []

        ui.fd.seek(start)
        data = ui.fd.read(200)
        self.offset_length = 0
        self.opcodes_length = 0
        self.mnemonics_length = 0
        
        for row in pydistorm.Decode(start, data):
            offset = "0x08%X" % row[0]
            self.offset_length = max(self.offset_length, len(offset))
            self.offsets.append(offset)
            self.offset_ints.append(row[0])
            self.mnemonics.append(row[2])
            self.mnemonics_length = max(self.mnemonics_length, len(row[2]))
            self.opcodes.append(row[3])
            self.opcodes_length = max(self.opcodes_length, len(row[3]))

    def handle_key(self, ui, key):
        if self.state == None:
            self.state = "disassembly"
            self.disassemble(ui, ui.mark)
        else:
            if key == 'esc' or key =='q':
                ui.mode = None
                self.state = None
            elif key == "down":
                i = self.offset_ints.index(ui.mark)
                ui.mark = self.offset_ints[i+1]
            elif key == 'up':
                i = self.offset_ints.index(ui.mark)
                ui.mark = self.offset_ints[i-1]
            elif key == 'page down':
                ui.mark = self.offset_ints[ui.height+1]
            elif key == 'window resize' or key =='ctrl l':
                ui.width, ui.height = ui.ui.get_cols_rows()
                
    def process_mouse_event(self,ui, width, height, event, button, col, row):
        if event == 'mouse press' and button==1:
            ui.mark = self.offset_ints[row]

    def get_current_row(self, ui):
        offset = bisect.bisect(self.offset_ints, ui.mark)
        if offset > ui.height:
            self.disassemble(ui, self.offset_ints[offset - 5])
            return self.get_current_row(ui)

        return len("\n".join(self.offsets[:offset]))

    def draw(self, ui):
        result = [ ('header', "Disassembly (Press escape to go back)")]
        current_row = self.get_current_row(ui)

        offsets = urwid.ListBox( [
            Hexeditor.OverlayEdit("\n".join(self.offsets),
                                  edit_pos = current_row)
            ])

        hex_area = urwid.ListBox( [
            Hexeditor.OverlayEdit("\n".join(self.opcodes))
            ] )
        
        chars   = urwid.ListBox( [
            Hexeditor.OverlayEdit("\n".join(self.mnemonics))
            ])

        columns = urwid.Columns( [ ('fixed', self.offset_length+1, offsets),
                                   ('fixed', self.opcodes_length+1, hex_area),
                                   ('fixed', self.mnemonics_length+1, chars),
                                   ], 0, min_width=11, focus_column=0)
        ui.top = urwid.AttrWrap(columns, 'body')
        
