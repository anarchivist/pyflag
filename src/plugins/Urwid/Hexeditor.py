# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************

""" This is an implementation of the hexeditor using urwid """
import cStringIO, re
import pyflag.Indexing as Indexing
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.FileSystem as FileSystem

PALETTE = [
    ('editfc','white', 'dark blue', 'bold'),
    ('editbx','light gray', 'light blue'),
    ('editcp','black','light gray', 'standout'),
    ('header', 'black', 'dark cyan', 'standout'),
    ('body','black','light gray', 'standout'),
    ('default', 'default', 'default', 'bold'),
    ('self', 'default', 'default'),
    ('help', 'yellow', 'default'),
    ('hit', 'yellow', 'black'),
    ('slack','light cyan', 'dark red',),
    ('overread','black', 'dark blue',),
    ('buttn','black','dark cyan'),
    ('buttnf','white','dark blue','bold'),
    ]

class Action:
    """ An action handler base class """
    ## This is the order we will be called when highlighting
    order = 10
    state = None
    ## This is the name of the mode the top level GUI will be in when
    ## we fire. This needs to be unique between all actions
    mode = ''
    event = ''
    def __init__(self, ui):
        """ The constructor - The most important thing to do here is
        to call ui.set_event() to ensure we get fired. """
        ui.set_event(self.event, self.mode)
    
    def handle_key(self, ui, key):
        """ This is called to process keys as the come in.  Note that
        keys will only arrive here if the ui's mode is set to
        self.mode.
        """
        return False

    def draw(self, ui):
        """ This is called when we wish to draw the screen. 
        By default we draw the hexeditor screen.
        """
        try:
            ui.hex.set_edit_pos((ui.mark - ui.file_offset)*3)
            ui.chars.set_edit_pos(ui.mark - ui.file_offset)
            ui.columns.set_focus_column(ui.focus_column)
        except AssertionError:
            print "Error in widgets mark is at %s, file offset %s %s" % (ui.mark,
                                                                         ui.file_offset,
                                                                         ui.size)
            raise

        ui.refresh_screen()                    
        
    def help(self):
        """ Return a helpful message about this module - should
        probably list all the key bindings
        """
        return ''

    def highlight(self, ui, offset, length, refreshed):
        """ A method called by the UI which allows us to place
        highlighting information. We get called when the ui wants to
        render the screen.

        We need to update the highlight overlay here. The file offset
        is shown from offset and is of length length. refreshed
        indicates if the underlying screen cache was changed - (If our
        underlying highlighting information is unlikely to have
        changed we can short cut here).
        """
        
class SearchAction(Action):
    """ A state machine which takes care of the search functionality """
    previous_search = ''

    def handle_key(self, ui, key):
        """ This gets called when we become active """
        if self.state == None and key != '/':
            return False
        
        if self.state ==None:
            self.state = 'prompt'
            ui.status_bar = PowerEdit("Search: ", self.previous_search,
                                      wrap='any', multiline=False)
            ui.status_bar.focus = True
        elif self.state == 'prompt':
            if key=='enter':
                self.state = 'waiting'
                self.previous_search = ui.status_bar.get_edit_text()
                Indexing.schedule_index(ui.case, ui.inode_id, self.previous_search,
                                        "literal", unique=False)
                ui.status_bar = urwid.Text('')
                ui.message = 'Waiting for Indexer'
                ## This effectively schedules us again so we can check
                ## if the word is already indexed:
                self.handle_key(ui, '')
            else:
            ## Pass key strokes to the text box:
                ui.status_bar.keypress( (ui.width, ), key)
            
        elif self.state == 'waiting':
            self.last_rendered_offset = -1
            ## Check if the inode is up to date:
            if Indexing.inode_upto_date(ui.case, ui.inode_id,
                                        unique=False):
                print "Going to next hit"
                old_mark = ui.mark
                for row in Indexing.list_hits(ui.case, ui.inode_id, self.previous_search,
                                              ui.mark + 1):
                    ui.mark = row['offset']
                    break

                if old_mark==ui.mark:
                    ui.message = "Not Found"
                else:
                    ui.message =''
                self.state = None
        else:
            print "Unknown search mode %s" % self.state

        return True

    def help(self):
        return  '/                        Search this file (uses the Indexer)'

    last_rendered_offset = -1

    def highlight(self, ui, offset, length, refreshed):
        ## Check if we are in the right state
        if not self.previous_search: return
        
        if self.state != "waiting" and self.last_rendered_offset != offset:
            ## Clear any previous hilights:
            ui.clear_overlay()
            for row in Indexing.list_hits(ui.case, ui.inode_id, self.previous_search,
                                          offset, offset+length):
                ui.overlay[row['offset'] - offset -1:
                           row['offset'] - offset + row['length'] -1 ] = [ 8,]*row['length']
                
            self.last_rendered_offset = offset

class Goto(Action):
    """ This allows us to jump to a fixed offset """
    previous_location = ''
    mode = 'goto'
    event = 'g'

    def help(self):
        return  'g                        Goto an offset (can be specified using sectors, k, m. 0x prefix means hex)'
    
    def handle_key(self, ui ,key):
        if self.state == None:
            self.state = 'prompt'
            ui.status_bar = PowerEdit("Goto: ", self.previous_location)
            ui.status_bar.focus = True
            
        elif self.state == 'prompt':
            if key=='enter':
                ui.mode = None
                self.state = None
                offset = ui.status_bar.get_edit_text()
                ui.status_bar = urwid.Text('')
                try:
                    offset = FlagFramework.calculate_offset_suffix(offset)
                except Exception,e:
                    ui.message = "Cant parse %s as offset" % offset
                    return True
                ui.mark = offset
            else:
            ## Pass key strokes to the text box:
                ui.status_bar.keypress( (ui.width, ), key)
                
        return True
    
class Navigate(Action):
    """ This allows us to navigate around the hex editor GUI """
    def __init__(self):
        self.events = {}

    def handle_key(self, ui, k):
        ## Check to see if a different mode should be fired:
        for event in self.events.keys():
            if k==event:
                ui.mode = self.events[k]
                ui.actions[ui.mode].handle_key(ui, k)
                return True
            
        if k=='page down':
            ui.mark += ui.pagesize
        elif k=='page up':
            ui.mark = ui.mark - ui.pagesize
        elif k=='right':
            ui.mark += 1
        elif k=='left':
            ui.mark -= 1
        elif k=='up':
            ui.mark -= ui.row_size
        elif k=='down':
            ui.mark += ui.row_size
        elif k == 'window resize' or k=='ctrl l':
            ui.width, ui.height = ui.ui.get_cols_rows()
        elif k=='tab':
            if ui.focus_column == 1:
                ui.focus_column = 2
            else:
                ui.focus_column = 1
                
        elif k=='<' or k=='home' or k=='meta <':
            ui.mark = 0
        elif k=='>' or k=='end' or k=='meta >':
            ui.mark = ui.size
        else:
            return False

        return True

    def help(self):
        return [('header','\n\nNavigation:\n'), ('body',
        'page down/up             Skip full pages\n'
        'right, left, up, down    Move around\n'
        'tab                      Switch between hex and char view\n'
        '<, >                     Jump to start or end of file\n'
                                             )]

    def draw(self,ui):
        ui.update_status_bar()
        Action.draw(self, ui)

    def highlight(self, ui, offset, length, refreshed):
        """ This callback is used to handle highlighting of constant
        strings which have been passed in the constructor.
        """
        if ui.highlights:
            for file_offset, hilight_length, type in ui.highlights:
                if file_offset > offset and file_offset < offset + length:
                    ui.overlay[file_offset - offset: \
                               file_offset - offset + hilight_length] = \
                               [type,] * hilight_length

class Help(Action):
    mode = 'help'
    event = 'h'

    def help(self):
        return 'h,?                      print this help'
    
    def handle_key(self, ui, key):
        if self.state == None:
            self.state = 'showing'
        else:
            self.state = None
            ui.mode = None

    def draw(self, ui):
        result = [('header','Help (press any key to go back)\n')]
        for action in ui.actions.values():
            tmp = action.help()

            if type(tmp)==type(""):
                result.append(('body',"%s\n" %  tmp))
            else:
                result.extend(tmp)

        ui.top = urwid.Frame(
            urwid.ListBox([urwid.Text(result)])
            )

class IncrementalSearch(Action):
    mode = "inc-search"
    event = "ctrl s"
    
    previous_search = ''
    preprevious_search = ''

    def help(self):
        return  "ctrl-s                   Incremental Regular Expression search (press ctrl-s again to go to the next hit)"

    def highlight(self, ui, offset, length, refreshed):
        if not self.state: return

        try:
            expr = re.compile(self.previous_search)
        except: return

        for m in expr.finditer(ui.screen_cache.getvalue()):
            ui.overlay[m.start():m.end()] = [8,] * (m.end() - m.start())

    def find_next_hit(self, ui, repeat=False):
        """ Finds the next hit and updates the ui """
        if not self.previous_search: return
        
        try:
            expr = re.compile(self.previous_search)
        except:
            ui.status_bar.set_edit_text("%s      (regex invalid)" % self.previous_search)
            return
        
        data = ''
        if repeat:
            offset = ui.mark + 1
            ui.fd.seek(ui.mark + 1)
        else:
            offset = ui.mark
            ui.fd.seek(ui.mark)
        while 1:
            ## Search for hit in the current file offset
            data += ui.fd.read(64 * 1024)
            if not data:
                ui.status_bar.set_edit_text("Not found")
                return

            m = expr.search(data)
            if m:
                ## Found it
                ui.mark = offset + m.start()
                ui.status_bar.set_edit_text("%s" % self.previous_search)
                return

            ## Provide some overlap margin
            new_data = data[:-100]
            offset += len(new_data)
            data = new_data
    
    def handle_key(self, ui, key):
        if self.state == None:
            self.state = 'operating'
            ui.message = "i-search: "
            self.preprevious_search = self.previous_search
            self.previous_search = ''
            ui.status_bar = PowerEdit("i-search: ", self.previous_search)
        else:
            if ui.status_bar.valid_char(key):
                self.previous_search += key
                ## Search ahead for the next match
                self.find_next_hit(ui)
            elif key=='ctrl s':
                ## Pressing ctrl s twice means to continue with
                ## previous search
                if self.previous_search == '':
                    self.previous_search = self.preprevious_search
                
                self.find_next_hit(ui, repeat=True)
            elif key=='backspace':
                self.previous_search = self.previous_search[:-1]
                self.find_next_hit(ui)
            elif key=='tab':
                ## We accept tab but do not break from search mode
                ui.actions[None].handle_key(ui, key)
            else:
                ## Any other key exits from this mode
                self.state = None
                ui.mode = None
                ui.status_bar = urwid.Text('')
                ui.message = ''
                ui.actions[None].handle_key(ui, key)

class SlackAction(Action):
    order = 1

    ## This action is only here for its highlighting
    def __init__(self, ui):
        pass

    def highlight(self, ui, offset, length, refreshed):
        try:
            file_size = ui.fd.size
            blocksize = ui.fd.block_size
            slacksize = blocksize - file_size % blocksize

            if offset + length > file_size:
                for i in range(file_size, file_size + slacksize):
                    try:
                        ui.overlay[i-offset] = 9
                    except: break

                for i in range(file_size + slacksize, file_size + slacksize + blocksize):
                    try:
                        ui.overlay[i - offset] = 10
                    except: break
        except AttributeError:
            pass

class AnnotateOffset(Action):
    mode = 'annotate'
    event = 'a'

    previous_description = ''

    def help(self):
        return  "a                        Add annotation to this offset (Creates a new inode)"

    def handle_key(self, ui, key):
        if self.state == None:
            self.state = 'pending'
            self.top = None
        elif self.state == 'pending':
            ## Pass the key stroke to the underlying form
            print "Sending %s" % key
            ui.top.keypress( (ui.width,ui.height) , key)

    def do_button(self, button, (ui, press)):
        if press == "Yes":
            print "Will do it"
            self.previous_description = self.description.get_edit_text()
            dbh = DB.DBO(ui.case)
            fsfd = FileSystem.DBFS(ui.case)
            inode_id = fsfd.VFSCreate(ui.fd.inode, "o%s" % ui.mark,
                                      "_Note_")
            dbh.insert("annotate",
                       inode_id = inode_id,
                       note = self.previous_description)
        else:
            print "Canceled"

        self.state = None
        ui.mode = None

    def draw(self, ui):
        if not self.top:
            self.length = urwid.AttrWrap(urwid.Edit(),'editbx', 'editfc' )
            self.description = urwid.AttrWrap(PowerEdit('',self.previous_description,
                                                        multiline = True),
                                              'editbx', 'editfc' )
            ui.top = urwid.Padding(
              urwid.ListBox(
                urwid.SimpleListWalker([
                    urwid.Divider(),
                    urwid.Text(('hit','Creating Inode %s|o%s' % (ui.fd.inode, ui.mark))),
                    urwid.Divider(),
#                    urwid.Text("Length"),
#                    urwid.Padding(
#                         self.length, 'left', 10, 10),
#                    urwid.Divider(),
                    urwid.Text("Description"),
                    self.description,
                    urwid.Divider(),
                    urwid.GridFlow([
                       urwid.AttrWrap(urwid.Button("Yes",self.do_button,
                                                   (ui, "Yes")),'buttn','buttnf'),
                       urwid.AttrWrap(urwid.Button("No",self.do_button,
                                                   (ui, "No")),'buttn','buttnf'),
                       ], 13,3,1, 'left')
                    ])
                )
              , 'left', ('relative', 50), 80)
            ui.top = urwid.AttrWrap(ui.top, 'body')
            header = urwid.AttrWrap(
                urwid.Text("Set annotation on current offset location.  "), 'header')
            ui.top = urwid.Frame(ui.top , header = header)
            self.top = ui.top
            
class Hexeditor:
    row_size = 25
    
    def __init__(self, fd, highlights = None):
        """ An interactive Hex editor based on the Urwid library.
        
        fd: The file descriptor to dump.
        highlights: a list of offset, length, type tuples of possible highlights.

        type is an integer refering to the palette in PALETTE
        """
        self.fd = fd
        self.case = fd.case
        self.inode_id = fd.lookup_id()
        fd.seek(0)
        ## We try to set the size to the maximum we can have:
        try:
            filesize = fd.size
            blocksize = fd.block_size
            slack = blocksize - filesize % blocksize
            self.fd.overread = blocksize
            self.fd.slack = True
            self.size = filesize + slack + blocksize
        except AttributeError:
            self.size = fd.size
            
        self.file_offset = 0
        self.mark = 0
        self.focus_column = 1

        ## Cache the fd into data which is currently displayed - this
        ## avoids us having to re-read the fd all the time.
        self.screen_cache = None
        self.screen_offset = -1

        ## These are the actions hooked to this gui
        self.actions = {None: Navigate()}
        for action in [Help, SearchAction, Goto, IncrementalSearch,
                       SlackAction, AnnotateOffset]:
            a = action(self)
            self.actions[a.mode] = a

        self.mode = None
        
        self.status_bar = urwid.Text('')

        ## This shows a useful message
        self.message = ''
        self.previous_search = ''

        ## Constant highlights.
        self.highlights = highlights

    def clear_overlay(self):
        self.overlay = [0, ] *(self.width * self.height + 10)
        
    def run(self):
        self.ui = Screen()
        self.ui.set_mouse_tracking()
        self.ui.register_palette(PALETTE)
        self.ui.start()
        return self.urwid_run()

    def set_event(self, key, mode):
        """ Sets the mode which will be fired when key is pressed. """
        self.actions[None].events[key] = mode

    def cache_screen(self):
        ## This flag indicates if the cache was refreshed - this
        ## allows highlighters to skip updating the overlay if their
        ## highlights were not likely to have changed.
        length = self.width * self.height
        refreshed = False

        if self.screen_offset != self.file_offset:
            self.fd.seek(max(0, self.file_offset))
            #data = self.fd.read(min(length, self.size - self.file_offset))
            data = self.fd.read(length)
            self.screen_cache = cStringIO.StringIO(data)
            self.clear_overlay()
            self.screen_offset = self.file_offset
            refreshed = True

            ## Sometimes our concept of the fd's size is incorrect because
            ## it can not be calculated. If we read some bytes off it - we
            ## can assume its a bit more than we have:
            #largest_offset = self.screen_offset + len(data)
            #if largest_offset > self.size:
            #    self.size = largest_offset + 1

        ## Call all the highlighters to update the overlay
        actions = self.actions.values()
        def sort(x,y):
            if x.order > y.order: return 1
            return -1
        actions.sort(cmp = sort)

        self.clear_overlay()
        for action in actions:
            action.highlight(self, self.screen_offset, length, refreshed)

    def format_urwid_markup(self, hex_view=True):
        """ returns an urwid compatible markup from the overlay and
        screen_cache.
        """
        self.screen_cache.seek(0)
        last = self.overlay[0]
        result = []
        chars = ''
        tag_id = 0

        x=0
        while 1:
            c = self.screen_cache.read(1)
            if not c: break

            if hex_view:
                chars += "%02X " % ord(c)
            else:
                if c.isalnum() or c in "!@#$%^&*()_ +-=[]\{}|;':\",./<>?":
                    chars += c
                else:
                    chars += '.'

            try:
                tag_id = self.overlay[x+1]
                if tag_id != last:
                    result.append((PALETTE[last][0], chars))
                    chars = ''
                    last = tag_id
            except IndexError:
                break
            x+=1
            
        result.append((PALETTE[tag_id][0], chars))
        return result

    def adjust_mark(self):
        """ Adjust the mark if it exceeds the current screen """
        ## Make sure we dont go past end of file
        if self.mark > self.size-1:
            self.mark = self.size-1

        if self.mark < 0:
            self.mark = 0

        ## Do we need to go to the next page?
        if self.mark < self.file_offset or \
               self.mark > self.file_offset + self.pagesize:
            self.file_offset = (self.mark / self.pagesize) * self.pagesize
        
    def refresh_screen(self):
        """ Redraws the whole screen with the current channel window
        set to channel
        """
        self.width, self.height = self.ui.get_cols_rows()
        self.offset_length = max(4, len("%X" % (self.file_offset))+1)
        ## We work out how much space is available for the hex edit
        ## area (i.e. number of hex bytes per line).
        
        ## This is the formula: width = offset_length + 3 * x + x
        ## (where x is the number of chars per line)
        self.row_size = (self.width - self.offset_length - 1)/4
        self.pagesize = self.row_size * (self.height - 5)
        self.adjust_mark()
        self.cache_screen()

        ## Fill in the offsets
        offsets = [ ("%%0%uX" % self.offset_length) % offset for offset in \
                    range(self.file_offset,
                          self.file_offset + self.height * self.row_size,
                          self.row_size) ]
        
        self.offsets = urwid.ListBox([urwid.Text("\n".join(offsets))])
        self.hex     = OverlayEdit(self.format_urwid_markup(hex_view=True),
                                   edit_pos = (self.mark - self.screen_offset) * 3)
        self.chars   = OverlayEdit(self.format_urwid_markup(hex_view=False),
                                   edit_pos = self.mark - self.screen_offset)
        hex          = urwid.ListBox([self.hex])
        chars        = urwid.ListBox([self.chars])
        self.columns = urwid.Columns([('fixed', self.offset_length+1, self.offsets),
                                      ('fixed', 3*self.row_size, hex), 
                                      ('fixed', self.row_size, chars),
                                      ],0,min_width = 11, focus_column=self.focus_column)

        top = urwid.AttrWrap(self.columns, 'body')
        
        #self.status_bar = urwid.Text('')
        args = dict(footer=urwid.AttrWrap(self.status_bar, 'header'))
        try:
            if self.status_bar.focus: args['focus_part']='footer'
        except AttributeError: pass
        
        self.top = urwid.Frame(top, **args)

    def update_status_bar(self):
        self.adjust_mark()
        self.status_bar.set_text(
            "%s/%s 0x%X/0x%X %s" % (self.mark,self.fd.size-1,
                                    self.mark,
                                    self.size-1, self.message))

    def goto_next_search_hit(self):
        ## Issue the indexing request
        pass
        
    def urwid_run(self):
        self.refresh_screen()
        while 1:
            ## We are a generator and we are ready for more input
            keys = self.ui.get_input((yield "Ready"))

            for key in keys:
                ## These are just screen update requests
                if key=='eh?': continue
                
                if urwid.is_mouse_event(key):
                    event, button, col, row = key
                    self.process_mouse_event(self.width, self.height,
                                             event, button, col, row)
                else:
                    self.actions[self.mode].handle_key(self, key)
                                    
            self.actions[self.mode].draw(self)
            self.draw_screen()

    def draw_screen(self):
        ## Refresh the screen:
        canvas = self.top.render( (self.width, self.height) , focus=True )
        self.ui.draw_screen( (self.width, self.height) , canvas )

    def process_mouse_event(self, width, height, event, button, col, row):
        if event=="mouse press" and button==1:
            widths = self.columns.column_widths((width,height))
            total_width = 0
            for i in range(0,len(widths)):
                ## Does col fall between all the widths of columns so
                ## far and the next column?
                if col >= total_width and col < total_width + widths[i]:
                    break

                total_width += widths[i]

            x = col - total_width
            if i==0:
                self.mark = self.file_offset + self.row_size * row
            elif i==1:
                self.mark = self.file_offset + self.row_size * (row) + x/3
                self.focus_column = 1
            elif i==2:
                self.mark = self.file_offset + self.row_size * (row) + x
                self.focus_column = 2

## Over ride the File hexeditor method:
def hexedit(self, query, result):
    ## Create the application
    screen = Hexeditor(self)
    generator = screen.run()
    generator.next()

    ## We need to set the initial offset
    screen.mark = int(query.get('offset',0))

    ## And any highlights required
    h = query.getarray('highlight')
    l = query.getarray('highlight_length')
    screen.highlights = [ (int(h[i]), int(l[i]), 8) for i in range(len(h)) ] 

    def urwid_cb(query, result):
        result.decoration = "raw"
        if query.has_key("_value"):
            ## Send any inputs to it: FIXME - this needs thread locks
            ## around it because web requests come in on multiple
            ## threads:
            generator.send(query.get('_value',''))

            ## Refresh the screen
            result.content_type = "text/plain"
            result.result = screen.ui.buffer
        else:
            result.content_type = "text/html"
            result.result = "".join(pyflag_display._html_page)                

    result.iframe(callback = urwid_cb)

try:
    import urwid
    import pyflag_display
    import pyflag.FileSystem as FileSystem
    import pyflag.conf
    config=pyflag.conf.ConfObject()

    config.add_option("DISABLE_URWID", default=False, action="store_true",
                      help = "Do not use interactive Urwid applications")

    config.parse_options(False)

    if not config.DISABLE_URWID:
        ## Upgrade the hexdump method of the File object
        FileSystem.File.hexdump = hexedit

    Screen = pyflag_display.Screen

    class OverlayEdit(urwid.Edit):
        """ A specialised edit box which supports highlighting of the
        edited text
        """
        def __init__(self, text, edit_pos=0):
            urwid.Edit.__init__(self, multiline = True, wrap = 'any')
            self.set_edit_text(text)
            self.set_edit_pos(edit_pos)

        def set_edit_pos(self, pos):
            self.edit_pos = min(pos, len(self.edit_text))

        def set_edit_text(self, text):
            self.edit_text, self.attrib = urwid.decompose_tagmarkup(text)
            if self.edit_pos > len(self.edit_text):
                self.edit_pos = len(self.edit_text)

            self._invalidate()


    class PowerEdit(urwid.Edit):
        """ An Edit box with a few more keys """
        def keypress(self, maxcol,key):
            p = self.edit_pos
            if key=="meta backspace":
                # Delete from point to the previous space
                left = self.edit_text[:p].rfind(" ")
                if left==-1: left = 0

                self.edit_text = self.edit_text[:left] + self.edit_text[p:]
                self.edit_pos = left
            else:
                return urwid.Edit.keypress(self, maxcol, key)

except ImportError:
    disabled = True

