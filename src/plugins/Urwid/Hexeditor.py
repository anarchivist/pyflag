""" This is an implementation of the hexeditor using urwid """
import cStringIO, re
import pyflag.Indexing as Indexing
import pyflag.FlagFramework as FlagFramework

PALETTE = [
    ('editfc','white', 'dark blue', 'bold'),
    ('editbx','light gray', 'light blue'),
    ('editcp','black','light gray', 'standout'),
    ('header', 'black', 'dark cyan', 'standout'),
    ('body','black','light gray', 'standout'),
    ('default', 'default', 'default', 'bold'),
    ('self', 'default', 'default'),
    ('help', 'yellow', 'default'),
    ]

class Action:
    """ An action handler base class """
    state = None
    ## This controls our order in the Action stack
    order = 0
    def handle_key(self, ui, key):
        """ This is called to process keys as the come in.

        If we return True - no further processing of the key will be
        performed."""
        return False

    def draw(self, ui):
        """ This is called when we wish to draw the screen. If we
        return False we allow the ui to draw the screen, otherwise we
        get to.
        """
        return False

    def help(self):
        """ Return a helpful message about this module - should
        probably list all the key bindings
        """
        return ''
    
class SearchAction(Action):
    """ A state machine which takes care of the search functionality """
    previous_search = ''

    def handle_key(self, ui, key):
        """ This gets called when we become active """
        if self.state == None and key != '/':
            return False
        
        if self.state ==None:
            self.state = 'prompt'
            ui.status_bar = urwid.Edit("Search: ", self.previous_search,
                                         wrap='any', multiline=False)
            ui.status_bar.focus = True
        elif self.state == 'prompt':
            if key=='enter':
                self.state = 'waiting'
                ui.status_bar = urwid.Text('')
                ui.message = 'Waiting for Indexer'
            else:
            ## Pass key strokes to the text box:
                ui.status_bar.keypress( (ui.width, ), key)
            
        elif self.state == 'waiting':
            ## Check if the inode is up to date:
            if Indexing.inode_upto_date(ui.case, ui.inode_id):
                print "Going to next hit"
                ui.message =''
                self.state = None
        else:
            print "Unknown search mode %s" % self.state

        return True

    def help(self):
        return "/  - Search this file (uses the Indexer)"

class Goto(Action):
    """ This allows us to jump to a fixed offset """
    previous_location = ''

    def help(self):
        return  'g                        Goto an offset (can be specified using sectors, k, m. 0x prefix means hex)'
    
    def handle_key(self, ui ,key):
        print self.state
        if self.state == None and key != 'g':
            return False

        if self.state == None:
            self.state = 'prompt'
            ui.status_bar = urwid.Edit("Goto: ", self.previous_location)
            ui.status_bar.focus = True

        elif self.state == 'prompt':
            if key=='enter':
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
    def handle_key(self, ui, k):
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

class Help(Action):
    def help(self):
        return 'h,?                      print this help\n'
    
    def handle_key(self, ui, key):
        if self.state == None and (key != 'h' and key !='?'):
            return False

        if self.state == None:
            self.state = 'help'
            result = [('header','Help (press q to go back)\n')]
            for action in ui.actions:
                tmp = action.help()
                if type(tmp)==type(str):
                    result.append(('help', tmp + "\n"))
                else:
                    result.extend(tmp)
                    
            ui.top = urwid.Frame(
                urwid.ListBox([urwid.Text(result)])
                )
            ui.draw_screen( (ui.width, ui.height) )
        else:
            self.state = None
            ui.refresh_screen()
            
        return True

    def draw(self, ui):
        if self.state:
            return True

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
        try:
            self.size = fd.size
        except AttributeError:
            fd.seek(0,2)
            self.size = fd.tell()
            
        self.file_offset = 0
        self.mark = 0
        self.focus_column = 1

        ## Cache the fd into data which is currently displayed - this
        ## avoids us having to re-read the fd all the time.
        self.screen_cache = None
        self.screen_offset = -1

        ## These are the actions hooked to this gui
        self.actions = [Help(), SearchAction(), Navigate(), Goto()]
        self.status_bar = urwid.Text('')

        ## This shows a useful message
        self.message = ''
        self.previous_search = ''

        ## Constant highlights.
        self.highlights = highlights
        
    def run(self):
        self.ui = Screen()
        self.ui.set_mouse_tracking()
        self.ui.register_palette(PALETTE)
        self.ui.start()
        return self.urwid_run()

    ## These call backs are used to alter the current hilighting
    ## overlay - this allows us to highlight various bits of text for
    ## different purposes.
    def constant_highlighter(self, offset, length, fresh=False):
        """ This callback is used to handle highlighting of contant
        strings which have been passed in the constructor.

        offset and length represent the current view port into the
        file.  The fresh flag indicates if the current overlay is
        brand new. We can skip updating it if its not brand new.
        """
        if not fresh: return
        
        if self.highlights:
            for file_offset, hilight_length, type in self.highlights:
                if file_offset > offset and file_offset < offset + length:
                    self.overlay[file_offset - offset: \
                                 file_offset - offset + hilight_length] = \
                                 [type,] * hilight_length

    highlighter_cbs = [ constant_highlighter, ]

    def cache_screen(self, offset, length):
        ## This flag indicates if the cache was refreshed - this
        ## allows highlighters to skip updating the overlay if their
        ## highlights were not likely to have changed.
        refreshed = False
        if self.screen_offset != offset:
            self.fd.seek(max(0, offset))
            self.screen_cache = cStringIO.StringIO(self.fd.read(length))
            self.overlay = [0,] * length
            self.screen_offset = offset
            refreshed = True
            
        ## Call all the highlighters to update the overlay
        for fn in self.highlighter_cbs:
            fn(self, self.screen_offset, length, refreshed)

    def format_urwid_markup(self, hex_view=True):
        """ returns an urwid compatible markup from the overlay and
        screen_cache.
        """
        self.screen_cache.seek(0)
        last = self.overlay[0]
        result = []
        chars = ''

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

            tag_id = self.overlay[x]
            if tag_id != last:
                result.append((PALETTE[last][0], chars))
                chars = ''
                last = tag_id
                
            x+=1
            
        result.append((PALETTE[tag_id][0], chars))
        return result

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

        ## Fill in the offsets
        offsets = [ ("%%0%uX" % self.offset_length) % offset for offset in \
                    range(self.file_offset,
                          self.file_offset + self.height * self.row_size,
                          self.row_size) ]
        
        self.cache_screen(self.file_offset, self.width * self.height)
        
        self.offsets = urwid.ListBox([urwid.Text("\n".join(offsets))])
        self.hex     = OverlayEdit(self.format_urwid_markup(hex_view=True))
        self.chars   = OverlayEdit(self.format_urwid_markup(hex_view=False))
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
        self.status_bar.set_text(
            "0x%X/0x%X %s" % (self.mark,
                              self.size-1, self.message))

    def goto_next_search_hit(self):
        ## Issue the indexing request
        pass
        
    def urwid_run(self):
        self.refresh_screen()
        action = None
        while 1:
            self.pagesize = self.row_size * (self.height - 5)

            if not action or not action.draw(self):
                try:
                    self.hex.set_edit_pos((self.mark - self.file_offset)*3)
                    self.chars.set_edit_pos(self.mark - self.file_offset)
                    self.columns.set_focus_column(self.focus_column)
                except AssertionError:
                    print "Error in widgets mark is at %s, file offset %s" % (self.mark,
                                                                              self.file_offset)
                    raise

                self.draw_screen( (self.width, self.height) )
                self.update_status_bar()
                self.refresh_screen()                    

            ## We are a generator and we are ready for more input
            keys = self.ui.get_input((yield "Ready"))

            for key in keys:
                for action in self.actions:
                    ## Does the handle take the key?
                    if action.handle_key(self, key):
                        break

                if urwid.is_mouse_event(key):
                    event, button, col, row = key
                    self.process_mouse_event(self.width, self.height,
                                             event, button, col, row)
                    
            ## Make sure we dont go past end of file
            if self.mark > self.size-1:
                self.mark = self.size-1

            if self.mark < 0:
                self.mark = 0

            ## Do we need to go to the next page?
            if self.mark < self.file_offset or \
                   self.mark > self.file_offset + self.pagesize:
                self.file_offset = (self.mark / self.pagesize) * self.pagesize

            if not action.draw(self):                
                self.update_status_bar()
                self.refresh_screen()                    

    def draw_screen(self, size):
        ## Refresh the screen:
        canvas = self.top.render( size, focus=True )
        self.ui.draw_screen( size, canvas )

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
                self.mark = self.file_offset + self.row_size * (row+1) + x
                self.focus_column = 2

## Over ride the File hexeditor method:
def hexedit(self, query, result):
    ## Create the application
    screen = Hexeditor(self)
    generator = screen.run()
    generator.next()

    def urwid_cb(query, result):
        result.decoration = "raw"
        if query.has_key("_value"):
            ## Send any inputs to it:
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
except ImportError:
    disabled = True

class OverlayEdit(urwid.Edit):
    """ A specialised edit box which supports highlighting of the
    edited text
    """
    def __init__(self, text):
        urwid.Edit.__init__(self, multiline = True, wrap = 'any')
        self.set_edit_text(text)

    def set_edit_text(self, text):
        self.edit_text, self.attrib = urwid.decompose_tagmarkup(text)
        if self.edit_pos > len(self.edit_text):
            self.edit_pos = len(self.edit_text)
            
        self._invalidate()
        
