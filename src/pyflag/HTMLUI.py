# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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

""" Main UI module.

The output within flag is abstracted such that it is possible to connect any GUI backend with any GUI Front end. This is done by use of UI objects. When a report runs, it will generate a UI object, which will be built during report execution. The report then returns the object to the calling framework which will know how to handle it. Therefore the report doesnt really know or care how the GUI is constructed """

import re,cgi,types,textwrap,sys
from urllib import quote
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.conf
import pyflag.UI as UI
config=pyflag.conf.ConfObject()
import pyflag.Theme as Theme
import cStringIO,csv,time
import pyflag.Registry as Registry
import pyflag.parser as parser

class HTMLException(Exception):
    """ An exception raised within the UI - should not escape from this module """

class HTTPObject:
    def __init__(self):
        self.content_type=None
        self.generator=None
        self.headers=[]


def goto_row_cb(query,result,variable='limit'):
    """ This is used by the table widget to allow users to skip to a
    certain row"""
    limit = query[variable]

    try:
        if query['refresh']:
            del query['refresh']

            ## Accept hex representation for limits
            if limit.startswith('0x'):
                del query[variable]
                query[variable]=int(limit,16)
            
            result.refresh(0,query,parent=1)            
    except KeyError:
        pass

    result.decoration = 'naked'
    result.heading("Skip directly to a row")
    result.para("You may specify the row number in hex by preceeding it with 0x")
    result.start_form(query, pane="parent")
    result.start_table()
    if limit.startswith('0x'):
        limit=int(limit,16)
    else:
        limit=int(limit)
        
    result.textfield('Row to skip to', variable)
    result.end_table()
    result.end_form()

class HTMLUI(UI.GenericUI):
    """ A HTML UI implementation.

    @cvar name: Name of the class may be queried by reports to find out what UI they are running under. Warning- use very sparingly, since UIs are supposed to automatically produce the same output regardless what the input is, you dont need this. Use only when you want to disable certain viewes on certain UI's because they dont make sense (e.g. htmlview on non html uis)
    """
    callback = None
    name = "HTMLUI"
    tree_id = 0
    ## This is used as a unique count of ids
    id=0
    def __init__(self,default = None,query=None):
        self.result = ''

        import pyflag.FlagFramework as FlagFramework
        self.flag = FlagFramework.GLOBAL_FLAG_OBJ
            
        if default != None:
            self.form_parms = default.form_parms
            self.form_target = None
            self.defaults = default.defaults
            self.toolbar_ui=default.toolbar_ui
            self.generator=default.generator
            self.depth = default.depth+1
            self.parent = default
        else:
            self.form_parms =FlagFramework.query_type(())
            self.form_target = None
            self.defaults = FlagFramework.query_type(())
            self.toolbar_ui=None
            self.generator=HTTPObject()
            self.depth=1
            self.parent = None

        if query:
            self.defaults=query

        self.color=None
        self.font=None
        self.table_depth = 0
        self.type = "text/html"
        #This specifies if we should render the UI in the theme or
        #naked. Note that this only affects UIs which are drawn in a
        #window not ones which are added to other UIs:
        self.decoration='full'
        self.title=''

## The __pyflag_parent, __pyflag_name are variables set in js window
## object to refer back to the logical parent of each pyflag
## window. The problem is that with regular JS each frame, and iframe
## is a seperate window object with different window.parent or window.opener
## properties. From Pyflags point of view, they are all a part of the
## same window (for example in a tree you have an iframe and 2 frames
## all belonging to the same logical window - but in different js
## windows). So we need to propagate the logical pyflag window and
## parent properties to each js window object blonging to it. This way
## when a pyflag link, refresh or submit need to go back to their
## parent they will know the correct js window to go to.        
    def display(self):
        ## Get the right theme
        theme=Theme.get_theme(self.defaults)
        if self.decoration=='raw':
            return theme.raw_render(data=self.__str__(), ui=self,title=self.title)

        ## Try to prpegate __pyflag_parent, __pyflag_name if present
        try:
            self.result = "<script> window.__pyflag_parent = %r; window.__pyflag_name = %r; </script>" % (self.defaults['__pyflag_parent'], self.defaults['__pyflag_name']) + self.result
        except Exception,e:
            pass

        if self.decoration=='naked' or self.decoration=='js':
            return theme.naked_render(data=self.__str__(), ui=self,title=self.title)
        else:
            return theme.render(data=self.__str__(), ui=self)
    
    def __str__(self):
        #Check to see that table tags are balanced:
        while self.table_depth>0:
            self.end_table()

        return self.result

    def heading(self,string):
        self.result += "<h1>%s</h1>"%string

    def para(self,string,**options):
        string = cgi.escape(string)
        if options.has_key('font'):
            if options['font'].lower() == "pre":
                self.result += "<pre>%s</pre>" %string
                return
            
        self.result += "\n\n<p>%s</p>\n\n" % string

    def opt_to_str(self,*args,**options):
        """ Converts a list of options into a string.

        May accept arbitrary number of parameters as a list or named parameters. Eg:

        >>> opt_to_str(\"a=1\",\"b=2\",c=3,d=4)
        \" a=1  b=2  c='3'  d='4' \"
        
        """
        
        if options:
            #Tuple concatenation
            args = args + (options,)
            
        option_str = ''
        for arg in args:
            if isinstance(arg,str):
                option_str += " "+arg+" "
            elif isinstance(arg,dict):
                for items in arg.items():
                    option_str += " %s=%r "% (items)

        return option_str

    table_depth = 0

    def download(self,file):
        """ Create a mechanism for the user to download the file.

        @arg file: A file like object derived from FileSystem.File (This must be a generator).
        """
        magic=FlagFramework.Magic(mode='mime')
        file.seek(0)
        data=file.read(1000)
        self.generator.content_type=magic.buffer(data)
        try:
            self.generator.headers=[("Content-Disposition","attachment; filename=%s" % file.inode),]
        except AttributeError:
            self.generator.headers=[("Content-Disposition","attachment; filename=%s" % file.name),]

        file.seek(0)
        self.generator.generator=file
        
    def image(self,image,**options):
        """ Plots the current image inside the UI.

        @arg image: An instance of the Image class.
        """
        opt = self.opt_to_str(**options)
        
        #Create a new UI for the graph:
        tmp = self.__class__(self)

        #Ask the image whats its ct:
        tmp.result = image.display()
        tmp.type = image.GetContentType()
        tmp.decoration='raw'
        #Redefine our display method to just dump the binary object back
        if tmp.type.startswith("image"):
            self.result +=  '<img type=%r src="f?draw_stored=%s" %s />'  % (tmp.type,self.store(tmp),opt)
        else:
        ## Store the ui for later retrieval by the browser when we fetch the target:
            self.result +=  '<object type=%r data="f?draw_stored=%s" %s />'  % (tmp.type,self.store(tmp),opt)

    def store_callback(self,callback):
        """ Function registers the callback with the server.

        If the user then issues  another request to it, it gets called to render the UI.

        This allows a report to specify a large number of items
        quickly which do not get rendered untill they are visible. For
        example if we show a pop up window, we dont actually render
        the window until the user pops it up.
        """

        cb_key = self.flag.store.put(callback, prefix="CB")
        return cb_key
    
    def store(self,ui):
        """ Function stores the current UI in a dict in the class method. This is required when we need to store a UI and later get the browser to retrieve it. """
        key = self.flag.store.put(ui, prefix="UI")
        return key
    
    def start_table(self,**options):
        self.table_depth += 1
        self.result += "<table %s>\n" % self.opt_to_str(options)

    def row(self,*columns, **options):
        #Sort through all the options for the ones that should go to the td html element
        td_opts = {}
        type = "td"
        
        if options:
            if options.has_key('colspan'):
                td_opts['colspan'] = options['colspan']

            if options.has_key('width'):
                td_opts['width'] = options['width']

            if options.has_key('type') and options['type'] == 'heading':
                type="th"
        
        #If the user forgot to start the table, we forgive them and just start it for them
        if not self.table_depth:
            self.start_table()
                        
        self.result+="<tr %s>\n" % self.opt_to_str(options)
        for column in columns:
            try:
                column = long(column)
                td_opts['class'] = 'Integer'
            except:
                td_opts['class'] = ''
                
            self.result += "<%s %s>%s</%s>" % (type,self.opt_to_str(td_opts),column,type)

        self.result+="</tr>\n"

    def end_table(self):
        self.table_depth -= 1
        self.result += "</table>\n"

    def pre(self,string):
        self.result += "<pre>%s</pre>" % string

    def _calculate_js_for_pane(self, target=None, pane="main", **opts):
        """ Returns the JS string required to facilitate opening in the requested pane

        Modifies query to remove stored callbacks if needed.

        target: The query we should link to. We will delete callbacks from it if needed.

        pane: Where we want to open the link can be:
        main (default): refresh to the main pane (default).
        parent: refresh to the pane that contains this pane. (useful for popups etc).
        popup: open a new popup window and draw the target in that.
        self: refresh to the current pane (useful for internal links in popups etc).
        """
        if pane=='self':
            return "post_link('f?%s',window.__pyflag_name); return false;" % target
        
        if pane=='popup':
            id=self.get_unique_id()
            return "window.open('f?%s&__pyflag_parent='+window.__pyflag_name+'&__pyflag_name=child_%s','child_%s',  'width=600, height=600,scrollbars=yes'); return false;" % (target, id,id)

        if target:
            ## Try to remove the callback which we are generated from:
            try:
                target.remove('callback_stored', self.callback)
            except:
                pass

        if pane=='parent':
            return "link_to_parent(\"%s\", window.__pyflag_parent); return false;" % target

        if pane=="main":
            return "post_link('f?%s','main'); find_window_by_name(window.__pyflag_name).close(); return false;" % target
    
    def link(self,string,target=None,options=None,icon=None,tooltip=None, pane='main', **target_options):
        ## If the user specified a URL, we just use it as is:
        try:
            self.result+="<a href='%s' target=_top>%s</a>" % (target_options['url'],string)
            return
        except KeyError:
            pass
        
        if target==None:
            q=FlagFramework.query_type(())
        else:
            q=target.clone()
            
        if target_options:
            for k,v in target_options.items():
                del q[k]
                q[k]=v

        if icon:
            tmp = self.__class__(self)
            tmp.icon(icon,alt=string,border=0, tooltip=tooltip)
            tooltip=string
            string=tmp

        js = self._calculate_js_for_pane(target=q, pane=pane)
        base = "<a href='f?%s' onclick=%r>%s</a>" % (q, js, string)

        ## Add tooltip if needed:
        if tooltip:
            self.result+="<abbr title='%s'>%s</abbr>" % (tooltip,base)
        else:
            self.result+=base

    def popup(self,callback, label,icon=None, tooltip=None, width=600, height=600, **options):
        """ This method presents a button on the screen, which when
        clicked will open a new window and use the callback to render
        in it.

        The new UI will be based on the current UI.
        @arg callback: A callback function to render into the new UI
        """
        if not tooltip: tooltip = label
        cb = self.store_callback(callback)

        if icon:
            base = "<img alt='%s' border=0 src='images/%s' onclick=\"popup('%s','%s',%r,%r); return false;\" class=PopupIcon />" % (label,icon, self.defaults,cb, width, height)
        else:
            base = "<input type=button value=%r onclick=\"popup('%s','%s',%r,%r); return false;\" />" % (label,self.defaults,cb,width,height)
        if tooltip:
            self.result += "<abbr title=%r>%s</abbr>" % (tooltip,base)
        else:
            self.result += base

    def radio(self,description,name,labels,**options):
        opts = self.opt_to_str(options)
        tmp ='' 
        for i in labels:
            if self.defaults[name] == i:
                tmp += "<input type=\"radio\" name=\"%s\" value=\"%s\" checked=\"checked\" %s />%s\n" % (name,i,opts,i)
            else:
                tmp += "<input type=\"radio\" name=\"%s\" value=\"%s\" %s />%s\n" % (name,i,opts,i)

        if self.form_parms.has_key(name):
            del self.form_parms[name]
        self.row(description,tmp)

    def hidden(self,name,value):
        """ Create a hidden parameter to be passed on form submission """
        self.form_parms[name]=value

    def checkbox(self,description,name,value,**options):
        """ Create a checkbox input for the name,value pair given. """
        opt_str = ''
        if options:
            opt_str = self.opt_to_str(options)
        if value in self.defaults.getarray(name):
            opt_str += 'checked'
        self.row(description,"<input type=checkbox name=\"%s\" value=\"%s\" %s>" % (name,value,opt_str))
        if self.form_parms.has_key(name):
            del self.form_parms[name]
            
    def const_selector(self,description,name,keys,values,**options):
        if options:
            opt_str = self.opt_to_str(options)
        else: opt_str = ''
        
        tmp = "<select name=\"%s\" %s>\n" % (name,opt_str);

        for k,v in zip(keys,values):
            if (name,k) in self.defaults.q:
                tmp +=  "<option selected value='%s'>%s</option>\n" % (k,v)
            else:
                tmp +="<option value='%s'>%s</option>\n" % (k,v)

        tmp+="</select>\n"
        #Remove this from the form_parms
        if self.form_parms.has_key(name):
            del self.form_parms[name]
            
        #Draw in a nice table format
        self.row(description,tmp)

    def tree(self, tree_cb = None, pane_cb=None, branch = None, layout=None):
        """ A tree widget.

        This implementation uses javascript/iframes extensively.
        """
        def draw_branch(depth,preamble,query):
            result = ''
            try:
            ## Get the right part:
                branch=FlagFramework.splitpath(query['open_tree'])
            except KeyError:
                branch=['']

            path = FlagFramework.joinpath(branch[:depth])

            ## This function returns the html for a single row.
            def render_row(name, value, state, preamble):
                result = ''
                ## Must have a name and value
                if not name or not value: return ''
                result+="<span class='PyFlagTreeRow'>" + preamble

                link = query.clone()
                del link['open_tree']
                del link['yoffset']
                del link['xoffset']
                cb = link.poparray('callback_stored')
                
                link['open_tree'] = FlagFramework.normpath("/".join(branch[:depth] + [name]))
                open_tree = FlagFramework.urlencode(link['open_tree'])
                sv=value.__str__().replace(' ','&nbsp;')

                ## Mark the currently opened branch especially
                img_class = 'PyFlagTreeNode'
                img_src = '/images/treenode_blank.gif'
                
                if 'branch' in state:
                    if depth < len(branch) and name == branch[depth]:
                        img_src = '/images/treenode_expand_minus.gif'
                    else:
                        img_src = '/images/treenode_expand_plus.gif'

                if 'up' in state:
                    img_src = '/images/up.png'
                elif 'down' in state:
                    img_src = '/images/down.png'

                ## We ensure to not draw vertical lines past the end
                ## of the tree
                if 'end' in state:
                    img_class = 'PyFlagTreeNodeEnd'
                    preamble += "<img class='PyFlagTreeSpacer' src='/images/treenode_blank.gif'>"
                else:
                    preamble += "<img class='PyFlagTreeVerticalLine' src='/images/treenode_blank.gif'>"

                result+="<a href=\"javascript:tree_open('%s','%s','f?%s')\"><img class=%r src='%s'>" % (cb,query['right_pane_cb'],quote(link.__str__()), img_class, img_src)

                if len(branch)-1==depth and name == branch[depth]:
                    result+="&nbsp;<span class='PyFlagTreeSelected'>%s</span></a></span>\n" % str(sv)
                else:
                    result+="&nbsp;%s</a></span>\n" % str(sv)
                    
                result+="\n"
                
                ## Draw any opened branches
                if len(branch)>depth and name == branch[depth]:
                    result += draw_branch(depth+1,preamble, query)

                return result

            ## We need to implement a sliding window of rows to render
            ## about the point where name == branch[depth]
            initial_rows = []
            window = []
            found = False
            for name,value,state in tree_cb(path):
                ## This is the initial MAXTREESIZE rows. If we cant
                ## find branch[depth] here, we just use this:
                if len(initial_rows) < config.MAXTREESIZE * 2:
                    initial_rows.append((name,value,[state,]))

                ## This is a sliding window
                if len(window) >= config.MAXTREESIZE * 2:
                    window = window[-config.MAXTREESIZE *2:]
                    
                window.append((name,value,[state,]))

                ## We need to center about this one - we discard the first few:
                if len(branch)>depth and name==branch[depth]:
                    found = True
                    l = len(window)
                    window = window[-config.MAXTREESIZE:]
                    
                    if l > config.MAXTREESIZE:
                        window[0][2].append("up")

                ## Are we too full?
                if found and len(window)==config.MAXTREESIZE *2:
                    break

            if found:
                displayed_rows = window
            else:
                displayed_rows = initial_rows

            ## Our displayed rows are full - we must assume there are
            ## more rows to go
            if len(displayed_rows)==config.MAXTREESIZE *2:
                displayed_rows[-1][2].append('down')
            else:
                try:
                    displayed_rows[-1][2].append('end')
                except: pass
                
            for name,value,state in displayed_rows:
                result+=render_row(name, value, state,preamble)

            return result

        def left(query,result):
            result.decoration = "js"
            result.content_type = "text/html"

            #The first item in the tree is the first one provided in branch
            link = query.clone()
            link.poparray('callback_stored')
            del link['open_tree']

            left_cb = query.getarray('callback_stored')[-1]
            right_pane_cb = query['right_pane_cb']
            result.result+="<div class='PyFlagTree' >"
            result.result+="<a href=\"javascript:tree_open('%s','%s','f?%s')\"><img class=PyFlagTreeNodeEnd src='/images/treenode_expand_plus.gif'></a>/" % (left_cb,query['right_pane_cb'],link.__str__())
            result.result+=draw_branch(0,"<img class='PyFlagTreeSpacer' src='/images/treenode_blank.gif'>",query)
            try:
                result.result+="<script>document.body.scrollTop = %s; document.body.scrollLeft = %s;</script>\n" % (query['yoffset'], query['xoffset'])
            except:
                pass

            result.result+="</div>"
            
        def right(query,result):
            result.decoration = "js"
            result.content_type = "text/html"

            try:
            ## Get the right part:
                path=FlagFramework.normpath(query['open_tree'])
            except KeyError:
                path=''

            pane_cb(path,result)

        l = self.store_callback(left)
        r = self.store_callback(right)

        ## This is a hack to make the tree boundary adjustable:
        def tree_frame_cb(query,result):
            result.decoration = 'raw'

            try:
                self.defaults.remove("callback_stored", self.callback)
            except:
                pass
            
            left_url = "%s&callback_stored=%s&right_pane_cb=%s&__pyflag_parent=%s&__pyflag_name=%s" % (self.defaults,l,r,query['__pyflag_parent'], query['__pyflag_name'])
            right_url ="%s&callback_stored=%s&__pyflag_parent=%s&__pyflag_name=%s" % ( self.defaults, r, query['__pyflag_parent'], query['__pyflag_name'])
                
            result.result = '''<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
            <HTML>
            <script> window.__pyflag_name = "%s"; window.__pyflag_parent="%s";</script>
            <FRAMESET FRAMEBORDER=1 FRAMESPACING=1 COLS="340,*">
            <FRAME SRC="%s" name=left id=left scrolling=auto>
            <FRAME SRC="%s" name=right id=right scrolling=auto>
            </FRAMESET>
            </HTML>''' % (query['__pyflag_name'], query['__pyflag_parent'], left_url, right_url)

        tfcb = self.store_callback(tree_frame_cb)
        id = self.get_unique_id()
        self.result += """<iframe id='TreeFrame%s' class=TreeFrame></iframe>
        <script>AdjustHeightToPageSize('TreeFrame%s');document.getElementById('TreeFrame%s').src='/f?callback_stored=%s&__pyflag_parent=' + window.__pyflag_parent + '&__pyflag_name=' + window.__pyflag_name;</script>
        """ % (id,id,id,tfcb)
        
    def new_toolbar(self):
        id = "Toolbar%s" % self.get_unique_id()
        self.result += '''<div class="Toolbar" id="%s"></div>''' % id
        return id

    def xxtree(self,tree_cb = None, pane_cb=None, branch = None, layout="horizontal"):
        """ A tree widget.

        This widget works by repeatadly calling the call back function for information about entries in the current tree. The format of the callback is:

        >>> def tree_cb(branch):

        The call back function is a generator which is expected to yield (name,value,state) tuples representing the entries under the requested branch:
              - name: The name of the tree branch. This name will be used to access the tree branches and may have limitations on the characters that may be present. __This can not be empty, or the line will be rejected___.
              - value: A string or a UI object that will be displayed at that position in the tree
              - state: Indicates if this is a \"branch\" (i.e. can be opened up) or a leaf.

        @Note: If you do not want to use generators you must return a list of (name,value,state) tuples from the call back function. (Its effectively the same thing).

        @Note: It is very important to stress that the call back is a generator, therefore it must yield results rather than return them.

        Also since multiple instances of the generator function may be called simultaneously, it is _imperative_ that the call back function not modify variables outside its scope, or serious locking issues may arise. In particular, it is imperative that database handles be created inside the local scope.

        @arg tree_cb: Call back registered to build the tree
        @arg branch: A list representing a branch to have initially expanded. Each item in the list represents a branch at its respective depth in the tree. e.g.

        >>> /usr/share/local = ('usr','share','local')
        
        """
        if not self.defaults: raise UIException("Must have default query for tree widget")
        query = self.defaults

        #Read in the current branch that needs to be opened from the open_tree parameter
        if query.has_key('open_tree'):
            open = query['open_tree']
            branch = [ d for d in open.split('/') ]
            branch[0]='/'

        #Start building the tree using the branch.
        def draw_branch(depth,tree_array):
            """ This is a recursive function used to build the tree. Complicating matters is the need to omit rows which are further than config.MAXTREESIZE away from the selected item. This is done in order to speed up browsing through a browser (its not needed for GTKUI for example).

            @note: We are using the callback as a generator here to ensure we do not need to parse potentially thousands of entries.
        
            @arg tree_array: This function builds tree_array as it goes to represent the final tree HTML structure.
            @arg depth: The current depth to calculate - an int pointing into the branch array
            """
            found =0
            tmp = []
            #We search through all the items until we find the one
            #that matches the branch for this depth, then recurse into
            #it.
            path=FlagFramework.joinpath(branch[:depth])
            for k,v,t in tree_cb(path):
                if not k: continue
                if not t: continue
                tmp.append((depth,k,v,t))
                try:
                    #We are further than config.MAXTREESIZE after the
                    #tree item that will matched, we can quit now
                    #after placing an arrow
                    if found and len(tmp)>config.MAXTREESIZE:
                        tree_array += tmp
                        if len(tmp) > config.MAXTREESIZE:
                            tree_array.append((depth,tmp[-1][1],'<img src=/images/down.png border=0> ...','special'))
                        return

                    #Do we find the current item in the list?
                    if k == branch[depth]:
                        match_pos = len(tmp)
                        
                        #Now slice the tmp array to append it to the tree array
                        if match_pos-config.MAXTREESIZE < 0:
                            start = 0
                        else:
                            start = match_pos - config.MAXTREESIZE
                            tree_array.append((depth,tmp[start-1][1],'<img src=/images/up.png border=0> ...','special'))
                        
                        tree_array += tmp[start:]
                        tmp = []
                        found = 1
                        #Recurse into the next level in the tree
                        draw_branch(depth+1,tree_array)
                                                
                except IndexError,e:
                    #This is triggered when there is no deeper level in the tree
                    if len(tmp) > config.MAXTREESIZE:
                        break

            #We get here if we exhausted all the items within
            #config.MAXTREESIZE or did not find the requested branch
            #in the tree
            split =  tmp[:config.MAXTREESIZE]
            tree_array += split
            if len(split) == config.MAXTREESIZE:
                tree_array.append( (depth,split[-1][1],'<img src=/images/down.png border=0> ...','special'))

        #### End draw_branch

        link = query.clone()
        tree_array = []

        #The first item in the tree is the first one provided in branch
        if not branch[0]:
            tree_array.append((0,'/','/','branch'))
        else:
            tree_array.append((0,branch[0],branch[0],'branch'))

        #Build the tree_array
        draw_branch(1,tree_array)       

        del link['open_tree']
        link['open_tree'] = FlagFramework.normpath("%s" % '/'.join(branch[:-1]))
        if not link['open_tree']:
            del link['open_tree']
            link['open_tree']='/'
        tmp = self.__class__()
        tmp.link("Up\n",link)
        self.text(tmp)

        left=self.__class__()

        #Now we draw the stuff saved in tree_array according to its classification
        for depth,k,v,t in tree_array:
            del link['open_tree']
            link['open_tree'] = FlagFramework.normpath("/".join(branch[:depth] + [k]))
            open_tree = FlagFramework.urlencode(link['open_tree'])
            sv=v.__str__().replace(' ','&nbsp;')
            left.icon("spacer.png",width=20*depth,height=20)
            if t =='branch':
                new_query = link
                left.link(str(sv),tooltip=link['open_tree'],target=link, name=open_tree,icon="folder.png")
                left.text("&nbsp;%s\n" % str(sv),color='black')
            elif t == 'special':
                left.link(str(v),tooltip=link['open_tree'],target=link, name=open_tree)
                left.text("\n")
            else:
                left.link(str(sv),tooltip=link['open_tree'],target=link, name=open_tree,icon="corner.png")
                left.text("&nbsp;%s\n" % str(sv),color='black')

        right=self.__class__(self)
        path=FlagFramework.normpath(query.get('open_tree','/'))
        pane_cb(path,right)

        self.result += '''<div class="TreeLeft">%s</div><div class="TreeRight">%s</div>''' % (left,right)

    def toolbar(self,cb=None,text=None,icon=None,popup=True,tooltip=None,link=None, toolbar=None, pane='self'):
        """ Create a toolbar button.

        When the user clicks on the toolbar button, a popup window is
        created which the callback function then uses to render on.
        """
        if self.toolbar_ui==None:
            self.toolbar_ui=self.__class__(self)

        if link:
            self.toolbar_ui.link(text,target=link,icon=icon,tooltip=tooltip, pane=pane)
        elif cb:
            self.toolbar_ui.popup(cb,text,icon=icon,tooltip=tooltip, pane=pane)
        else:
            self.toolbar_ui.icon(icon,tooltip=text)

    def table(self,elements=[],table='',where='',groupby = None,case=None, **opts):
        ## Building up the args list in this way ensure that defaults
        ## can be specified in _make_sql itself and not be overwritten
        ## by our defaults.
        query = self.defaults
        try:
            pagesize = opts['pagesize']
        except:
            pagesize = config.PAGESIZE
        
        try:
            order = int(query.get('order',0))
        except: order=0

        try:    limit = int(query.get('limit',0))
        except: limit = 0

        args = dict( elements = elements, table = table, case=case,
                     groupby = groupby, order = order)

        if where: args['where'] = where

        try:    args['filter'] = query['filter']
        except: pass

        try:    args['direction'] = query['direction']
        except: pass

        sql = self._make_sql(**args)

        self.result+='''<table class="PyFlagTable" >
        <thead><tr>'''

        ## Make the table headers with suitable order by links:
        hiddens = [ int(x) for x in query.getarray('_hidden') ]
            
        for e in range(len(elements)):
            if e in hiddens: continue
            new_query = query.clone()
            n = elements[e].name

            if order==e:
                if query.get('direction','1')=='1':
                    del new_query['direction']
                    del new_query['order']
                    self.result+="<th><a href='%s&order=%s&direction=0'>%s<img src='/images/increment.png' /></a></th>\n" % (new_query,e, n)
                else:
                    del new_query['direction']
                    del new_query['order']
                    self.result+="<th><a href='%s&order=%s&direction=1'>%s<img src='/images/decrement.png' /></a></th>\n" % (new_query,e,n)
            else:
                del new_query['order']
                del new_query['direction']
                self.result+="<th><a href='%s&order=%s&direction=1'>%s</a></th>\n" % (new_query,e,n)


        self.result+='''</tr></thead><tbody class="scrollContent">'''
        
        ## Now do the rows:
        dbh = DB.DBO(case)

        ## This allows pyflag to cache the resultset, needed to speed
        ## paging of slow queries.
        dbh.cached_execute(sql,limit=limit, length=pagesize)
        old_sorted = None
        old_sorted_style = ''

        ## Total number of rows
        row_count=0

        for row in dbh:
            row_elements = []
            tds = ''

            ## Render each row at a time:
            for i in range(len(elements)):
                if i in hiddens: continue

                ## Give the row to the column element to allow it
                ## to translate the output suitably:
                value = elements[i].display(row[elements[i].name],row,self)

                ## Render the row styles so that equal values on
                ## the sorted column have the same style
                if i==order and value!=old_sorted:
                    old_sorted=value
                    if old_sorted_style=='':
                        old_sorted_style='alternateRow'
                    else:
                        old_sorted_style=''

                ## Render the sorted column with a different style
                if i==order:
                    tds+="<td class='sorted-column'>%s</td>" % (value)
                else:
                    tds+="<td class='table-cell'>%s</td>" % (value)

            self.result+="<tr class='%s'> %s </tr>\n" % (old_sorted_style,tds)
            row_count += 1

        self.result+="</tbody></table>"

        new_query = query.clone()

        ## The previous button goes back if possible:
        previous_limit = limit-pagesize
        if previous_limit<0:
            self.toolbar(icon = 'stock_left_gray.png')
        else:
            del new_query['limit']
            new_query['limit'] = previous_limit
            self.toolbar(icon = 'stock_left.png',
                         link = new_query,
                         tooltip='Previous Page (Rows %s-%s)' % (previous_limit, limit))

        ## Now we add the paging toolbar icons
        ## The next button allows user to page to the next page
        if row_count<pagesize:
            self.toolbar(icon = 'stock_right_gray.png')
        else:
            ## We could not fill a full page - means we ran out of
            ## rows in this table
            del new_query['limit']
            new_query['limit'] = limit+pagesize
            self.toolbar(icon = 'stock_right.png',
                         link = new_query,
                         tooltip='Next Page (Rows %s-%s)' % (limit, limit+pagesize))

        ## Add a skip to row toolbar icon:
        self.toolbar(
            cb = goto_row_cb,
            text="Row %s" % limit,
            icon="stock_next-page.png"
            )

        def filter_help(query,result):
            """ Print help for all operators available """
            result.heading("Available operators")
            result.para("Filter expressions consist of the syntax: column_name operator argument")
            result.para("following is the list of all the operators supported by all the columns in this table:")
            result.start_table( **{'class':'GeneralTable'})
            result.row("Column Name","Operator","Description", **{'class':'hilight'})
            for e in elements:
                tmp = result.__class__(result)
                tmp.text(e.name,color='red', font='bold')
                result.row(tmp,'','')
                for name,method_name in e.operators().items():
                    try:
                        method = getattr(e,method_name)
                        doc = method.__doc__
                    except:
                        pass
                    if not doc:
                        try:
                            ## This allows for late initialisation of
                            ## doc strings
                            doc = e.docs[method_name]
                        except:
                            doc=''
                    
                    result.row('',name, doc)

        ## Add a possible filter condition:
        def filter_gui(query, result):
            result.heading("Filter Table")
            try:
                filter_str = query['filter']
                result.para(filter_str)

                ## Check the current filter string for errors by attempting to parse it:
                try:
                    sql = parser.parse_to_sql(filter_str,elements)

                    ## This is good if we get here - lets refresh to it now:
                    if query.has_key('submit'):
                        del query['submit']
                        result.refresh(0,query,pane='parent')
                        return
                    
                except Exception,e:
                    result.text('Error parsing expression: %s' % e, color='red')
                    result.text('\n',color='black')
                    
            except KeyError,e:
                print e
                pass

            result.start_form(query, pane="self")

            result.textarea("Search Query", 'filter', cols=60)

            result.result += """<tr></tr>
            <tr><td colspan=2 align=center>The following can be used to insert text rapidly into the search string</td></tr>
            <tr><td>Column</td><td>
            <select id=filter_column>
            %s
            </select> <a href=# onclick='document.getElementById("filter").value += document.getElementById("filter_column").value;'>Insert </a></td></tr>
            """ % "\n".join(["<option value=' \"%s\" '>%s</option>" % (e.name,e.name) for e in elements if e.operators()])

            ## Round up all the possible methods from all colmn types:
            operators = {}
            for e in elements:
                for k,v in e.operators().items():
                    operators[k]=v

            methods = operators.keys()
            methods.sort()
            result.result+="""<tr><td>Operators</td><td>
            <select id=filter_operators>
            %s
            </select><a href=# onclick='document.getElementById("filter").value += document.getElementById("filter_operators").value;'>Insert </a></td></tr>
            """ % "\n".join(["<option value=' %s '>%s</option>" % (m,m) for m in methods])

            result.end_form()

            result.toolbar(cb=filter_help, text="Click here for operator help", icon='help.png')

        ## Add a toolbar icon for the filter:
        self.toolbar(cb=filter_gui, icon='filter.png',
                     tooltip=self.defaults.get('filter','Click here to filter table'))

        ## This is a toolbar popup which allows some fields to be hidden:
        def hide_fields(query, result):
            if query.has_key('submit'):
                del query['submit']
                result.refresh(0,query,pane='parent')
                return
            
            result.heading("Hide Columns")
            
            result.start_form(query, pane='self')
            for i in range(len(elements)):
                result.checkbox(elements[i].name, '_hidden', "%s" % i)

            result.end_form()

        self.toolbar(cb=hide_fields, icon='spanner.png',
                     tooltip="Hide columns")

        ## This part allows the user to save the table in CSV format:
        def save_table(query,result):
            def generate_output(rows_left):
                row_number = 0
                data = cStringIO.StringIO()
                hidden_columns = [ int(i) for i in query.getarray('_hidden')]

                names_list = [ elements[i].name for i in range(len(elements)) if i not in hidden_columns ]
                yield "#Pyflag Table widget output\n#Query was %s.\n" % query
                try:
                    yield "# Filter: %s\n" % query['filter']
                except KeyError:
                    pass

                yield "#Fields: %s\n""" % ",".join(names_list)

                csv_writer = csv.DictWriter(data,names_list,dialect='excel')

                while rows_left>0:
                ## Do the query now - we issue multiple queries
                ## because we have a better chance of hitting the
                ## cache this way.
                    rows_to_fetch = min(rows_left,100)
                    rows_left -= rows_to_fetch
                    dbh.cached_execute(sql, limit=row_number, length=rows_to_fetch)
                    count = 0
                    for row in dbh:
                        count += 1
                        row_number+=1
                        result = {}
                        for i in range(len(elements)):
                            if i in hidden_columns: continue

                            ## Allow the ColumnType to translate the data to csv suitability.
                            key = elements[i].name
                            result[key] = elements[i].csv(row[key].__str__())
                            
                        csv_writer.writerow(result)

                    if count==0: break
                    data.seek(0)
                    tmp=data.read()
                    yield tmp
                    data.truncate(0)

            if query.has_key('save_length'):            
                rows_required = int(query['save_length'])
                if rows_required==0:
                    rows_required = sys.maxint
                
                result.generator.generator = generate_output(rows_required)
                result.generator.content_type = "text/csv"
                result.generator.headers = [("Content-Disposition","attachment; filename=%s_%s.csv" %(case,table) ),]
                return

            result.heading("Save Table output")
            result.start_form(query)
            try:
                result.defaults['save_length']
            except:
                result.defaults['save_length'] = 0
                
            result.textfield("How many rows to save? (0 for all rows)", "save_length")
            result.end_form()
            
        self.toolbar(save_table,'Save Table',icon="floppy.png")

    def text(self,*cuts,**options):
        wrap = config.WRAP

        #If the user finished with this text box, we need to flush it
        if options.has_key('finish'):
            self.result += self.text_var+"</font>"
            return
        elif options.has_key('wrap_size'):
            wrap=options['wrap_size']

        def do_options(d,options):
            """ Process options """
            format = ''
            if (options.has_key('color') and options['color'] != self.color):
                format += "</font><font color=%r>" %(options['color'])
                self.color = options['color']

            if options.has_key('font') and options['font'] != self.font:
##            if options.has_key('font'):
                if options['font'] == 'typewriter':
                    format += "</pre><pre>"
                elif options['font'] == 'bold':
                    format += "</b><b>"
                elif options['font'] == 'normal':
                    format += "</b></pre>"
                self.font = options['font']

            if options.has_key('sanitise'):
                if options['sanitise'] == 'full':
                    import cgi
                    d = cgi.escape(d)
                    import re
                    d = re.sub("[\x80-\xFF\x01-\x09\x0e-\x1f\x00]",".",d)
                    d = d.replace("\t","    ")

            if options.has_key('highlight') and options['highlight']:
                self.result += "%s<span class='hilight'>%s</span>" % (format,d)
            else:
                self.result += "%s%s" % (format,d)

        for d in cuts:
            self.text_var = str(d)
            line_break="<br>\n"
            if (options.has_key('font') and options['font']=='typewriter'):
                line_break = "\n"
            else:
                self.text_var=self.text_var.replace("\n","<br>")
                
            if options.has_key('wrap') and options['wrap'] == 'full':
                for line in self.text_var.splitlines(True):
                    new_lines = textwrap.wrap(line,wrap)
                    for i in range(len(new_lines)):
                        new_line = new_lines[i]
                        do_options(new_line,options)
                        ## Only put line break if the line was
                        ## actually broken, and then not on the very
                        ## last line
                        if len(new_line)<len(line) and i<len(new_lines)-1:
                            self.result+="&nbsp;" * (wrap-len(new_line))
                            self.result+="<img src='images/next_line.png'>"
                        self.result+=line_break
                self.result+=line_break
            else:
                do_options(self.text_var,options)

    def upload_file(self, description, name, **options):
        # FIXME - Implement a proper file upload mechanism here to be
        # able to handle large files...
        """ Supply a file upload widget.

        After uploading the file, query[name] will contain the file data (We hope files are not too large at the moment).
        """
        self.textfield(description,name,type='file',**options)

    def textfield(self,description,name,**options):
        """ Draws a text field in the form.

        The text field consists of a description of the purpose of the input, and a text field. When the user enters text to the input box, the variable 'name' will be appended to the query string.

        The following options are supported:
              - Additional, This specifies that this parameter must be taken in addition to the current UI default string, rather than in its place. This is required when you need to build HTTP parameter arrays by repeating the same parameter several times in the query. Note that the default behaviour is to replace the variable name from the input.
        """
        default = ''
        try:
            if options['Additional']:
                del options['Additional']
        except KeyError:
            ## If additional was not specified, we take the default
            ## from the current value of name
            import cgi
            try:
                default = cgi.escape(self.defaults[name],quote=True)
            except KeyError:
                pass
            except AttributeError:
                default = str(self.defaults[name])
            
            ## And remove if from the form
            if self.form_parms.has_key(name):
                del self.form_parms[name]
        
        option_str = self.opt_to_str(options)
        left = description
        right = "<input name='%s' %s value='%s'>" % (name,option_str,default)
        self.row(left,right)

    def textarea(self,description,name, **options):
        """ Draws a text area with the default content

        This is very similar to the textfield above.
        """
        default = ''
        try:
            if options['Additional']:
                del options['Additional']
        except KeyError:
            ## If additional was not specified, we take the default
            ## from the current value of name
            import cgi
            try:
                default = cgi.escape(self.defaults[name],quote=True)
            except (KeyError,AttributeError):
                pass
            
            ## And remove if from the form
            if self.form_parms.has_key(name):
                del self.form_parms[name]
        
        option_str = self.opt_to_str(options)
        left = description
        right = "<textarea id='%s' name='%s' %s>%s</textarea>" % (name,name,option_str,default)
        self.row(left,right,valign="top")
        
    def start_form(self,target, pane='self', **hiddens):
        """ start a new form with a local scope for parameters.

        @arg target: A query_type object which is the target to the form. All parameters passed through this object are passed to the form's action.
        """
        self.form_parms=target.clone()
        self.form_id=self.get_unique_id()
        self.form_target = pane
        
        #Append the hidden params to the object
        for k,v in hiddens.items():
            self.form_parms[k]=v

        self.result += '<form id="pyflag_form_1" name="pyflag_form_1" method=POST action="/f" enctype="multipart/form-data">\n'

    def end_form(self,value='Submit',name='submit',**opts):
        base = ''

        ## Do not propagate __ parameters:
        for k,v in self.form_parms:
            if not k.startswith("__"):
                base += "<input type=hidden name='%s' value='%s'>\n" % (k,v)

        if value:
            base += "<input type=submit name=%s value='%s' onclick=\"submit_form(%r,%r); return false;\" %s>\n" % (name,value,self.form_target,self.callback,self.opt_to_str(opts))

        if self.table_depth>0:
            self.row(base)
        else:
            self.result+=base

        #Check to see that table tags are balanced:
        while self.table_depth>0:
            self.end_table()

        self.result+="</form>"

    def join(self,ui):
        """ Joins the supplied ui object with this object """
        self.result += ui.__str__()

    def filebox(self,dir=None,target="datafile",multiple="single"):
        """ Draws a file selector for all the files in directory dir.

        For security purposes, flag is unable to read files outside that directory.
        """
        import os
        self.result +="<select name=\"%s\" size=\"7\" multiple=\"%s\">\n" % (target,multiple)
        import cgi
        if not dir: dir=config.UPLOADDIR

        for dirpath, dirnames, filenames in os.walk(dir):
            filenames.sort()
            for filename in filenames:
                file=os.path.join(dirpath,filename)
                if (target,file) in self.defaults.q:
                    self.result+="<option value=\"%s\" selected=\"selected\">%s</option>\n" % (cgi.escape(file,quote=True),file[len(dir):])
                else:
                    self.result+="<option value=\"%s\">%s</option>\n" % (cgi.escape(file,quote=True),file[len(dir):])

        self.result += "</select><br>Files taken from %s" % (dir)
        if self.form_parms.has_key(target):
            del self.form_parms[target]
                
    def ruler(self):
        if self.table_depth:
            self.result += "<tr><td colspan=10><hr /></td></tr>\n"
        else:
            self.result += "<hr />\n"
        
    def refresh(self,interval, query, pane='self'):
        del query['time']
        query['time'] = time.time()

        if pane=='parent':
            query.poparray('callback_stored')
            
        if int(interval)>0:
            base = "window.setTimeout(function() {refresh('f?%s',%r);},%s);" % (query, pane, 1000*int(interval))
        else:
            base = "refresh('f?%s',%r);" % (query,pane)

        self.result += "<script>%s</script>" % base

    def icon(self, path, tooltip=None, **options):
        """ This allows the insertion of a small static icon picture. The image should reside in the images directory."""
        option_str = self.opt_to_str(options)
        data = "<img border=0 src='images/%s' %s />" % (path, option_str)
        if tooltip:
            data = "<abbr title='%s'>%s</abbr>" % (tooltip,data)
        self.result += data

    def wizard(self,names=[],context="wizard",callbacks=[],title=''):
        """ This implements a wizard.
        
        A wizard is a series of screens with a next/previous button to allow users to work through a process. Callbacks are called for each page. Each page is drawn inside a form, pressing the next button will submit the form, but pressing the previous button will not.
        
        Note that the results of all the forms are collected within the query object, so callers must manage the query objects by removing parameters as needed. You must ensure that the wizard callbacks generate enough parameters to display the report.
        
        Prototype for callbacks is:
        
        cb(query,result)

        The callback should draw on the result using the parameters in query.
        The return value of cb is boolean, true indicating that this page is ok, and we should continue to the next page, while false indicates an error condition, and the page is redisplayed. Note that it is the callbacks responsibility to indicate what has gone wrong to the user.
        """
        def wizard_cb(query,result):
            """ This callback is responsible for managing the wizard popup window """
            result.title="Pyflag Wizard %s" % title
            try:
                page=int(query[context])
            except:
                page=0
                
            result.heading(names[page])
            new_query=query.clone()
            del new_query[context]
            del new_query['submit']
            
            result.start_form(new_query)
            result.start_table()

            ## Ask the cb to draw on us: (We do not want the cb to stuff
            ## with our form_parms so we create an empty ui)
            tmp=result.__class__(query=query)
            if query.has_key('submit'):
                if callbacks[page](new_query,tmp):
                    page+=1
            ## This is the last page and it was ok - we just go to our parent page
                    if query['submit']=='Finish':
                        del new_query['callback_stored']
                        result.refresh(0,new_query,parent=1)
                        return
                else:
                    self.text("There was an error with the form:",color="red")

            ## This time we want to properly display the form
            tmp=result.__class__(result)
            tmp.defaults=query
            callbacks[page](new_query,tmp)
            result.row(tmp)

            ## Add the form elements as hidden parameters:
            result.hidden(context,page)
            for k,v in result.form_parms:
                result.result += "<input type=hidden name='%s' id='%s' value='%s'>\n" % (k,k,v)

            result.end_table()
            if page>0:
                result.result+="<input type=button value=Previous onclick=\"window.location=\'%s&%s=%s\';\" />" % (new_query,context,page-1)
            ## Make the update button
            result.result += "<input type=submit value='Update'>"

            if page<len(names)-1:
                result.result += "<input type=button value='Next' onclick=\"document.getElementById(\'%s\').value=\'%s\'; document.pyflag_form_1.submit();\" >\n" % (context, page+1)
            elif page==len(names)-1:
                result.result += "<input type=submit value='Finish' name=submit>\n"

            result.decoration='naked'

        cb = self.store_callback(wizard_cb)
        self.result+="""<script language=javascript>var client; function open_wizard_window() {window.open('%s&%s=0&callback_stored=%s','client','toolbar=0,menubar=0,HEIGHT=600,WIDTH=800,scrollbars=yes')}; open_wizard_window(); </script><abbr title=\"If your browser blocks popups, click here to popup a wizard\"><a onclick=\"open_wizard_window()\">Click here to launch wizard</a></abbr>""" % (self.defaults,context,cb)
        raise FlagFramework.DontDraw()
                
    def notebook(self,names=[],context="notebook",callbacks=[],
                 descriptions=[], callback_args=[]):
        """ Draw a notebook like UI with tabs.

        If no tab is selected, the first tab will be selected.

        @arg names: A list of names for each tab
        @arg callbacks: A list of callbacks to call for each name
        @arg context: A context variable used to allow the selection of names in queries
        @arg descriptions: A list of descriptions to assign to each tab. The description should not be longer than 1 line.
        """
        query=self.defaults.clone()            
        try:
            context_str=query[context]
            index = names.index(context_str)
            cbfunc=callbacks[index]
        except (ValueError,KeyError):
            cbfunc=callbacks[0]
            context_str=names[0]
            index=0

        out = '\n<div class="NotebookContainer"><div class=Tablist>'
        for i in names:
            q=query.clone()
            del q[context]
            q[context]=i

            if(i==context_str):
                out+="<div class='TabActive'><span>%s</span></div>\n" % i
            else:
                out+="<div class='Tab' onclick='document.location=\"f?%s\"'><span>%s</span></div>\n" % (q,i)
        
##        out='\n<div id="notebook"><ul id="topmenu">'
        
##        for i in names:
##            q=query.clone()
##            del q[context]
##            q[context]=i
##            tmplink = '''<a class="tab" href="%s">%s</a>''' % (q,i)

##            if(i==context_str):
##                out+="<li><a class='tabactive'>%s</a></li>\n" % i
##            else:
##                out+="<li>%s</li>\n" % tmplink

##        out+="</ul>"
        
        #Now draw the results of the callback:
        result=self.__class__(self)
        try:
            option = callback_args[index]
            cbfunc(query,result, option)
        except IndexError:
            cbfunc(query,result)

        id=self.get_unique_id()
        
        out+="</div>\n<div class='TabContent' id='Notebook%s'>%s</div></div>\n" % (id,result)
        self.result+=out + "<script>AdjustHeightToPageSize('Notebook%s');</script>" % id

    def get_unique_id(self):
        self.id+=1
        return self.id

    def raw(self, html):
        """ Allows the insertion of raw html into the GUI

        Other UIs will just ignore this.

        This should be avoided whenever possible.
        """
        self.result+=html

    ## FIXME: Do this properly.
    def sanitise_data(self,data):
        """ Return a sanitised version of data. This is mostly to
        avoid XSS attacks etc.

        Note that PyFlag currently does not have much in the way of
        XSS protections or access controls and should not be used on
        the open web without authentication.
        """
        allowed_tags = [ "b","i", "br" ]
        tag_regex = "<([^>]+)>"

        def filter_tag(tag):
            tag = tag.group(1)
            tmp = tag.strip().lower()
            if tmp.startswith("/"):
                extra="/"
                tmp = tmp[1:]
            else: extra =''

            tmp = tmp.split(" ")[0]

            for allowed in allowed_tags:
                if tmp==allowed:
                    return "<%s%s >" % (extra,allowed)
            return ''

        return re.sub(tag_regex, filter_tag, data)

