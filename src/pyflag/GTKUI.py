# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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

""" GTKUI Module

The output within flag is abstracted such that it is possible to connect any GUI backend with any GUI Front end. This is done by use of UI objects. When a report runs, it will generate a UI object, which will be built during report execution. The report then returns the object to the calling framework which will know how to handle it. Therefore the report doesnt really know or care how the GUI is constructed

This module implements a GTK UI model which is intended to work with the FlagGTKServer implementation.
"""

import re,cgi,types
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.conf
import pyflag.UI as UI
config=pyflag.conf.ConfObject()
import gtk,gobject,pango,gtk.gdk
import pyflag.Registry as Registry
import re

#config.LOG_LEVEL=7

class GTKUI_Exception(Exception):
    """ This exception is raised when we want to draw a form """

pointer=gtk.gdk.Cursor(gtk.gdk.HAND2)

### Some helper functions:
def destroy_window_cb(widget,event):
    widget.get_parent_window().destroy()

## This is the tree model used for building trees in flag.
class FlagTreeModel(gtk.GenericTreeModel):
    '''This class represents the model of a tree.

    FLAG trees are built using a callback, so it is not necessary to represent the entire tree in memory at runtime, only the branches which are currently open are used.
    '''
    TREE_DEPTH = 4
    TREE_SIBLINGS = 5
    def __init__(self,callback,pane_cb,base):
        '''constructor for the model.

        callback is a generator used to receive items for opening leaves:
        def tree_cb(branch)

        where branch is a tuple representing the different branch hirarchy required to be enumerated.
        the callback needs to yield a tuple of (name,value,state). For more information see UI.tree.
        '''
        gtk.GenericTreeModel.__init__(self)
        self.callback=callback
        self.pane_cb=pane_cb
        ## Here we cache the results inside the data model. For each index we are required to expand, we store a list of tuples associated with the index in a dictionary. We start with an empty cache:
        self.cache={}
        self.base=base
        self._cache_cb(())     
        
    ## the implementations for TreeModel methods are prefixed with on_
    def on_get_flags(self):
        '''returns the GtkTreeModelFlags for this particular type of model'''
        return 0

    def on_get_n_columns(self):
        '''returns the number of columns in the model'''
        return 1

    def on_get_column_type(self, index):
        '''returns the type of a column in the model'''
        return gobject.TYPE_STRING

    def on_get_path(self, node):
        '''returns the tree path
        (a tuple of indices at the various levels) for a particular node.'''
        return node

    def on_get_iter(self, path):
        '''returns the node corresponding to the given path.
        
        In our case, the node is the path'''
        return path

    def on_get_value(self, path, column):
        '''returns the value stored in a particular column for the node'''
        assert column == 0
        branch=path[:-1]
        index=path[-1]

        try:
            return self.cache[branch][index][0]
        except (KeyError,IndexError):
            return None

    def on_iter_next(self, path):
        '''returns the next node at this level of the tree'''
        branch=path[:-1]
        index=path[-1]

        try:
            ## Get the cached results from the callback
            results=self.cache[branch]
            if index>=len(results)-1:
                return None
            return branch+(index+1,)
        except KeyError:
            ## Calculate the results for this node
            self._cache_cb(branch)
            if len(self.cache[branch])==0 or self.cache[branch][0][0]==None:
                return None

            return branch+(index+1,)
    
    def on_iter_children(self, node):
        '''returns the first child of this node'''
        if node == None: # top of tree
            return (0,)
        return node + (0,)

    def path_from_node(self,node):
        """ Returns  a tuple representing the tree from node coordinates """
        path = self.base + [ self.cache[tuple(node[:i])][node[i]][0] for i in range(len(node)) ]
        return path[1:]
    
    def _cache_cb(self,branch):
        if branch==():
            self.cache[branch]=[("/",None,'branch')]
            return
        
        path=self.path_from_node(branch)
        self.cache[branch]=[ d for d in self.callback(path[1:]) if d[0] ]
        if len(self.cache[branch])==0 or self.cache[branch][0][0]==None:
            self.cache[branch]=[("(empty)",None,'leaf')]

    def on_iter_has_child(self, node):
        '''returns true if this node has children'''
        branch=node[:-1]
        index=node[-1]

        try:
            if not self.cache.has_key(branch):
                self._cache_cb(branch)

            if self.cache[branch][index][2]=='branch':
                return True
            else:
                return False
        except (IndexError,KeyError):
            return False
        
    def on_iter_n_children(self, node):
        '''returns the number of children of this node'''
        if node==None: return 1
        
        branch=node[:-1]
        index=node[-1]
        
        try:
            ## Get the cached results from the callback
            results=self.cache[branch]
            return len(results)
        except KeyError:
            return None
        
    def on_iter_nth_child(self, node, n):
        '''returns the nth child of this node'''
#        if node == None:
#            return (n,)
        ## I have no idea what this does, but it stops nasty GTK warnings (MC)
        return (n,)
        
    def on_iter_parent(self, node):
        '''returns the parent of this node'''

        if len(node) == 0:
            return None
        else:
            return node[:-1]

class FlagToolbar(gtk.HBox):
    """ Flag Toolbar class.

    Toolbars are areas for GTKUIs to draw tool button on.
    There is only one application toolbar on the server window, but recursive UIs all need to draw on it. Therefore all UI get access to the toolbar object when they get created.
    There are a number of UIs which manager these toolbars, e.g. notebook and tree views. By managing the toolbar we mean that these widgets are able to add and remove toolbar icons from their children depending on which is exposed. For example if we have a notebook with a table in one page and something else in the other page, the notebook needs to update its toolbar as pages are changed.
    This implementation has toolbars forming a tree, with the root toolbar owned by the server. As each management widget hides and redraws new UIs, they remove the toolbars from the tree and splice other ones in.
    """
    def __init__(self,tparent):
        gtk.HBox.__init__(self)
        self.tchildren = []
        self.tparent = tparent
        self.tparent.add_toolbar_child(self)
        
    def add_toolbar(self,button):
        """ Adds a button to this toolbar. """
        self.pack_start(button,False,False)
        button.show_all()

    def add_toolbar_child(self,child):
        """ Add child to this toolbar """
        self.tchildren.append(child)
        
    def destroy_toolbar(self):
        """ Disassociate this toolbar from its parents.

        Ask our parent to remove us from their list """
        self.tparent.delete(self)

    def delete(self, child):
        """ Remove this child from our list """
        del self.tchildren[self.tchildren.index(child)]
        self.redraw()

    def redraw(self):
        """ Ask our parent to redraw us """
        self.tparent.redraw()

    def install(self, hbox):
        """ When the parent is ready, they can ask us to draw our children on this hbox """
        hbox.pack_start(self,False,False)
        for c in self.tchildren:
            c.install(hbox)
        self.show_all()

class FlagNotebook(gtk.Notebook):
    """ A Flag notebook class.

    The Flag notebook needs to manage a bunch of toolbar related stuff along with the notebook"""
    def __init__(self, ui):
        gtk.Notebook.__init__(self)
        self.ui = ui # master (parent) toolbar
        self.toolbars = {}
        self.views = {}
        self.callbacks = {}
        self.queries = {}
        self.names = {}
        self.switchid=self.connect("switch-page", self.switch)
        self.curpage=None
        self.page_id=0

    def remove_page(self,page):
        if self.curpage!=None:
            self.toolbars[self.curpage].destroy_toolbar()
        self.curpage=None        
        gtk.Notebook.remove_page(self,page)
        
    def get_page_with_id(self,page_id):
        """ Gets the page widget for the specified id

        Page id are given to pages as they are created sequentially. When pages are destroyed, the IDs are used to map pages to their respective slots in the notebook.
        """
        for tested_page in range(0,self.page_id):
            w=self.get_nth_page(tested_page)
            if w.get_data('page_id')==page_id:
                return tested_page
        
    def switch(self, notebook, p, pagenum):
        """ This is called whenever the user switched from one page to the next.

        We check that the new page has been drawn. If it has not been drawn we draw it by calling the relevant callback. This just in time approach makes the notebook very fast.
        Note that once a UI has been generated for the page, we cache that and will not need to redraw this page again.
        """
        # just-in-time page drawing stuff
        p = self.get_nth_page(pagenum)
        page_id=p.get_data('page_id')
        if not self.views.has_key(page_id):
            # create and store a new toolbar for UI to use - Each page
            # has a toolbar parented at our own toolbar
            self.toolbars[page_id] = FlagToolbar(self.ui.ftoolbar)

            # Create a new UI for the page to be drawn on - toolbar buttons are drawn on our private toolbar
            result = pyflag.GTKUI.GTKUI(self.ui, query=self.queries[page_id],ftoolbar=self.toolbars[page_id])
            try:
                self.callbacks[page_id](self.queries[page_id],result)
            except Exception,e:
                self.ui.server.error_popup(e)
                return
            
            self.views[page_id]=result.display()
            p.add_with_viewport(self.views[page_id])
            p.show_all()
            
        else:
            ## add the toolbar as a child to our own toolbar
            self.ui.ftoolbar.add_toolbar_child(self.toolbars[page_id])

        # just do toolbar swapping, rip out old toolbar by asking it
        if self.curpage != None:
            self.toolbars[self.curpage].destroy_toolbar()

        ## Force toolbars to be redrawn
        self.ui.ftoolbar.redraw()

        ## Remember current page so we can remove this toolbar when page changes
        self.curpage=page_id

    def add_page(self, name, callback, query):
        """ add a new tab with given label

        This function creates a new tab by storing the callback and query. Note that the page is not drawn until we switch to it.
        """
        # each new page goes in a scrolled window
        self.disconnect(self.switchid)
        scroll = gtk.ScrolledWindow()
        scroll.set_data('page_id',self.page_id)
        idx = self.page_id
        self.page_id+=1
        scroll.set_policy(gtk.POLICY_AUTOMATIC,gtk.POLICY_AUTOMATIC)
        
        self.callbacks[idx] = callback
        self.names[idx] = name
        self.queries[idx] = query
        
        self.append_page(scroll, gtk.Label(name))
        self.switchid=self.connect("switch-page", self.switch)
        return idx
                

class GTKUI(UI.GenericUI):
    """ A GTK UI Implementation.

    This is the main UI implementation for GTK. It is different from the HTML UI because in the HTML UI we can count on the server to retransmit the results of the forms each time the user clicks submit. Here, we dont have the same request/response model like HTTP, so we must manager our own widgets. This leads to lots of callbacks and much more complex code :-(.

    We still use the query as a way of passing parameters around though.
    """
    def __init__(self,default = None,query=None,server=None,ftoolbar=None):
        # Create the Main Widget
        self.result=gtk.VBox()
        
        # Inherit properties
        if default != None:
            self.form_parms = default.form_parms
            self.defaults = default.defaults
            ## This is an array of form widgets. Every time we draw a form widget in this UI, we store it here, and then when we submit the widget, we take the values from here.
            self.form_widgets=default.form_widgets
            self.tooltips = default.tooltips
            self.ftoolbar = default.ftoolbar
            self.server=default.server
        else:
            self.form_parms = {}
            self.defaults = FlagFramework.query_type(())
            self.form_widgets=[]
            self.tooltips = gtk.Tooltips()
            self.ftoolbar=None

        ## Overriding keyword args
        if ftoolbar:
            self.ftoolbar = ftoolbar

        if server:
            self.server=server
        
        if query:
            self.defaults=query

        ## It is critical that we have access to our server, It is now
        ## illegal to instatiate new UIs like this:
        ## tmp =result.__class__()
        ##
        ## You must do this:
        ## tmp=result.__class__(result)
        ##    
        ## Or an exception will sound!!!
        assert(self.server)
        assert(self.ftoolbar)
        
        self.current_table=None
        self.current_table_options={}
        self.next = None
        self.previous = None
        self.pageno = 0
        self.widgets = []
        self.title = None
        return

    def heading(self,string):
        self.title = string
        
    def refresh(self, int, query):
        print "Will refresh to %s" % query
        self.server.process_query(query)

    def link_callback(self,query):
        """ Calls the server to add a new page with the given query """
        self.server.process_query(query)

    def __str__(self):
        """ This method should not be used directly by reports.

        There was a bad habbit, while using the HTML UI, to get access to the raw HTML data by calling this method. This is not legal and is no longer supported!!!

        It breaks this UI (and other future UIs), and goes against the spirit of UI abstraction.
        """
        return "GTKUI Widget"
    
    def display(self):
        ## Did the user forget to call end_table??? 
        if self.current_table:
            self.end_table()

        if self.title:
            frame = gtk.Frame(self.title)
            frame.set_label_align(0.5,0.5)
            frame.set_border_width(5)
            #frame.set_shadow_type(gtk.SHADOW_OUT)
            frame.add(self.result)
            return frame
        return self.result

    def start_table(self,**options):
        if self.current_table==None:
            # I'm confused, should we allow nested tables in the *same* UI object?
            # No. UI objects can nest in tables, not tables directly nest in UI objects (MC)
##            self.current_table=gtk.Table(1,1,False)
##            self.current_table.set_border_width(5)
##            self.current_table.set_homogeneous(False)
##            self.current_table_row=0
            self.current_table_size=[0,0]
            self.current_table=[]
            self.current_table_opts=[]
        self.current_table_options.update(options)
            
    def row(self,*columns, **options):
#        print "Adding columns %s %s" % (columns,len(columns))
        if self.current_table==None:
            self.start_table()

        ## Add an extra row on the end
        self.current_table_size[0]+=1
        if self.current_table_size[1]<len(columns):
            self.current_table_size[1]=len(columns)

##        self.current_table_row+=1
##        self.current_table.resize(self.current_table_row,len(columns))
##        if self.current_table_size[1]<len(columns):
##            self.current_table_size[1]=len(columns)
            
##        self.current_table_size[0]=self.current_table_row
        column_widgets=[]
        for i in range(len(columns)):
            col=columns[i]
            ## If this column is a string, (and therefore not a GTK
            ## Widget), we create a new widget for it
            if isinstance(col,self.__class__):
##                col=col.display()
                frame=gtk.Frame()
                frame.add(col.display())
                col=frame
            elif not isinstance(col,gtk.Widget):
                if 1:
                    t="%s" % col
                    l = gtk.Label(t)
                    l.set_justify(gtk.JUSTIFY_LEFT)
                    l.set_line_wrap(True)
                    col = gtk.Alignment(0,0,0,1)
                    col.add(l)
                else:
                    l=gtk.TextView()
                    l.set_editable(False)
                    l.set_cursor_visible(False)
                    lb = l.get_buffer()
                    l.set_wrap_mode(gtk.WRAP_WORD)
                    #                l.set_wrap_mode(gtk.WRAP_NONE)
                    lb.set_text("%s"%col)
                    col=l
            column_widgets.append(col)
            
        ##Attach the column to row at the end of the table:
        self.current_table.append(column_widgets)
        self.current_table_opts.append(options)
##            right_attach = i+1            
##            if options.has_key('colspan'):
##                print "Colspan %s" % options['colspan']
##                right_attach = i+options['colspan']
##                if right_attach>self.current_table_size[1]:
##                    right_attach=self.current_table_size[1]
##                print right_attach,self.current_table_size

##            if options.has_key('stretch'):
##                if options['stretch']:
##                    stretch =gtk.EXPAND | gtk.FILL | gtk.SHRINK
##                else:
##                    stretch = 0
##            else:
##                stretch = gtk.EXPAND | gtk.FILL

##            self.current_table.attach(col, i, right_attach, self.current_table_row-1, self.current_table_row,gtk.EXPAND | gtk.FILL, stretch, 0, 0)

    def end_table(self):
        table=gtk.Table(self.current_table_size[0],self.current_table_size[1],homogeneous=False)
        table.set_border_width(5)
        for row_index in range(len(self.current_table)):
            row=self.current_table[row_index]
            options=self.current_table_opts[row_index]
            stretch = gtk.EXPAND | gtk.FILL
            try:
                if not options['stretch']:
                    stretch = 0
            except:
                pass
                    
            hstrech=gtk.EXPAND | gtk.FILL
            try:
                if not options['hstrech']:
                    hstrech=0
            except:
                pass

            table_hstretch=True
            try:
                table_hstretch=self.current_table_options['hstretch']
            except:
                pass
            
            for i in range(len(row)):
                col=row[i]
                right_attach=i+1
#                print "%s %s %s" % (i,len(row),self.current_table_size)
                if len(row)<self.current_table_size[1] and i==len(row)-1:
                    right_attach=self.current_table_size[1]
#                print "Attaching to %s %s %s %s" % (i,right_attach,row_index,row_index+1)
                table.attach(col, i,right_attach, row_index,row_index+1,hstrech, stretch, 0, 0)

        ## Add the table to the result UI:
#        frame=gtk.Frame("table %s" % (self.current_table_size,))
#        frame.add(table)

        if table_hstretch:
            self.result.pack_start(table,True,True)
        else:
            hbox=gtk.HBox()
            hbox.pack_start(table,False,False)
            self.result.pack_start(hbox,True,True)
            
##            self.result.pack_start(self.current_table,True,True)
        self.current_table=None
        self.current_table_options={}
##            self.start_table()
            
    def goto_link(self,widget,event,target):
        """ This is the callback function from links

        If the target report does not have all its parameters - we should invoke the form for it here - this is different than the html ui since the HTML UI passes the link request into the server again. Here we dont, so we need to do same here.
        
        @arg target: A query object specifying where to go to.
        """
        ## Only respond to left clicks
        try:
            if event.button !=1: return
        except:
            pass

        self.server.process_query(target)

    def tooltip(self, string):
        """ redundant, never used """
        pass
        
    def icon(self, path, **options):
        image = gtk.Image()
        image.set_from_file("%s/%s" % (config.IMAGEDIR, path))
        self.row(image,stretch=False)

    def image(self, image, **options):
        pass

    def create_popup_window(self):
        """ Create a new window and render ourselves in it """
        self.server.create_window(self.display())
        
    def popup(self,callback, label,icon=None,toolbar=0, menubar=0, **options):
        pass

    def ruler(self):
        """ Ruler, spans all columns """
        ruler = gtk.HSeparator()
        self.row(ruler, colspan=50,stretch=False)

    def checkbox(self,description,name,value,**options):
        """ Create a checkbox input for the name,value pair given. """
        checkbox = gtk.CheckButton(description)
        checkbox.set_data('name',name)
        checkbox.set_data('value',value)
        if value in self.defaults.getarray(name):
            checkbox.set_active(True)

        def callback(widget):
            if widget.get_active():
                return (widget.get_data('name'),widget.get_data('value'))
            else:
                pass

        self.form_widgets.append((checkbox,callback))
        self.row(checkbox,stretch=False)

    def notebook(self,names=[],context="notebook",callbacks=[],descriptions=[]):
        """ Draw a notebook like UI with tabs.

        If no tab is selected, the first tab will be selected. Tabs are selected by specifying a page number in query[context].

        @arg names: A list of names for each tab
        @arg callbacks: A list of callbacks to call for each name
        @arg context: A context variable used to allow the selection of names in queries
        @arg descriptions: A list of descriptions to assign to each tab. The description should not be longer than 1 line.
        """
        query=self.defaults.clone()
        ## If the user supplied a tab which should be open by default
        try:
            context_str=query[context]
        ## Otherwise we open the first one by default
        except:
            context_str=names[0]
            
        notebook = FlagNotebook(self)
        for i in range(len(names)):
            notebook.add_page(names[i],callbacks[i],query)
            
        self.result.pack_start(notebook,True,True)
        notebook.set_current_page(names.index(context_str))

    def link(self,string,target=FlagFramework.query_type(()),**target_options):
        """ This method simulates a link by using an event box around a label.

        Clicking the even box will call the link callback. This is a little hack because clicking anywhere within the event box will cause a link to fire - not necessarily on the text.
        """
        target=target.clone()
        if target_options:
            for k,v in target_options.items():
                target[k]=v

        ## Create an eventbox to catch the click event
        ev=gtk.EventBox()
        
        if isinstance(string,self.__class__):
            label=string.display()
        elif not isinstance(string,gtk.Widget):
            l=gtk.Label()
            l.set_markup("<span foreground=\"blue\" style=\"italic\" underline=\"single\">%s</span>"%string)
            label = gtk.Alignment(0,0,0,0)
            label.add(l)
        else: label=string
            
        ev.set_data('query',target)    
        ev.add(label)
        ev.add_events(gtk.gdk.BUTTON_PRESS_MASK)
        ev.connect("button_press_event",self.goto_link,target)
        self.row(ev,stretch=False)

    def const_selector(self,description,name,keys,values,**options):
        combobox = gtk.combo_box_new_text()
        combobox.set_data('name',name)
        idx = len(values)
        for v in values:
            combobox.append_text(v)
            try:
                if self.form_parms[name]==v:
                   combobox.set_active(len(values)-idx)
                   idx = -2
            except KeyError:
                pass
            idx -= 1
        if idx > -1:
            combobox.set_active(idx)
        
        def callback(widget):
            model = widget.get_model()
            active = widget.get_active()
            if active < 0:
                active = 0
            try:
                value=model[active][0]
                for k,v in zip(keys,values):
                    if value==v:
                        return (widget.get_data('name'), k)
                    
            except IndexError:
                pass

        self.form_widgets.append((combobox,callback))
        self.row(description,combobox,stretch=False)

    def start_form(self,target, **hiddens):
        for k,v in hiddens.items():
            self.form_parms[k]=v
            
        for k in target.q:
            self.form_parms[k[0]]=k[1]

    def textfield(self,description,name,**options):
        widget=gtk.Entry()
        widget.set_data('name',name)
        try:
            widget.set_text(self.defaults[name])
        except KeyError:
            pass

        def callback(widget):
            return (widget.get_data('name'),widget.get_text())

        self.form_widgets.append((widget,callback))
        self.row(description,widget,stretch=False)

    def submit(self,widget,event=None,data=None):
        new_query=FlagFramework.query_type(())
        # case comes set by default, dont know why
        # but is screws things up here
        del new_query['case']

        for widget,callback in self.form_widgets:
            parameter=callback(widget)
            try:
                if parameter[0]:
                    # the default case keeps coming back!!!
                    # FIXME: find out where it comes from
                    try:
                        if parameter[0] == 'case' and new_query['case']:
                            continue
                    except KeyError:
                        pass
                    new_query[parameter[0]]=parameter[1]
            except TypeError:
                pass
#        print "DEBUG: Submitting Form, new_query is: %s" % new_query
        self.link_callback(new_query)

    def end_form(self,name='Submit',toplevel_window=None):
        def callback(a):
            return (a,self.form_parms[a])

        for k in self.form_parms.keys():
            self.form_widgets.append((k,callback))
            
        ok=gtk.Button(label="Submit",stock=gtk.STOCK_OK)
        ok.connect("button_press_event",self.submit)
        if toplevel_window:
            cancel=gtk.Button(label="Cancel",stock=gtk.STOCK_CANCEL)
            cancel.connect("button_press_event",lambda x,y: toplevel_window.hide())
            self.row(ok,cancel,stretch=False)
        else: self.row(ok,stretch=False)

    text_widget = None
    text_widget_buffer = None
    text_widget_iter=None

    def create_tags(self, text_buffer):
        """Create a bunch of tags. Note that it's also possible to
        create tags with gtk.text_tag_new() then add them to the
        tag table for the buffer, text_buffer.create_tag() is
        just a convenience function. Also note that you don't have
        to give tags a name; pass None for the name to create an
        anonymous tag.
        
        In any real app, another useful optimization would be to create
        a GtkTextTagTable in advance, and reuse the same tag table for
        all the buffers with the same tag set, instead of creating
        new copies of the same tags for every buffer.

        Tags are assigned default priorities in order of addition to the
        tag table. That is, tags created later that affect the same text
        property affected by an earlier tag will override the earlier
        tag. You can modify tag priorities with
        gtk.text_tag_set_priority().
        """

        import pango
        text_buffer.create_tag("font_heading",
                               weight=pango.WEIGHT_BOLD,
                               size=15 * pango.SCALE)
        
        text_buffer.create_tag("font_italic", style=pango.STYLE_ITALIC)
        text_buffer.create_tag("font_normal", style=pango.STYLE_NORMAL)

        text_buffer.create_tag("font_bold", weight=pango.WEIGHT_BOLD)
        
        # points times the pango.SCALE factor
        text_buffer.create_tag("big", size=20 * pango.SCALE)
        
        text_buffer.create_tag("xx-small", scale=pango.SCALE_XX_SMALL)
        
        text_buffer.create_tag("x-large", scale=pango.SCALE_X_LARGE)
        
        text_buffer.create_tag("font_typewriter", family="monospace")
        
        text_buffer.create_tag("color_red", foreground="red")
        text_buffer.create_tag("color_blue", foreground="blue")
        text_buffer.create_tag("color_black", foreground="black")
        
        text_buffer.create_tag("red_background", background="red")
                
        text_buffer.create_tag("big_gap_before_line", pixels_above_lines=30)
        
        text_buffer.create_tag("big_gap_after_line", pixels_below_lines=30)
        
        text_buffer.create_tag("double_spaced_line", pixels_inside_wrap=10)
        
        text_buffer.create_tag("not_editable", editable=False)
        
        text_buffer.create_tag("wrap_full", wrap_mode=gtk.WRAP_WORD)
        
        text_buffer.create_tag("char_wrap", wrap_mode=gtk.WRAP_CHAR)
        
        text_buffer.create_tag("wrap_none", wrap_mode=gtk.WRAP_NONE)
        
        text_buffer.create_tag("center", justification=gtk.JUSTIFY_CENTER)
        
        text_buffer.create_tag("right_justify", justification=gtk.JUSTIFY_RIGHT)
        
        text_buffer.create_tag("wide_margins",
                               left_margin=50, right_margin=50)
        
        text_buffer.create_tag("strikethrough", strikethrough=True)
        
        text_buffer.create_tag("underline",
                               underline=pango.UNDERLINE_SINGLE)
        
        text_buffer.create_tag("double_underline",
                               underline=pango.UNDERLINE_DOUBLE)
        
        text_buffer.create_tag("superscript",
                               rise=10 * pango.SCALE, # 10 pixels
                               size=8 * pango.SCALE) #  8 points
        
        text_buffer.create_tag("subscript",
                               rise=-10 * pango.SCALE, # 10 pixels
                               size=8 * pango.SCALE) #  8 points
        
        text_buffer.create_tag("rtl_quote",
                               wrap_mode=gtk.WRAP_WORD, direction=gtk.TEXT_DIR_RTL,
                               indent=30, left_margin=20, right_margin=20)
        
        
    def text(self,*cuts,**options):
        tags=[]
        
        if not self.text_widget:
            self.text_widget=gtk.TextView()
            self.text_widget.set_editable(False)
            self.text_widget.set_cursor_visible(False)
            self.text_widget_buffer = self.text_widget.get_buffer()
            self.text_widget.set_wrap_mode(gtk.WRAP_WORD)
            self.create_tags(self.text_widget_buffer)
            self.text_widget_iter = self.text_widget_buffer.get_iter_at_offset(0)
            self.result.pack_start(self.text_widget,False,False)
            #self.row(self.text_widget)

        ##Fix up the options:
        possible_options=('color','font','wrap')
        for opt in possible_options:
            if options.has_key(opt):
                tags.append("%s_%s"%(opt,options[opt]))

        for d in cuts:
            if not d:
                continue
            elif isinstance(d,gtk.Widget):
                child=self.text_widget_buffer.create_child_anchor(self.text_widget_iter)
                self.text_widget.add_child_at_anchor(d,child)
            elif isinstance(d,self.__class__):
                widget=d.display()
                child=self.text_widget_buffer.create_child_anchor(self.text_widget_iter)
                self.text_widget.add_child_at_anchor(widget,child)
                #self.row(widget)
            else:
                self.text_widget_buffer.insert_with_tags_by_name(self.text_widget_iter,d,*tags)

    def para(self,string,**options):
        #FIXME, whats the difference between 'para' and 'text'
        self.text(string, font='heading')
        #self.buffer.insert_with_tags_by_name(self.iter,string+"\r\n\r\n",'text')

    def filebox(self,dir=None,target="datafile",multiple="single"):
        f=gtk.FileSelection()

        def choose_file(widget,event):
#            f=widget.get_data('filedialog')
            file=f.get_filename()
            label=f.get_data('label')
            label.set_markup(file)
            f.hide()

        def hide_box(widget,event):
#            f=widget.get_data('filedialog')
            f.hide()

        def callback(widget,event):
            file=widget.get_data('filewidget')
            file.show()

        def get_my_filename(widget):
            return (target,widget.get_text())
        
        f.ok_button.set_data('filedialog',f)
        f.ok_button.connect("button_press_event",choose_file)
        f.cancel_button.connect("button_press_event",hide_box)
        f.set_filename(config.UPLOADDIR)

        button=gtk.Button("Choose file")
        button.set_data('filewidget',f)
        button.connect("button_press_event",callback)
        try:
            label=gtk.Label(self.form_parms[target])
        except KeyError:
            label=gtk.Label("")
            
        f.set_data('label',label)
#        del self.form_parms[target]
        self.form_widgets.append((label,get_my_filename))
        self.row(label,'   ',button,stretch=False)
        try:
            del self.form_parms[target]
        except KeyError:
            pass

    def link_callback_ui(self, action, query):
        """ wrapper function to satisfy clicked signal callback prototype """
        self.link_callback(query)

    def toolbar(self, cb=None, text=None, icon=None, popup=False, tooltip=None, stock=None,link=None):
        """ Add an item to the toolbar
        cb may be a query item rather than a callback
        in which case the query is run by flag and the results displayed in the pane

        popup determines in the page will be opened in a new notebook page, or in a special popup window.
        """
        def proxy_cb(widget, cb, result, query):
            if popup:
                result=self.__class__(self)
                if cb(query,result):
                    self.create_window(result.display())
            else:
                self.server.notebook.add_page(result, cb,query)
        
        i = None
        if icon:
            i = gtk.Image()
            i.set_from_file('%s/%s' % (config.IMAGEDIR, icon))
            i.show()
            button = gtk.ToolButton(icon_widget=i, label=text)
        elif stock:
            button = gtk.ToolButton(stock)
        else:
            button = gtk.ToolButton(icon_widget=None, label=text)

        if not tooltip: tooltip=text
        button.set_tooltip(self.tooltips, tooltip)

        if link:
            button.connect('clicked',  self.goto_link,link)
        else:
            button.connect('clicked', proxy_cb, cb, self, self.defaults)
            
        self.ftoolbar.add_toolbar(button)

    def table(self,sql="select ",columns=[],names=[],links=[],table='',where='1',groupby = None,case=None,callbacks={},**opts):
        """ Main table redered method.

        The GTK Table widget is automatically refreshed by clicking it - rather than refreshing the entire page as is the case with the HTML UI. Hence it manages its own callbacks etc.
        """
        names=list(names)
        
        # Get a new SQL generator for building the table with.
        generator,new_query,names,columns,links = self._make_sql(sql=sql,columns=columns,names=names,links=links,table=table,where=where,groupby = groupby,case=case,callbacks=callbacks,**opts)
        if not new_query: new_query=self.defaults

        try:
            if not groupby:
                groupby=self.defaults['group_by']
        except KeyError:
            groupby=None

        ## All columns are strings in here...
        store=gtk.ListStore(*tuple([gobject.TYPE_STRING] * len(names)))

        def populate_store(store,generator,names):
            store.clear()
            count=0
            for row in generator:
                iter = store.append()
                x=[iter]
                for i in range(len(names)):
                    x.append(i)
                    x.append(str(row[names[i]]))

                store.set(*x)
                count+=1
            return count

        ## Add filter to toolbar as well
        self.toolbar(cb=
                     lambda query,result: search_menu_popup(None,None),
                     text="Add filter to table",
                     stock=gtk.STOCK_ADD,
                     popup=True
                     )
        
        ##### Callback functions for Table right click menus ######
        def right_button_menu(treeview, event):
            """ Callback to render the right click menu """
            if event.button == 3:
                x = int(event.x)
                y = int(event.y)
                time = event.time
                pthinfo = treeview.get_path_at_pos(x, y)
                try:
                    column = pthinfo[1]
                except:
                    column=None
                
                if pthinfo != None:
                    path, col, cellx, celly = pthinfo
                    treeview.grab_focus()
                    treeview.set_cursor( path, col, 0)

                menu=gtk.Menu()

                if column:
                    ## Get row content:
                    model=treeview.get_model()
                    iter=model.get_iter(path)
                    data=model.get_value(iter,column.get_data('column_number'))

                    ## Search menu entry
                    search_menu=gtk.MenuItem("Add filters on Table")
                    search_menu.connect("activate",search_menu_popup,column,data)
                    menu.add(search_menu)

                    ## Group by menu entry
                    groupby_menu=gtk.MenuItem("Count Unique items")
                    def groupby_menu_popup(widget,column):
                        """ Launch the groupby popup.

                        This popup displays the group by table in the popup and creates links to the original store
                        """
                        query=self.defaults.clone()
                        query['group_by']=column.get_title()
                        result=self.__class__(self,query=query)
                        print "Will group by on %s" % column.get_title()
                        result.table(columns=columns,names=names,table=table,where=where,groupby=groupby,case=case,callbacks=callbacks,**opts)
                        self.server.create_window(result.display())

                    groupby_menu.connect("activate",groupby_menu_popup,column)
                    menu.add(groupby_menu)

                    menu.add(gtk.SeparatorMenuItem())

                ## Add all currently enforced filter conditions:
                def remove_filter_condition(widget,index):
                    """ Callback to remove a specific filter condition as found in the right click menu """
                    del self.filter_text[index]
                    del self.filter_conditions[index]
                    if len(self.filter_conditions):
                        new_where = "%s and %s" % (where,' and '.join(self.filter_conditions))
                        print "my where is ",where,new_where
                    else: new_where=where

                    ## Update the store with the new data
                    generator,new_query,x,y,z = self._make_sql(sql=sql,columns=columns,names=names,links=links,table=table,where=new_where,groupby = groupby,case=case,callbacks=callbacks,**opts)
                    populate_store(store,generator,names)

                for i in range(len(self.filter_conditions)):
                    m=gtk.MenuItem("remove %s" % self.filter_text[i])
                    m.connect("activate",remove_filter_condition,i)
                    menu.add(m)

                if len(self.filter_conditions) or column:
                    menu.show_all()
                    menu.popup( None, None, None, event.button, time)
                    return 1
            return 0

        def search_menu_popup(widget,column,data='',table=None):
            """ Launch the filter on column popup window

            This popup can be launched from the right click menu as well as from the toolbar.
            If launched from the right click menu we already know which column we filter on (by getting the position where the click occured). Otherwise we have a checkbox for that.
            """
            result=self.__class__(self)
            result.heading("Add filter condition")
            result.text("Add a new filter condition to column ")
            combobox=None
            if column:
                result.text(column.get_title()+'\n',color='red',font='bold')
            else:
                hbox=gtk.HBox(False,8)
                combobox=gtk.combo_box_new_text()
                for c in treeview.get_columns():
                    combobox.append_text(c.get_data('name'))
                hbox.pack_start(gtk.Label("Column to filter:"))
                hbox.pack_start(combobox)
                result.row(hbox,stretch=False)
                
            text_entry = gtk.Entry()
            text_entry.set_text(data)
            result.row(text_entry,stretch=False)
            widget=gtk.Button("Submit",stock=gtk.STOCK_OK)
            if column:
                column_name=columns[names.index(column.get_title())]
                column_title=column.get_title()
            else:
                column_name=None
                column_title=None

            widget.connect("button_press_event", process_filter_cb,column_name, column_title, text_entry, store,combobox)
            result.row(widget,stretch=False)
            dialog=result.create_popup_window()
            text_entry.grab_focus()

        def process_filter_cb(widget,event,column_name,column_title,filter_str_widget,store,comboname):
            """ Filter the data in the store, enforcing filter conditions chosen by right click menu """
            parent=widget.get_parent_window()
            ## If comboname is given, we need to read the column_name,
            ## column_title from the combo box
            if comboname:
                active=comboname.get_active()
                if active<0:
                    tmp = self.__class__(self)
                    tmp.heading("Error")
                    tmp.text("You must choose a column to filter on")
                    self.server.create_window(tmp.display(),gtk.STOCK_DIALOG_ERROR)
                    return

                column_name=columns[active]
                column_title=names[active]
                
            ## Work out which column we are working on (column widget)
            for c in treeview.get_columns():
                if c.get_data('name')==column_title:
                    column=c
                    break

            try:
                self.filter_text.append(FlagFramework.make_sql_from_filter(filter_str_widget.get_text(),self.filter_conditions,column_name,column.get_title()))
            except IndexError:
                widget.get_parent_window().destroy()
                return

            new_where = ' and '.join(['1']+self.filter_conditions)
            print "my where is ",where,new_where

            ## Update the store with the new data
            generator,new_query,x,y,z = self._make_sql(sql=sql,columns=columns,names=names,links=links,table=table,where=new_where,groupby = groupby,case=case,callbacks=callbacks,**opts)
            populate_store(store,generator,names)
            widget.get_parent_window().destroy()

        populate_store(store,generator,names)
        ## Create a new widget
        treeview = gtk.TreeView(store)
        treeview.set_rules_hint(True)

        treeview.connect('button-press-event',right_button_menu)
        
##        ## callback for all the links:
##        def table_link_callback(widget,event=None):
##            """ Get the query object from the widget and refresh to it, after appending various form parameters. """
##            q=widget.get_data('query')
##            for widget,callback in self.form_widgets:
##                parameter=callback(widget)
##                if parameter[0]=='group_by' and parameter[1]!='':
##                    q['group_by']=parameter[1]
##            self.link_callback(q)

        def column_callback(column,event=None):
            store=column.get_data('store')
            name=column.get_data('name')
            number=column.get_data('number')
            self.sort[2].set_sort_indicator(False)
            self.sort[-1]=column
            self.sort[0]=number
            column.set_sort_indicator(True)
            if self.sort[1]=='order':
                column.set_sort_order(gtk.SORT_ASCENDING)
                self.sort[1]='dorder'
            else:
                column.set_sort_order(gtk.SORT_DESCENDING)
                self.sort[1]='order'

            ## Get new SQL iterator:
            generator,new_query,x,y,z = self._make_sql(sql=sql,columns=columns,names=names,links=links,table=table,where=where,groupby = groupby,case=case,callbacks=callbacks)

            populate_store(store,generator,names)

        # add nav toolitems directly to the toolbar
        prev_button = gtk.ToolButton(gtk.STOCK_GO_BACK)
        next_button = gtk.ToolButton(gtk.STOCK_GO_FORWARD)

        def previous_cb(widget):
            del self.defaults['limit']
            self.defaults['limit']=self.previous
            self.previous-=config.PAGESIZE
            if self.previous<0:
                self.previous=0
                self.next=self.previous+config.PAGESIZE
                prev_button.set_sensitive(False)

            ## Get new SQL iterator:
            generator,new_query,x,y,z = self._make_sql(sql=sql,columns=columns,names=names,links=links,table=table,where=where,groupby = groupby,case=case,callbacks=callbacks)
            
            count=populate_store(store,generator,names)
            if count==config.PAGESIZE:
                next_button.set_sensitive(True)
            else: next_button.set_sensitive(False)
                
#            return result

        def next_cb(widget):
            old_next=self.next
            del self.defaults['limit']
            self.defaults['limit']=self.next
            self.next+=config.PAGESIZE
            ## Get new SQL iterator:
            generator,new_query,x,y,z = self._make_sql(sql=sql,columns=columns,names=names,links=links,table=table,where=where,groupby = groupby,case=case,callbacks=callbacks)
            self.defaults=new_query
            count=populate_store(store,generator,names)
            if count<config.PAGESIZE:
                self.next=old_next
                next_button.set_sensitive(False)
            else: next_button.set_sensitive(True)

            if self.next>0:
                prev_button.set_sensitive(True)

        prev_button.set_tooltip(self.tooltips, 'Go to Previous Page')
        prev_button.connect('clicked', previous_cb)
        self.ftoolbar.add_toolbar(prev_button)
#        self.ftoolbar.insert(prev_button, 0)
        next_button.set_tooltip(self.tooltips, 'Go to Next Page')
        next_button.connect('clicked', next_cb)
        self.ftoolbar.add_toolbar(next_button)
        previous_cb(None)

        # add to a scrolled window
        sw = gtk.ScrolledWindow()
        sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        sw.add(treeview)
        self.result.pack_start(sw, True, True)

        ## Add the columns to the widget
        for i in range(len(names)):
            renderer=gtk.CellRendererText()
            column = gtk.TreeViewColumn(names[i], renderer,text=i)
            column.set_resizable(True)
            column.set_clickable(True)
            column.set_reorderable (True)
            column.set_data('number',i)
            try:
                if links[i]:
                    column.set_data('link',links[i])
                    renderer.set_property('foreground','blue')
                    renderer.set_property('underline','single')
            except (KeyError,IndexError):
                pass
            
            q=new_query.clone()

            ## Make the ordered column headers
            if i==self.sort[0]:
                self.sort.append(column)
                column.set_sort_indicator(True)
                if self.sort[1]=='order':
                    column.set_sort_order(gtk.SORT_ASCENDING)
                    del q['dorder']
                    q['dorder']=names[i]
                else:
                    column.set_sort_order(gtk.SORT_DESCENDING)
                    del q['order']
                    q['order']=names[i]
            else:
                q['order']=names[i]
                
            column.set_data('query',q)
            column.set_data('store',store)
            column.set_data('column_number',i)
            column.set_data('name',names[i])
            column.connect('clicked',column_callback)
            treeview.append_column(column)

        treeview.columns_autosize()
        self.table_widget=treeview

        def click_callback(widget,event):
            """ This callback is for emulating links within tables """
            ## Only respond to left click here
            if event.button!=1: return
            x,y = (event.x,event.y)
            try:
                path,column,cellx,celly = widget.get_path_at_pos(int(x),int(y))
                ## This is a workaround GTK - if we click on the column headers we get an event here..
                if x<10: return
            except:
                return
            q=column.get_data('link')
            
            if q:
                model=widget.get_model()
                iter=model.get_iter(path)
                new_query = q.clone()
                target=new_query['__target__']
                del new_query['__target__']
                del new_query[target]
                new_query[target] = model.get_value(iter,column.get_data('column_number'))
                self.link_callback(new_query)
                
        treeview.connect('button-press-event',click_callback)                    

    def tree(self,tree_cb = None, pane_cb=None, branch = ('/'),layout='horizontal'):
        """ This tree uses the FlagTreeModel to represent the data.

        @arg tree_cb: is a callback required to enumerate the tree branches as they are being manipulated. This is used by the data store model (FlagTreeModel).
        @arg pane_cb: is a callback to render the pane. The pane located to the right of the tree and updates each time a new node is clicked on.
        """
        hbox=gtk.HPaned()
        sw = gtk.ScrolledWindow()
        #hbox.set_size_request(800, 400)
        sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        hbox.add1(sw)
        
        model=FlagTreeModel(tree_cb,pane_cb,branch)
        treeview = gtk.TreeView(model)
        sw.add(treeview)
        
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("tree", cell, text=0)
        treeview.append_column(column)

        def selection_changed(selection):
            treeview = selection.get_tree_view()
            model, iter  = selection.get_selected()

            ## Destroy old toolbar
            try:
                self.tree_toolbar.destroy_toolbar()
            except:
                pass

            ## Create a new toolbar for child UI
            self.tree_toolbar=FlagToolbar(self.ftoolbar)
            result=self.__class__(self, ftoolbar=self.tree_toolbar)
                
            try:
                path=model.get_path(iter)
                ## Call the pane callback with the selected item
                path=model.path_from_node(path)
                if path[-1]!="(empty)":
                    pane_cb(path,result)
            except TypeError:
                pane_cb('/',result)
                
            ## Rip the widget from result and stick it in place of the old instance
            try:
                hbox.remove(self.right_pane)
            except AttributeError:
                pass

            ## Force a redraw of the new toolbar
            self.ftoolbar.redraw()
            self.right_pane=gtk.ScrolledWindow()
            self.right_pane.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
            self.right_pane.add_with_viewport(result.display())
            hbox.add2(self.right_pane)
            hbox.show_all()

        selection = treeview.get_selection()
        selection_changed(selection)
                
        selection.set_mode(gtk.SELECTION_SINGLE)
        selection.connect('changed', selection_changed)
        self.result.pack_start(hbox,True,True)
        hbox.set_position(200)

    def download(self,file):
        self.text("Click the button below to save the file to disk")
        button=gtk.Button("Save As")
        self.row(button,stretch=False)
        
        def button_cb(widget,event):
            f=gtk.FileSelection("Save File as")
            f.set_filename("%s/%s" % (config.RESULTDIR,file.inode))

            def choose_file(widget,event):
                fd=open(f.get_filename(),'w')
                for data in file:
                    fd.write(data)

                destroy_window_cb(widget,event)

            f.ok_button.connect("button_press_event",choose_file)
            f.cancel_button.connect("button_press_event",destroy_window_cb)
            f.show_all()

        button.connect("button_press_event",button_cb)

    def image(self,image,**options):
        """ Draw the image inside this GTKUI """
        pixbuf_loader=gtk.gdk.PixbufLoader()
        data=image.display()
        pixbuf_loader.write(data)
        pixbuf_loader.close()
        pixbuf=pixbuf_loader.get_pixbuf()
        pix = gtk.Image()
        pix.set_from_pixbuf(pixbuf)

        self.row(pix)

    def wizard(self,names=None,callbacks=None):
        """ Draws a wizard displaying the callbacks one at the time.

        prototype for callbacks is cb(query,result)
        """
        box=gtk.VBox()
        sw=gtk.ScrolledWindow()
        sw.set_policy(gtk.POLICY_AUTOMATIC,gtk.POLICY_AUTOMATIC)
        fbut=gtk.ToolButton(gtk.STOCK_GO_FORWARD)
        bbut=gtk.ToolButton(gtk.STOCK_GO_BACK)
        query=self.defaults.clone()
        query['page']=0

        def process_click(result,query):
            """ Updates query by adding the parameters specified by result's form_widgets """
            print result.form_widgets
            for widget,callback in result.form_widgets:
                parameter=callback(widget)
                print "parameter %s" % (parameter,)
                del query[parameter[0]]
                query[parameter[0]]=parameter[1]

        def check_callback(page):
            """ Checks if the form rendered ok. Returns true if the form was ok, false if it needs to be refilled """
            result=self.__class__(server=self.server,ftoolbar=self.ftoolbar,query=query)
            error_state=callbacks[page](query,result)
            if not error_state:
                print "There was an error with the form %s" % query
                result.text("There was an error with the form",color="red")
            
            return error_state
        
        def draw_wizard_cb(widget=None,page=0):
            """ Draw the page specified inside the wizard. """
            result=self.__class__(server=self.server,ftoolbar=self.ftoolbar,query=query)
            callbacks[page](query,result)
                
            child=sw.get_child()
            if child:
                sw.remove(child)
            sw.add_with_viewport(result.display())
            sw.show_all()
            return result
        
        def process_wizard_page(widget=None,page=0,result=None):
            if page==len(names)-1:
                process_click(result,query)
                self.refresh(0,query)
                wizard_box.destroy()
                print "finishing"
                return

            print "processing page %s %s" % (page,len(names))
            if result:
                process_click(result,query)
                
            ## Were we called from the button press?
            if widget:
                ## Is this page good?
                if check_callback(page):
                    result=draw_wizard_cb(widget,page+1)
                    ## Set the next click button to direct to the next page
                    fbut.disconnect(fbut.get_data('clicked'))
                    print "setting callback to page %s" % page
                    fbut.set_data('clicked',fbut.connect('clicked',process_wizard_page,page+1,result))
                    return

            result=draw_wizard_cb(page)
            print "setting callback to page %s" % page
            try:
                fbut.disconnect(fbut.get_data('clicked'))
            except TypeError:
                pass

            fbut.set_data('clicked',fbut.connect('clicked',process_wizard_page,page,result))

        process_wizard_page(page=0)
        box.pack_start(sw,True,True)
        hbox=gtk.HButtonBox()
        hbox.set_layout(gtk.BUTTONBOX_EDGE)
        hbox.add(bbut)
        hbox.add(fbut)
        box.pack_start(hbox,False,False)
        wizard_box=self.server.create_window(box)
        raise FlagFramework.DontDraw()

##    def case_selector(self,case='case',message='Case:', **options):
##        """ In the GTK window we use the case as chosen using the case selector on the tool bar for all reports. """
##        combo=self.server.case_selector_combo
##        model = combo.get_model()
##        active = combo.get_active()
##        def case_cb(widget):
##            if active==0: return ('case',None)
##            return ('case',model[active][0])
        
##        self.row("Current case:",model[active][0])
##        if active>0:
##            del self.defaults['case']
##            self.defaults['case']=model[active][0]
##        self.form_widgets.append((1,case_cb))
