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
#  Version: FLAG $Version: $
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

import re,cgi,types
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.conf
import pyflag.UI as UI
config=pyflag.conf.ConfObject()
import gtk,gobject,pango,gtk.gdk
from gtk import TRUE, FALSE

#config.LOG_LEVEL=7

pointer=gtk.gdk.Cursor(gtk.gdk.HAND2)

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
        return path
    
    def _cache_cb(self,branch):
        path=self.path_from_node(branch)
        self.cache[branch]=[ d for d in self.callback(path) ]
        if len(self.cache[branch])==0 or self.cache[branch][0][0]==None:
            self.cache[branch]=[("",None,'leaf')]

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
        branch=node[:-1]
        index=node[-1]
        try:
            ## Get the cached results from the callback
            results=self.cache[branch]
            return len(results)
        except KeyError:
            return 0
        
    def on_iter_nth_child(self, node, n):
        '''returns the nth child of this node'''
        return
        if node == None:
            return (n,)

        print node
        results=self.cache[node]
        return results[n][0]
        
    def on_iter_parent(self, node):
        '''returns the parent of this node'''

        if len(node) == 0:
            return None
        else:
            return node[:-1]

class GTKUI(UI.GenericUI):
    """ A GTK UI Implementation. """
    def __init__(self,default = None):
        # Create the Main Widget
        self.result=gtk.VBox()

        # Inherit properties
        if default != None:
            self.form_parms = default.form_parms
            self.defaults = default.defaults
            ## This is an array of form widgets. Every time we draw a form widget in this UI, we store it here, and then when we submit the widget, we take the values from here.
            self.form_widgets=default.form_widgets
        else:
            self.form_parms = {}
            self.defaults = FlagFramework.query_type(())
            self.form_widgets=[]
            
        self.current_table=None
        self.nav_query=None
        self.widgets = []
        self.title = None
        return

    def heading(self,string):
        self.title = string
        
    def refresh(self, int, query):
        pass

    def __str__(self):
        return self.display()
#        return "GTKUI Widget"
    
    def display(self):
        ## Did the user forget to call end_table??? Dumb user!!!
        if self.current_table:
            self.end_table()
        if self.title:
            frame = gtk.Frame(self.title)
            frame.add(self.result)
            return frame
        return self.result

    def start_table(self,**options):
        if not self.current_table:
            # I'm confused, should be allow nested tables in the *same* UI object?
            self.current_table=gtk.Table(1,1,False)
            self.current_table_row=0

    def row(self,*columns, **options):
        if not self.current_table:
            self.start_table()

        ## Add an extra row on the end
        self.current_table_row+=1
        self.current_table.resize(self.current_table_row,len(columns))
        for i in range(len(columns)):
            try:
                col=columns[i]
            ## If this column is a string, (and therefore not a GTK Widget), we create a new widget for it
                if isinstance(col,self.__class__):
                    col=col.display()
                elif not issubclass(col.__class__,gtk.Widget):
                    col = gtk.Label("%s" % col)
                    col.set_justify(gtk.JUSTIFY_LEFT)
                    col.set_line_wrap(gtk.TRUE)
            except AttributeError:
                col = gtk.Label("%s" % col)
                col.set_justify(gtk.JUSTIFY_LEFT)
                col.set_line_wrap(gtk.TRUE)
                
                
            ##Attach the column to row at the end of the table:
            right_attach = i+1            
            if options.has_key('colspan'):
                right_attach = i+options['colspan']
            self.current_table.attach(col, i, right_attach, self.current_table_row-1, self.current_table_row, gtk.FILL|gtk.EXPAND, 0, 0, 0)

    def end_table(self):
        ## Add the table to the result UI:
        if self.current_table:
            self.result.pack_start(self.current_table, False)
            self.current_table=None

    def goto_link(self,widget,event):
        if self.link_callback:
            self.link_callback(widget.get_data('query'))

    def tooltip(self, string):
        pass
    
    def toolbar(self, popup, string, icon):
        pass
    
    def icon(self, path, **options):
        image = gtk.Image()
        image.set_from_file("%s/%s" % (config.IMAGEDIR, path))
        self.row(image)

    def image(self, image, **options):
        pass

    def popup(self,callback, label,icon=None,toolbar=0, menubar=0, **options):
        pass

    def ruler(self):
        """ Ruler, spans all columns """
        ruler = gtk.HSeparator()
        self.row(ruler, colspan=50)

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
        self.row(checkbox)

    def notebook(self,names=[],context="notebook",callbacks=[],descriptions=[]):
        """ Draw a notebook like UI with tabs.

        If no tab is selected, the first tab will be selected.

        @arg names: A list of names for each tab
        @arg callbacks: A list of callbacks to call for each name
        @arg context: A context variable used to allow the selection of names in queries
        @arg descriptions: A list of descriptions to assign to each tab. The description should not be longer than 1 line.
        """
        query=self.defaults.clone()
        ## If the user supplied a context (a tab which should be open by default)
        try:
            context_str=query[context]
        ## Otherwise we open the first one by default
        except:
            context_str=names[0]
            
        self.notebook_views= {}
        
        def switch_cb(notepad, page, pagenum, callbacks, query):
            p = notepad.get_nth_page(pagenum)
            if not self.notebook_views.has_key(pagenum):
                self.notebook_views[pagenum]=callbacks[pagenum](query).display()
                p.pack_start(self.notebook_views[pagenum])
                p.show_all()
            
        # draw the notebook
        notebook = gtk.Notebook()
        notebook.connect('switch-page', switch_cb, callbacks, query)
        for name in names:
            notebook.append_page(gtk.VBox(), gtk.Label(name))
            
        self.result.pack_start(notebook)
                
    def link(self,string,target=FlagFramework.query_type(()),**target_options):
        target=target.clone()
        if target_options:
            for k,v in target_options.items():
                target[k]=v

        ## Create an eventbox to catch the click event
        ev=gtk.EventBox()
        label=gtk.Label()
        label.set_markup("<span foreground=\"blue\" style=\"italic\" underline=\"single\">%s</span>"%string)
        ev.set_data('query',target)
        ev.add(label)
        ev.add_events(gtk.gdk.BUTTON_PRESS_MASK)
        ev.connect("button_press_event",self.goto_link)
        self.row(ev)
        #child=self.buffer.create_child_anchor(self.iter)
        #self.result.add_child_at_anchor(ev,child)

    def const_selector(self,description,name,keys,values,**options):
        combobox = gtk.combo_box_new_text()
        combobox.set_data('name',name)
        idx = len(values)
        for v in values:
            combobox.append_text(v)
            try:
                if self.form_parms[name]==v:
                   #print "form_parms already has %s -> %s" % (name,self.form_parms[name])
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
                return (widget.get_data('name'), model[active][0])
            except IndexError:
                pass

        self.form_widgets.append((combobox,callback))
        self.row(description,combobox)

    def start_form(self,target, **hiddens):
        for k,v in hiddens:
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
        self.row(description,widget)

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
        #print "DEBUG: Submitting Form, new_query is: %s" % new_query
        self.link_callback(new_query)

    def end_form(self,name='Submit'):
        def callback(a):
            return (a,self.form_parms[a])

        for k in self.form_parms.keys():
            self.form_widgets.append((k,callback))
            
        widget=gtk.Button("Submit")
        widget.connect("button_press_event",self.submit)
        self.text("\r\n",widget)

    def text(self,*cuts,**options):
        for d in cuts:
            if not d:
                continue
            elif isinstance(d,gtk.Widget):
                #child=self.buffer.create_child_anchor(self.iter)
                #self.result.add_child_at_anchor(d,child)
                self.row(d)
            elif isinstance(d,self.__class__):
                widget=d.display()
                #child=self.buffer.create_child_anchor(self.iter)
                #self.result.add_child_at_anchor(widget,child)
                self.row(widget)
            else:
                label = gtk.Label(d)
                label.set_line_wrap(gtk.TRUE)
                label.set_justify(gtk.JUSTIFY_LEFT)
                self.row(label)
                #self.buffer.insert_with_tags_by_name(self.iter,d,'text')

    def para(self,string,**options):
        #FIXME, whats the difference between 'para' and 'text'
        self.text(string, options)
        #self.buffer.insert_with_tags_by_name(self.iter,string+"\r\n\r\n",'text')

    def filebox(self,dir=None,target="datafile",multiple="single"):
        f=gtk.FileSelection()

        def choose_file(widget,event):
            f=widget.get_data('filedialog')
            file=f.get_filename()
            print "You chose %s" % file
            label=f.get_data('label')
            label.set_markup(file)
            f.hide()

        def hide_box(widget,event):
            file=widget.get_data('filewidget')
            file.hide()

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
            label=gtk.Label(self.defaults[target])
        except KeyError:
            label=gtk.Label("")
            
        f.set_data('label',label)
#        del self.form_parms[target]
        self.form_widgets.append((label,get_my_filename))
        self.text(label,'   ',button)
        try:
            del self.form_parms[target]
        except KeyError:
            pass

    def _make_sql(self,sql="select ",columns=[],names=[],links=[],table='',where='',groupby = None,case=None,callbacks={},**opts):
        """ An SQL generator for the table widget (private) """
        #in case the user forgot and gave us a tuple, we forgive them:
        names=list(names)
        columns = list(columns)

        #First work out what is the query string:
        query_str = sql;
        query = self.defaults
        
        #The new_query is the same one we got minus all the UI specific commands. The following section, just add UI specific commands onto the clean sheet
        new_query = query.clone()
        del new_query['dorder']
        del new_query['order']
        del new_query['limit']

        #find the group by clause - if we get a group by clause we need to change the rest of the query so heavily that we need check the group by last.
        if not groupby:
            group_by_str = ",".join([ " `%s`" % d for d in query.getarray('group_by') ])
            if group_by_str:
                 #If we have a group by, we actually want to only show a count and those columns that are grouped by, so we over ride columns and names...
                 #Mask contains those indexes for which names array matches the group_by clause
                 try:
                     mask = [ names.index(d) for d in query.getarray('group_by') ]
                     links = [None]+ [ self.make_link(query,"where_%s" % names[d],target_format="=%s") for d in mask ]
                     for d in links:
                         if d:
                             #For links we dont want these variables to be there
                             del d['group_by']
                             del d['limit']

                     names = ['Count'] + [ names[d] for d in mask ]
                     columns = [ 'count(*)' ] +  [ columns[d] for d in mask ]

                     #Note that you cant have a group_by and a having clause together - so if you get a group_by we drop the having conditions
                     for d in query.keys():
                         if d.startswith('where_'):
                             del query[d]
                        
                 #if the user asked for a weird group by , we ignore it.
                 except ValueError:
                     group_by_str = None
        else:
            group_by_str = groupby

        #Form the columns in the sql
        tmp = [ k+ " as `" +v+"`" for (k,v) in zip(columns,names) ]
            
        query_str+=",".join(tmp) 

        #Form the table and where clause
        query_str+=" from %s " % table

        #Work out the having clause.
        having=['1']
        conditions=[]
        for d,v in query:
            if d.startswith('where_'):
                #Find the column for that name
                try:
                    index=names.index(d[len('where_'):])
                except ValueError:
                    ## If we dont know about this name, we ignore it.
                    continue
                        
                if v.startswith('=') or v.startswith('<') or v.startswith('>'):
                    ## If the input starts with !, we do an exact match
                    having.append("%s %s %r " % (columns[index],v[0],v[1:]))
                    condition_text="%s %s %s" % (d[len('where_'):],v[0],v[1:])
                elif v.find('%')>=0:
                    #If the user already supplied the %, we dont add our own:
                    having.append("%s like %r " % (columns[index],v.replace('%','%%')))
                    condition_text="%s like %s" % (d[len('where_'):],v)
                elif v[0] == '!':
                    #If the user already supplied the %, we dont add our own:
                    having.append("%s not like %r " % (columns[index],"%%%%%s%%%%"% v[1:]))
                    condition_text="%s not like %s" % (d[len('where_'):],"%%%s%%" % v[1:])
                else:
                    ## Otherwise we do a fuzzy match. 
                    having.append("%s like %r " % (columns[index],"%%%%%s%%%%"% v))
                    condition_text="%s like %s" % (d[len('where_'):],"%%%s%%" % v)

                #Create a link which deletes the current variable from the query string, allows the user to remove the current condition:
                tmp_query=query.clone()
                tmp_query.remove(d,v)
                tmp_link=self.__class__(self)
                tmp_link.link(condition_text,target=tmp_query)
                conditions.append(tmp_link)

        having_str = " and ".join(having)

        if where:
            query_str+= " where (%s) and (%s) " %(where,having_str)
        elif having:
            query_str+=" where %s " % having_str
            
        if group_by_str:
            query_str += " group by %s " % group_by_str

        #Find the order by clause - We look at self.sort to establish which column needs to be sorted. We assume self.sort is correctly initialised first.
        print self.sort
        if self.sort[1]=='order':
            order= " `%s` asc " % names[self.sort[0]]
        else:
            order= " `%s` desc " % names[self.sort[0]]

        print "order is %s" % order
        query_str+= " order by %s " % order

        #Calculate limits
        if not query.has_key('limit'):
            query['limit'] = "0"

        self.previous = int(query['limit']) - config.PAGESIZE
        if self.previous<0: self.previous=0

        print "setting self.previous to %s" % self.previous
        self.next = int(query['limit']) + config.PAGESIZE
        self.pageno =  int(query['limit']) /config.PAGESIZE
                
        query_str+=" limit %s, %s" % (int(query['limit']) , config.PAGESIZE)

        dbh = DB.DBO(case)

        #Do the query, and find out the names of all the columns
        dbh.execute(query_str,())
        return dbh,new_query

    def toolbar(self,cb,text,icon=None,popup=True):
        pass

    def table(self,sql="select ",columns=[],names=[],links=[],table='',where='',groupby = None,case=None,callbacks={},**opts):
        """ Main table redered method.

        The GTK Table widget is automatically refreshed by clicking it - rather than refreshing the entire page as is the case with the HTML UI. Hence it manages its own callbacks etc.
        """
        ## Establish the sorting order
        try:
            self.sort=[list(names).index(self.defaults['order']),'order']
        except KeyError:
            try:
                self.sort=[self.defaults['dorder'],'dorder']
            except KeyError:
                self.sort=[0,'order']

        # Get a new SQL generator for building the table with.
        generator,new_query = self._make_sql(sql=sql,columns=columns,names=names,links=links,table=table,where=where,groupby = groupby,case=case,callbacks=callbacks,**opts)
        if not new_query: new_query=self.defaults

        try:
            groupby=self.defaults['group_by']
            print "Group by is %s" % groupby
        except KeyError:
            groupby=None
        
        ## All columns are strings in here...
        store=gtk.ListStore(*tuple([gobject.TYPE_STRING] * len(names)))

        for row in generator:
            iter = store.append()
            x=[iter]
            for i in range(len(names)):
                x.append(i)
                x.append(str(row[names[i]]))
                
            store.set(*x)

        ## Create a new widget
        treeview = gtk.TreeView(store)
        treeview.set_rules_hint(TRUE)

        def page_cb(widget,event=None):
            """ Call back for pagination """
            store=widget.get_data('store')
            dir=widget.get_data('direction')
            q=widget.get_data('query')
            self.defaults=q
            
            ## Get new SQL iterator:
            generator,new_query = self._make_sql(sql=sql,columns=columns,names=names,links=links,table=table,where=where,groupby = groupby,case=case,callbacks=callbacks)

            self.previous = int(q['limit']) - config.PAGESIZE
            if self.previous<0: self.previous=0

            ## Update the navigation buttons
            del q['limit']
            q['__target__']='limit'
            self.right_button.set_data('query',self.FillQueryTarget(q,self.next))
            self.left_button.set_data('query',self.FillQueryTarget(q,self.previous))

            ## Refresh the store with new data
            store.clear()
            for row in generator:
                iter = store.append()
                x=[iter]
                for i in range(len(names)):
                    x.append(i)
                    x.append(str(row[names[i]]))

                store.set(*x)

            
        ## callback for all the links:
        def link_callback(widget,event=None):
            """ Get the query object from the widget and refresh to it, after appending various form parameters. """
            q=widget.get_data('query')
            for widget,callback in self.form_widgets:
                parameter=callback(widget)
                if parameter[0]=='group_by' and parameter[1]!='':
                    q['group_by']=parameter[1]
            self.link_callback(q)

        def column_callback(column,event=None):
            store=column.get_data('store')
            name=column.get_data('name')
            number=column.get_data('number')
            self.sort[2].set_sort_indicator(FALSE)
            self.sort[-1]=column
            self.sort[0]=number
            column.set_sort_indicator(TRUE)
            if self.sort[1]=='order':
                column.set_sort_order(gtk.SORT_ASCENDING)
                self.sort[1]='dorder'
            else:
                column.set_sort_order(gtk.SORT_DESCENDING)
                self.sort[1]='order'

            ## Get new SQL iterator:
            generator,new_query = self._make_sql(sql=sql,columns=columns,names=names,links=links,table=table,where=where,groupby = groupby,case=case,callbacks=callbacks)

            store.clear()
            for row in generator:
                iter = store.append()
                x=[iter]
                for i in range(len(names)):
                    x.append(i)
                    x.append(str(row[names[i]]))

                store.set(*x)

            ## Update the navigation buttons
            q=self.right_button.get_data('query')
            del q['limit']
            q['limit']=0
            self.right_button.set_data('query',q)
            self.left_button.set_data('query',q)

        ## Create buttons for navigation: FIXME: This code should really be in the application window's toolbar, and be global for the entire app.
        if not self.nav_query:
            q = self.defaults.clone()          
            q['__target__']='limit'
            
        left=gtk.Button("Previous")
        left.set_data('query',self.FillQueryTarget(q,self.previous))
        left.set_data('store',store)
        left.connect("clicked",page_cb)
        self.left_button=left

        right=gtk.Button("Next")
        self.right_button=right
        right.set_data('query',self.FillQueryTarget(q,self.next))
        right.set_data('store',store)
        right.set_data('direction','forward')
        right.connect("clicked",page_cb)

        ## Attach the widget to the result canvas
        self.text(left,right,'\r\n')
        self.text(treeview)

        ## Create a group by selector
        tmp=self.__class__(self)
        tmp.const_selector("Group by a column: ",'group_by',['None']+list(names),['']+list(names))
        self.text('\r\n',tmp)

        ## Add the columns to the widget
        for i in range(len(names)):
            renderer=gtk.CellRendererText()
            column = gtk.TreeViewColumn(names[i], renderer,text=i)
            column.set_resizable(TRUE)
            column.set_clickable(TRUE)
            column.set_reorderable (TRUE)
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
                column.set_sort_indicator(TRUE)
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
            x,y = (event.x,event.y)
            path,column,cellx,celly = widget.get_path_at_pos(int(x),int(y))
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

    def tree(self,tree_cb = None, pane_cb=None, branch = ('/')):
        """ This tree uses the FlagTreeModel to represent the data.

        @arg tree_cb: is a callback required to enumerate the tree branches as they are being manipulated. This is used by the data store model (FlagTreeModel).
        @arg pane_cb: is a callback to render the pane. The pane located to the right of the tree and updates each time a new node is clicked on.
        """
        hbox=gtk.HPaned()
        sw = gtk.ScrolledWindow()
        hbox.set_size_request(800, 400)
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
            path=model.get_path(iter)
            ## Call the pane callback with the selected item
            print model.path_from_node(path)
            result=self.__class__()
            pane_cb(model.path_from_node(path),result)

            ## Rip the widget from result and stick it in place of the old instance
            try:
                hbox.remove(self.right_pane)
            except AttributeError:
                pass

            
            self.right_pane=gtk.ScrolledWindow()
#            self.right_pane.set_size_request(400, 400)
            self.right_pane.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
            self.right_pane.add_with_viewport(result.display())
            hbox.add2(self.right_pane)
            hbox.show_all()

        selection = treeview.get_selection()
        selection.set_mode(gtk.SELECTION_SINGLE)
        selection.connect('changed', selection_changed)
        self.text(hbox)
