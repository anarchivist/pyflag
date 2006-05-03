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
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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

import re,cgi,types,textwrap
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.conf
import pyflag.UI as UI
config=pyflag.conf.ConfObject()
import pyflag.Theme as Theme
import cStringIO,csv
import pyflag.Registry as Registry

class HTMLException(Exception):
    """ An exception raised within the UI - should not escape from this module """

class HTTPObject:
    def __init__(self):
        self.content_type=None
        self.generator=None
        self.headers=None


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
    result.start_form(query, refresh="parent")
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

    name = "HTMLUI"
    tree_id = 0
    store_dict = {}
    callback_dict = {}
    callback_time_dict={}
    time_dict={}
    ## This is used as a unique count of ids
    id=0
    
    def __init__(self,default = None,query=None):
        
        HTMLUI.id+=1
        
        self.result = ''
        
        if default != None:
            self.form_parms = default.form_parms
            self.defaults = default.defaults
            self.toolbar_ui=default.toolbar_ui
            self.generator=default.generator
            self.depth = default.depth+1
        else:
            import pyflag.FlagFramework as FlagFramework
            self.form_parms =FlagFramework.query_type(())
            self.defaults = FlagFramework.query_type(())
            self.toolbar_ui=None
            self.generator=HTTPObject()
            self.depth=1

        if query:
            self.defaults=query
            
        self.table_depth = 0
        self.type = "text/html"
        self.previous = None
        self.next = None
        self.pageno = 0
        self.meta = ''
        self.color=None
        self.bgcolor=None
        self.font = None
        self.text_var = ''
        self.text_line_count = 0
        self.nav_query = None
        #This specified if we should render the UI in the theme or
        #naked. Note that this only affects UIs which are drawn in a
        #window not ones which are added to other UIs:
        self.decoration='full'
        self.title=''
        
    def display(self):
        ## If the method is post, we need to emit the pseudo post form:
        if self.decoration!='raw':
            self.result="<form name=PseudoForm method=POST action='/post'><input type=hidden id=pseudo_post_query name=pseudo_post_query value='' /></form><script>if(!window.name) window.name='ID%s'; </script>\n<script src='/images/functions.js'></script>\n" % self.id + self.result

        #Make a toolbar
        if not self.nav_query:
            q = self.defaults.clone()
            del q['__target__']
            q['__target__']='limit'
        else: q = self.nav_query

        try:
            q['family']
        except KeyError:
            q['family'] =''
            
        ## Get the right theme
        theme=Theme.get_theme(q)
        
        if self.decoration=='naked':
            return theme.naked_render(data=self.__str__(), ui=self,title=self.title)
        elif self.decoration=='raw' or self.decoration=='js':
            return self.__str__()
        else:
            return theme.render(q,meta=self.meta,data=self.__str__(),next=self.next , previous=self.previous , pageno=self.pageno, ui=self)
    
    def __str__(self):
        #Check to see that table tags are balanced:
        while self.table_depth>0:
            self.end_table()

        return self.result

    def heading(self,string):
        self.result += "<h1>%s</h1>"%string

    def para(self,string,**options):
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
        ## Negotiate a prefered format with the graph
        format = image.SetFormat(config.GRAPHFORMAT)
        
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

    max_store_count = 1
    max_callback_count = 1

    def store_callback(self,callback):
        """ Function registers the callback with the server.

        If the user then issues  another request to it, it gets called to render the UI.

        This allows a report to specify a large number of items
        quickly which do not get rendered untill they are visible. For
        example if we show a pop up window, we dont actually render
        the window until the user pops it up.
        """
        count = HTMLUI.max_callback_count
        import time
        
        key= "CB%u" % count
        HTMLUI.callback_dict[key] = callback
        HTMLUI.callback_time_dict[key] = time.time()
        HTMLUI.max_callback_count+=1
        return key
    
    def store(self,ui):
        """ Function stores the current UI in a dict in the class method. This is required when we need to store a UI and later get the browser to retrieve it. """
        count = HTMLUI.max_store_count
        import time
        
        key= "UI%u" % count
        HTMLUI.store_dict[key] = ui
        HTMLUI.time_dict[key] = time.time()
        HTMLUI.max_store_count+=1
        return key

    def svg(self,text):
        """ Output the text as SVG
        @arg text: Scalable Vector Graphics image
        """

        #SVG overrides all the other HTML
        if self.defaults.has_key('draw_svg'):
            self.result = text
            self.display = self.__str__
            self.type='image/svg+xml'
        else:
            self.result += '<object type="image/svg+xml" data=f?%s&draw_svg=yes width=100%% height=100%% > </object>' % self.defaults
    
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
            self.result += "<%s %s>%s</%s>" % (type,self.opt_to_str(td_opts),column,type)

        self.result+="</tr>\n"

    def end_table(self):
        self.table_depth -= 1
        self.result += "</table>\n"

    def pre(self,string):
        self.result += "<pre>%s</pre>" % string

    def link(self,string,target=None,options=None,icon=None,tooltip=None,**target_options):
        ## If the user specified a URL, we just use it as is:
        try:
            self.result+="<a href='%s'>%s</a>" % (target_options['url'],string)
            return
        except KeyError:
            pass
        
        if target==None:
            target=FlagFramework.query_type(())
        q=target.clone()
        if target_options:
            for k,v in target_options.items():
                del q[k]
                q[k]=v

        if not options:
            options={}

        if icon:
            tmp = self.__class__(self)
            tmp.icon(icon,alt=string,border=0)
            tooltip=string
            string=tmp

        tmp = []
        try:
            tmp=target['__opt__'].split(',')
            del q['__opt__']
            if 'popup' in tmp:
                options['onclick'] ="window.open('%s','client','HEIGHT=600,WIDTH=600,scrollbars=yes')" % q
                self.result+="<a href=# %s >%s</a>" %(self.opt_to_str(options),string)
                return
        except KeyError:
            pass

        ## If the user right clicked, we open in a new window
        if config.METHOD=='POST':
            if 'parent' in tmp:
                action = "javascript: document.PseudoForm.target=self.opener.window.name; document.getElementById(\'pseudo_post_query\').value=\'%s\';  document.PseudoForm.submit(); self.close();" % (q,)
            else:
                window=q.window+".name"
                action = "javascript: if(isMiddleClick(event) || isLeftClick(event)) { if(isMiddleClick(event)){ document.PseudoForm.target='new_page';} else {document.PseudoForm.target=%s;};  document.getElementById(\'pseudo_post_query\').value=\'%s\';document.PseudoForm.method=\'POST\';  PseudoForm.submit();};" % (window,q)
            base = '<a %s href="%s" onmousedown="%s" >%s</a>' % (self.opt_to_str(options),action,action,string)
        else:
            if 'parent' in tmp:
                options['onclick']="self.opener.location=\"%s\"; self.close();" % q

            base ="<a href='blah?%s' %s>%s</a>" % (q,self.opt_to_str(options),string)
            
        if tooltip:
            self.result+="<abbr title='%s'>%s</abbr>" % (tooltip,base)
        else:
            self.result+=base

    def toolbar_popup(self,callback, label,icon=None,toolbar=0, menubar=0, tooltip=None, **options):
        """ This method presents a button on the screen, which when
        clicked will open a new window and use the callback to render
        in it.

        The new UI will be based on the current UI.
        @arg callback: A callback function to render into the new UI
        """
        if not tooltip: tooltip = label
        cb = self.store_callback(callback)

        self.result+="""<script language=javascript>  var client_%s; function open_%s_window() { query = '%s&parent_window='+window.name; query += "&stored_query_%s="+escape(query); client_%s=window.open(query+'&callback_stored=%s','client_%s','toolbar=%s,menubar=%s,HEIGHT=600,WIDTH=600,scrollbars=yes');  }; </script><abbr title=%r>""" % (cb,cb,self.defaults,cb,cb,cb,cb,toolbar,menubar,tooltip)

        if icon:
            self.result+="""<a href=\"javascript:open_%s_window()\" onclick=\"javascript:open_%s_window()\"><img alt=%s border=0 src=images/%s></a>""" % (cb,cb,label,icon)
        else:
            self.result+="""<input type=button value=%r onclick=\"open_%s_window()\"> """ % (label,cb)

        self.result+="</abbr>"

    def popup(self,callback, label,icon=None,toolbar=0, menubar=0, tooltip=None, **options):
        """ This method presents a button on the screen, which when clicked will open a new window and use the callback to render in it.

        The new UI will be based on the current UI.
        @arg callback: A callback function to render into the new UI
        """
        if not tooltip: tooltip = label
        cb = self.store_callback(callback)
        ## Here we have a snippet of javascript which reads the values
        ## of all form parameters which have been filled already -
        ## this allows the subwindow to return back to this page with
        ## form members filled, even without submitting. Note that we
        ## need to remove the submit parameter itself in order to
        ## allow the engine to differentiate between a refresh to this
        ## page with pre-filled parameters and a form which was
        ## submitted by the user.

        ## Unfortunately MS Internet Explorer is a very brain damaged
        ## browser and it seems to truncate the GET query string at an
        ## arbitrary location. This means we need to do some
        ## gymnastics to get the browser to submit in POST or we risk
        ## losing a lot of our parameters.
        self.result+="""<script language=javascript>
        var tmp;
        function open_%s_window() {
           var query='';
           client_page = window.open('','child_window_%s','toolbar=%s,menubar=%s,HEIGHT=600,WIDTH=900,scrollbars=yes,dependent');
           //Here we read the forms contents, so we can let the popup window know the values of currently filled in fields (Before submitting).
           for(var i=0; i<document.pyflag_form_1.elements.length; i++) {
              //Checkboxes should only be added if they are checked
              if(document.pyflag_form_1.elements[i].type=='checkbox' && !document.pyflag_form_1.elements[i].checked) {
                continue;
              };
              //We must leave the submit button off, so that when the popup window refreshes to its parent we know it wasnt actually submitted.
              if(document.pyflag_form_1.elements[i].type!='submit' && document.pyflag_form_1.elements[i].name.length>0 ) {
                 query+=document.pyflag_form_1.elements[i].name+'='+encodeURIComponent(document.pyflag_form_1.elements[i].value)+'&';
              };
           };
           query+= "&parent_window="+self.name;
           query+="&stored_query_%s="+escape(query);
           tmp=document.getElementById('pseudo_post_query');
           tmp.value=query+'&callback_stored=%s';
           document.PseudoForm.target = 'child_window_%s';
           document.PseudoForm.submit();
        }; </script><abbr title=%r>
        """ %(cb,cb,toolbar,menubar,cb,cb,cb,tooltip)
        #(cb,self.defaults,cb,toolbar,menubar,tooltip)
        
        if icon:
            self.result+="""<a  href=\"javascript:open_%s_window()\" onclick=\"javascript:open_%s_window()\"><img alt=%s border=0 src=images/%s></a>""" % (cb,cb,label,icon)
        else:
            self.result+="""<input type=button value=%r onclick=\"open_%s_window()\"> """ % (label,cb)

        self.result+="</abbr>"

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

    def make_link(self,query,target,target_format = None,**options):
        """ Makes a query_type object suitable for use in the links array of the table

        @note: the returned object is a clone of query.
        @note: Private ui parameters are automatically cleaned. e.g. limit, nextpage etc.
        @arg query: Original query to base the new object on
        @arg target: a string representing the name of the target
        @arg target_format: An optional format string that will be used to format the target arg for each cell in the table. There must be only one format specifier.
        """
        q = query.clone()
        del q[target]
        del q['__target__']
        del q['limit']
        del q['order']
        del q['dorder']
        
        q['__target__']=target
        try:
            q['__mark__']=options['mark']
        except KeyError:
            pass
        
        if target_format:
            q[target]=target_format

        return q

    def tree(self, tree_cb = None, pane_cb=None, branch = None, layout=None):
        """ A tree widget.

        This implementation uses javascript/iframes extensively.
        """
        def draw_branch(depth,query, result):
            try:
            ## Get the right part:
                branch=query['open_tree'].split('/')
            except KeyError:
                branch=['/']
            
            for name,value,state in tree_cb(branch[:depth]):
                ## Must have a name and value
                if not name or not value: continue
                result.result+="<tr><td>"
                result.icon("spacer.png", width=20*depth, height=20)
                link = query.clone()
                del link['open_tree']
                del link['yoffset']
                del link['xoffset']
                cb = link['callback_stored']
                del link['callback_stored']
                
                link['open_tree'] = FlagFramework.normpath("/".join(branch[:depth] + [name]))
                open_tree = FlagFramework.urlencode(link['open_tree'])
                sv=value.__str__().replace(' ','&nbsp;')
                
                if state=="branch":
                    result.result+="<a href=\"javascript:tree_open('%s','%s','f?%s')\"><img border=0 src=\"/folder.png\"></a>" % (cb,query['right_pane_cb'],link)
                else:
                    result.result+="<a href=\"javascript:tree_pane_open('%s','%s','f?%s')\"><img border=0 src=\"/corner.png\"></a>" % (cb,query['right_pane_cb'],link)
                    
                result.result+="&nbsp;%s</td></tr>\n" % str(sv)
                result.result+="\n"

                try:
                ## Draw any opened branches
                    if name == branch[depth]:
                        draw_branch(depth+1,query, result)
                except IndexError:
                    pass

        def left(query,result):
            result.decoration = "js"
            result.content_type = "text/html"

            #The first item in the tree is the first one provided in branch
            link = query.clone()
            del link['callback_stored']
            result.result+="<a href=\"javascript:tree_open('%s','%s','f?%s')\"><img border=0 src=\"/folder.png\"></a>" % (query['callback_stored'],query['right_pane_cb'],link)
            result.result+="&nbsp;/<br>\n"

            result.result+="<table width=100%>"
            draw_branch(1,query, result)
            try:
                result.result+="<script>document.body.scrollTop = %s; document.body.scrollLeft = %s;</script>\n" % (query['yoffset'], query['xoffset'])
            except:
                pass

            result.result+="</table>"
            
        def right(query,result):
            result.decoration = "js"
            result.content_type = "text/html"
#            result.result += "<script>window.onunload = function() { if(document != top) top.location = window.document.location; }; </script>\n"
            try:
            ## Get the right part:
                branch=query['open_tree'].split('/')
            except KeyError:
                branch=['/']

            pane_cb(branch,result)

        l = self.store_callback(left)
        r = self.store_callback(right)

        self.result+='<table width="100%%"  height="100%%"><tr height="400+"><td width="40%%" height="80%%"><iframe id="left" name="left" height="100%%" width=300 src="%s&callback_stored=%s&right_pane_cb=%s"></iframe></td><td width="40%%" height="80%%"><iframe name="right" id="right" height="100%%" width=1000 src="%s&callback_stored=%s" > </iframe></td></tr></table>' % (self.defaults,l,r,self.defaults,r)

    def xtree(self,tree_cb = None, pane_cb=None, branch = ('/'), layout="horizontal"):
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

        #This is needed if we want to have more than one tree per
        #page. FIXME - this is not currently implemented.
        self.tree_id += 1
        
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
            branch_array=branch[:depth]
            for k,v,t in tree_cb(branch_array):
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
                            tree_array.append((depth,tmp[-1][1],'<img src=/flag/images/down.png border=0> ...','special'))
                        return

                    #Do we find the current item in the list?
                    if k == branch[depth]:
                        match_pos = len(tmp)
                        
                        #Now slice the tmp array to append it to the tree array
                        if match_pos-config.MAXTREESIZE < 0:
                            start = 0
                        else:
                            start = match_pos - config.MAXTREESIZE
                            tree_array.append((depth,tmp[start-1][1],'<img src=/flag/images/up.png border=0> ...','special'))
                        
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
                tree_array.append( (depth,split[-1][1],'<img src=/flag/images/down.png border=0> ...','special'))

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
        
        try:
            ## Get the right part:
            branch=query['open_tree'].split('/')
        except KeyError:
            branch=['/']

        pane_cb(branch,right)
        
        ## Now draw the left part
        if layout=="vertical":            
            self.row(left)
            self.row(right)
        else:
            self.row(left,right,valign='top')

    def toolbar(self,cb=None,text=None,icon=None,popup=True,tooltip=None,link=None):
        """ Create a toolbar button.

        When the user clicks on the toolbar button, a popup window is
        created which the callback function then uses to render on.
        """
        if self.toolbar_ui==None:
            self.toolbar_ui=self.__class__(self)

        if link:
            self.toolbar_ui.link(text,target=link,icon=icon,tooltip=tooltip)
        elif cb:
            self.toolbar_ui.toolbar_popup(cb,text,icon,tooltip=tooltip)
        else:
            self.toolbar_ui.icon(icon,tooltip=text)
                
    def table(self,sql="select ",columns=[],names=[],links=[],table='',where='',groupby = None,case=None,callbacks={},**opts):
        """ Shows the results of an SQL query in a searchable/groupable/browsable table

        The format of the sql statement is:
        $sql $columns from $table where $where having $__having__ orderby $orderby

        Note that the caller has no control on the having clause, it is constructed by the UI object subject to parameters passed to the UI object's `defaults` query object.

        The links list specifies links to be created in place of each column (x) in the table. If links[x] is not None, we display the link. If the link contains the special element '__target__' having the value v, we check links[v] for a format specifier. if present the cell value is interpolated into it, else a new element if created with its value set to the cell value.

        If the callbacks variable is specified, it is a dictionary mapping names to callback function. These callbacks will be invoked to render the result of that column and should return a UI object. For example if the names arguement contains the name 'deleted':

        >>> def function(value,query=query):
        ....    @return: ui based on value
        
        >>> callbacks=['deleted':function]

        __target__ may be specified any number of times.

        @arg sql: initial part of sql statement to run. Defaults to select
        @arg columns: array of columns to be used for select query.
        @arg names: array of names to be used for each column.
        @arg links: array of query_type used to link each column in the list.
        @arg where: where clause that will be used in this query
        @arg callbacks: A dictionary mapping names (from the names array) to callback functions.
        @note: The user has a lot of fine control over the where clause. In the text entry boxes at the bottom of the screen, the user may enter the search term in the following convention:
              - If the search term does not contain any wildcards (%), wildcards are added before and after the search term to match the occurance of the word anywhere in the data. This approach is generally what is wanted, but may prove too slow since indexing cant be used.
              - If the search term has a wild card in it, no further wild cards are added. This allows the user to specify a wildcard at the end of a word, which allows indexing to be used, but will only match the start of the word.
              - If any of the following characters (=,<,>) preceed the search term, the comparison is an exact mathematical comparison. e.g. '>5' means column>5.
        """
        #in case the user forgot and gave us a tuple, we forgive them:
        names=list(names)
        columns = list(columns)
        for l in links:
            try:
                l.window="top.window"
            except:
                pass
        
        #First work out what is the query string:
        query_str = sql;
        query = self.defaults
        
        #The new_query is the same one we got minus all the UI
        #specific commands. The following section, just add UI
        #specific commands onto the clean sheet
        new_query = query.clone()
        del new_query['dorder']
        del new_query['order']
        del new_query['limit']

        select_clause=[]
        new_names=[]
        new_columns=[]
        #find the group by clause. If the caller of this widget set
        #their own group by, we cant use the users group by
        #instructions.
        if not groupby:
             #If we have a group by, we actually want to only show a
             #count and those columns that are grouped by, so we over
             #ride columns and names... We do not however nuke the
             #original names and columns until _after_ we calculate
             #our where conditions.  Mask contains those indexes for
             #which names array matches the group_by clause
             try:
                 mask = [ names.index(d) for d in query.getarray('group_by') ]
                 if not mask: raise ValueError
                 links = [None]+ [ self.make_link(query,"where_%s" % names[d],target_format="=%s") for d in mask ]
                 for d in links:
                     if d:
                         #For links we dont want these variables to be there
                         del d['group_by']
                         del d['limit']

                 group_by_str = ",".join([ " `%s`" % d for d in query.getarray('group_by') ])
                 new_names=['Count'] +[ names[d] for d in mask ]
                 new_columns= [ 'count(*)' ] +[ columns[d] for d in mask ]
                 select_clause = [ k+ " as `" +v+"`" for (k,v) in zip(new_columns,new_names) ]
             ## if the user asked for a weird group by , we ignore it.
             except ValueError:
                 group_by_str = None
        else:
            group_by_str = groupby

        #Form the columns in the sql
        if not select_clause:
            select_clause= [ " %s as `%s` " % (k,v) for (k,v) in zip(columns,names) ]
            
        query_str+=",".join(select_clause) 

        #Form the table clause
        query_str+=" from %s " % table

        #Work out the having clause.
        having=['1']
        conditions=[]
        condition_text_array=[]
        for d,v in query:
            if d.startswith('where_'):
                #Find the column for that name
                try:
                    index=names.index(d[len('where_'):])
                except ValueError:
                    ## If we dont know about this name, we ignore it.
                    continue

                condition_text = FlagFramework.make_sql_from_filter(v,having,columns[index],d[len('where_'):])
                
                #create a link which deletes the current variable from
                #the query string, allows the user to remove the
                #current condition:
                tmp_query=query.clone()
                tmp_query.remove(d,v)
                tmp_link=self.__class__(self)
                tmp_link.link(condition_text,target=tmp_query)
                conditions.append(tmp_link)
                condition_text_array.append(condition_text)

        having_str = " and ".join(having)

        if where:
            where_str= " where (%s) and (%s) " %(where,having_str)
        elif having:
            where_str=" where %s " % having_str

        query_str+=where_str
        
        ## At this point we can add the group by calculated above, and
        ## replace the names and columns arrays from the group by
        if group_by_str:
            query_str += " group by %s " % group_by_str

        if new_names:
            names=new_names
            columns=new_columns

        #Find the order by clause
        #Were we given a dorder param?
        try:
            order = " `%s` desc " % query['dorder']
            #Remember the column number that was ordered
            ordered_col = names.index(query['dorder'])
        except (ValueError,KeyError):
            #Ok then were we given an order param?
            try:
                order = " `%s` asc " % query['order']
                ordered_col = names.index(query['order'])
            except (ValueError,KeyError):
                #If an order was not specified, we pick the first column as the order
                order = " `%s` asc " % names[0]
                ordered_col = 0

        ## This is used to render things in the popups. The query
        ## string here is naked without order by clauses
        query_str_basic = query_str
        query_str+= " order by %s " % order

        #Calculate limits
        if not query.has_key('limit'):
            query['limit'] = "0"

        ## Add next and previous button as needed:
        previous = int(query['limit']) - config.PAGESIZE
        next = int(query['limit']) + config.PAGESIZE
        
        self.pageno =  int(query['limit']) /config.PAGESIZE
                
        query_str+=" limit %u, %u" % (int(query['limit']) , config.PAGESIZE)

        dbh = DB.DBO(case)

        #Do the query, and find out the names of all the columns
        dbh.execute(query_str)

        if group_by_str:
            def table_groupby_popup(query,result):
                result.display = result.__str__
                result.heading("Most commonly seen %s" % query['group_by'])
                if condition_text_array:
                    result.start_table()
                    result.row("The following filter conditions are enforced")
                    for i in condition_text_array:
                        result.row(i)
                    result.end_table()
                    result.start_table()

                #Find out how many results there are all up
                dbh.execute("select count(*) as total from %s %s" %(table, where_str))
                total = dbh.fetch()['total']
                dbh.execute(query_str_basic+" order by `Count` desc limit 8",())
                values=[]
                labels=[]
                count=0
                for row in dbh:
                    values.append(row['Count'])
                    count+=int(row['Count'])
                    try:
                        tmp_value=row[names[1]]
                        labels.append("%s\\n (%s)" % (callbacks[names[1]](tmp_value),row['Count']))
                    except KeyError:
                        labels.append("%s\\n (%s)" % (row[names[1]],row['Count']))

                ## Insert an others entry:
                values.append(total - count)
                labels.append("Others (%s)" % (total-count))
                
                import pyflag.Graph as Graph
                ##Create a new pie chart:
                pie = Graph.Graph()
                pie.pie(labels,values,explode="0.1", legend='yes')
                result.image(pie)

            ## End of table_groupby_popup
                
            ## Add a popup to allow the user to draw a graph
            self.toolbar(table_groupby_popup,'Graph',icon='pie.png')
        else: ## Not group by
            def table_configuration_popup(query,result):
                try:
                    if query['refresh']:
                        del query['refresh']
##                        del query['callback_stored']
                        result.refresh(0,query,parent=1)
                except KeyError:
                    pass
                
                result.decoration = 'naked'
                result.heading("Select columns to hide:")
                result.start_form(query, refresh="parent")
                result.start_table()
                for name in names:
                    result.checkbox(name,"hide_column",name)
                result.end_table()
                result.end_form()
 
                    
            ## End table_configuration_popup

            if query.getarray('hide_column'):
                self.toolbar(table_configuration_popup,'Some columns hidden (%s)' % ','.join(query.getarray('hide_column')),icon='spanner.png')
            else:
                self.toolbar(table_configuration_popup,'Configure Table View',icon='spanner.png')

        ## Draw a popup to allow the user to save the entire table in CSV format:
        def save_table(query,result):
            dbh = DB.DBO(case)

            def generate_output():
                query_row_limit = 1024
                data = cStringIO.StringIO()
                hidden_columns = list(query.getarray('hide_column'))

            ## FIXME - We dont usually want to save called back
            ## columns becuase they rarely make sense (but sometimes
            ## they do?? which should we do here???)
                for i in callbacks.keys():
                    if i not in hidden_columns:
                        hidden_columns.append(i)
                    
                names_list = [ i for i in names if i not in hidden_columns ]
                inittext= "#Pyflag Table widget output\n#Query was %s.\n#Fields: %s\n""" %(query," ".join(names_list))
                if condition_text_array:
                    inittext+= "#The following conditions are in force\n"
                for i in condition_text_array:
                    inittext += "# %s\n" % i
                yield inittext
                
                csv_writer = csv.DictWriter(data,names_list,dialect='excel')
                limit = 0
                while 1:
                    dbh.execute(query_str_basic + " order by %s limit %s,%s" %
                                (order,limit,limit+query_row_limit))

                    count = 0
                    for row in dbh:
                        count+=1
                    ## If there are any callbacks we respect those now.
                        new_row={}
                        for k,v in row.items():
                            if k in hidden_columns: continue
                            try:
                                row[k]=callbacks[k](v)
                            except (KeyError,Exception):
                                pass

                        ## Escape certain characters from the rows - some
                        ## spreadsheets dont like these even though they
                        ## are probably ok:
                            tmp=str(row[k])
                            tmp=tmp.replace("\r","\\r")
                            tmp=tmp.replace("\n","\\n")

                            new_row[k]=tmp

                        csv_writer.writerow(new_row)
                        data.seek(0)
                        tmp=data.read()
                        yield tmp
                        data.truncate(0)

                    if count==0: break
                    limit+=query_row_limit

            result.generator.generator = generate_output()
            result.generator.content_type = "text/csv"
            result.generator.headers = [("Content-Disposition","attachment; filename=%s_%s.csv" %(case,table) ),]

            del query['callback_stored']
            
            return
            
            
            
        self.toolbar(save_table,'Save Table',icon="floppy.png")

        ## Write the conditions at the top of the page:
        if conditions:
            self.start_table()
            self.row("The following filter conditions are enforced")
            for i in conditions:
                self.row(i)
            self.row("Click any of the above links to remove this condition")
            self.end_table()
            self.start_table()

        tmp_links = []
        hidden_columns = []
        for i in range(len(names)):
            d=names[i]
            
            ## Skip the hidden columns
            if d in query.getarray('hide_column'):
                hidden_columns.append(i)
                continue
            
            #instatiate a whole lot of UI objects (based on self) for the table header
            tmp = self.__class__(self)

            #Create links to the current query as well as an ordering
            #parameter - note the addition of parameters we get by
            #using the new query's str method, and the addition of
            #parameters by using named args...
            try:
                assert(query['dorder'] == d)
                tmp.link(d,target=new_query,order=d)
            except (KeyError,AssertionError):
                tmp.link(d,target=new_query,dorder=d)

            #If the current header label is the same one in
            #ordered_col, we highlight it to show the user which
            #column is ordered:
            if names[ordered_col] == d:
                tmp2=self.__class__(self)
                tmp2.start_table()
                tmp2.row(tmp,bgcolor=config.HILIGHT)
                tmp = tmp2
                
            tmp_links.append(tmp)

        #This array keeps track of each column width
        width = [ len(names[d]) for d in range(len(names))]

        #output the table header
        if opts.has_key('headers'):
            try:
                h = []
                for i in range(len(names)):
                    if i not in hidden_columns:
                        try:
                            h.append(opts['headers'][names[i]])
                        except KeyError:
                            h.append('')
            except KeyError:
                pass

            self.row(*h)

        self.row(*tmp_links)

        #This is used to keep track of the lines with a common sorting
        #key: common = (bgcolor state, last value)
        common = [False,0]
        count =0
        
        #output the rest of the lines in a table:
        while 1:
            row = dbh.fetch()
            if not row: break

            #Form a row of strings
            row_str=[]
            for i in range(len(row)):
                row_str.append("%s" % row[names[i]])
                if width[i] < len(row_str[i]):
                    width[i] = len(row_str[i])

            #Work through the row and create entry uis for each of them.
            for i in range(len(row_str)):
                value=row_str[i]

                ## Check if the user specified a callback for this column
                if callbacks.has_key(names[i]):
                    value=callbacks[names[i]](value)
                else:
                ## Sanitise the value to make it HTML safe. Note that
                ## callbacks are required to ensure they sanitise
                ## their output if they need.
                    value=cgi.escape(value)

                ## Now add links if they are required
                try:
                    if links[i]:
                        q = links[i]
                        try:
                            q=q.clone()
                            q.FillQueryTarget(row_str[i])
                            
                        #No __target__ specified go straight here
                        finally:
                            tmp = self.__class__(self)
                            tmp.link(value, q)
                            value=tmp

                #links array is too short
                except IndexError:
                    row_str[i] = value
                    continue

                row_str[i] = value
                continue
                            
            #Work out the background color
            if common[1] != row[names[ordered_col]]:
                common[1] = row[names[ordered_col]]
                common[0] = not common[0]

            options = {}
            if common[0]:
                bgcolor1=config.BGCOLOR
                bgcolor=config.BGCOLOR1
            else:
                bgcolor1=config.BGCOLOR1
                bgcolor=config.BGCOLOR
                
            options['bgcolor'] = bgcolor
            try:
                options['valign'] = opts['valign']
            except KeyError:
                pass
            
            options['onmouseover']="setPointer(this,%u,'over',%r,%r,%r);" % (count,bgcolor,config.HILIGHT,config.SELECTED)
            options['onmouseout']="setPointer(this,%u,'out',%r,%r,%r);" % (count,bgcolor,config.HILIGHT,config.SELECTED)
            options['onmousedown']="setPointer(this,%u,'click',%r,%r,%r);" % (count,bgcolor,config.HILIGHT,config.SELECTED)

            count += 1
            #Add the row in
            self.row(*[ row_str[i] for i in range(len(row_str)) if i not in hidden_columns],**options)

        if opts.has_key('simple'):
            return

        if not groupby:
            self.row("click here to group by column",colspan=50,align='center')

            #Insert the group by links at the bottom of the table
            tmp_links = []
            for i in range(len(names)):
                if i in hidden_columns: continue
                d=names[i]
                tmp = self.__class__(self)
                tmp.link(d,target=new_query,group_by=d)
                tmp_links.append(tmp)
                
            self.row(*tmp_links)
            
        self.row("Enter a term to filter on field (% is wildcard)",colspan=50,align='center')

        #Now create a row with input boxes for each parameter
        tmp_links=[]
        for d in range(len(names)):
            if d in hidden_columns: continue
            tmp = self.__class__(self)
            #It doesnt make sense to search for columns with
            #callbacks, so we do not need to show the form.
            if callbacks.has_key(names[d]):
                try:
#                    cb_result=callbacks[names[d]](query['where_%s' % names[d]])
                    new_q=query.clone()
                    del new_q['where_%s' % names[d]]
#                    tmp.link(cb_result,new_q)
                except KeyError:
                    pass
            else:
                tmp.start_form(new_query)
                tmp.start_table()
                tmp.textfield('','where_%s' % names[d],size=width[d],Additional=True)
                tmp.end_table()
                tmp.end_form('Go')
                
            tmp_links.append(tmp)

        self.row(*tmp_links)
        
        self.row(*[ names[i] for i in range(len(names)) if i not in hidden_columns ])

        #If our row count is smaller than the page size, then we dont
        #have another page, set next page to None
        if count < config.PAGESIZE:
            next = None

        new_query=query.clone()
        if previous<0 and int(query['limit'])>0:
            previous=0
            
        if previous>=0:
            del new_query['limit']
            new_query['limit']=previous        
            self.toolbar(text="Previous page", icon="stock_left.png", link=new_query)
        else:
            self.toolbar(text="Previous page", icon="stock_left_gray.png")

        if next:
            del new_query['limit']
            new_query['limit']=next
            self.toolbar(text="Next page", icon="stock_right.png", link=new_query)
        else:
            self.toolbar(text="Next page", icon="stock_right_gray.png",popup=False)

        ## Add a skip to row toolbar icon:
        self.toolbar(
            cb = goto_row_cb,
            text="Row %s" % query['limit'],
            icon="stock_next-page.png"
            )


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
                self.result += "%s<span style='background-color:yellow'>%s</span>" % (format,d)
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
                            self.result+="<img src='next_line.png'>"
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
        right = "<textarea name='%s' %s>%s</textarea>" % (name,option_str,default)
        self.row(left,right,valign="top")
        
    def tooltip(self,message):
        """ REDUNDANT? AFAIK no report uses it,
        Tooltips can be specified as parameters for some widgets eg. toolbar"""
        #message = message.replace("\n"," ")
        #self.result = "<abbr title=%r>%s</abbr>" % (message,self.result)
        pass
        
    def start_form(self,target, **hiddens):
        """ start a new form with a local scope for parameters.

        @arg target: A query_type object which is the target to the form. All parameters passed through this object are passed to the form's action.
        """
        self.form_parms=target.clone()
        #Append the hidden params to the object
        for k,v in hiddens.items():
            self.form_parms[k]=v

        self.result += '<form name=pyflag_form_%s method=%s action="/f" enctype="multipart/form-data">\n' % (self.depth, config.METHOD)

    def end_form(self,value='Submit',name='submit',**opts):
        for k,v in self.form_parms:
            self.result += "<input type=hidden name='%s' value='%s'>\n" % (k,v)

        if value:
            self.result += "<input type=submit name=%s value='%s' %s>\n" % (name,value,self.opt_to_str(opts))

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
        
    def refresh(self,interval,query,**options):
        target_window = "'_self'"
        target_js = 'window'
        close = ''
        if int(interval)>0:
            timeout = "window.setTimeout(refresh,%s);" % (1000*int(interval))
        else:
            timeout = "refresh();"

        if not options:
            options={}

        try:
            if options.has_key('parent'):
                if config.METHOD=="POST":
                    ## This is required because some browsers forget
                    ## which window opened this one so self.opener
                    ## does not work. We therefore try to pass this
                    ## information in the query to ensure that the
                    ## correct parent is opened.
                    try:
                        if options['parent'].startswith("ID"):
                            target_window = "%r" % options['parent']
                        else:
                            raise AttributeError
                    except AttributeError:
                        try:
                            ## Pop off the parent_window and the
                            ## stored_query information from the
                            ## query:
                            callback_stored = query.poparray('callback_stored')
                            stored_query = query['stored_query_%s' % callback_stored]
                            stored_query = FlagFramework.query_type(cgi.parse_qsl(stored_query))
                            del query['stored_query_%s' % callback_stored]
                            target_window =  "%r"%stored_query['parent_window']
                        except KeyError:
                            target_window = "self.opener.window.name"
                        
                    close = "self.close();"
                else:
                    target_js = 'self.opener'

        except KeyError:
            pass

        ## We do both javascript refresh as well as meta refresh to
        ## ensure that the browser supports either method
        if config.METHOD=="POST":
            self.result+="""<script language=javascript>
            function refresh() {
            document.PseudoForm.target=%s;
            document.getElementById(\'pseudo_post_query\').value=\'%s\';
            document.PseudoForm.submit(); %s
            };
            %s
            </script>""" % (target_window,query,close,timeout)
        else:
            self.result+=""" <script>function refresh() {%s.location="%s";}; setTimeout("refresh()",%s) </script>""" % (target_js,query,int(interval)*1000)
            self.meta += "<META HTTP-EQUIV=Refresh Content=\"%s; URL=%s\">" % (interval,query)

    def icon(self, path, tooltip=None, **options):
        """ This allows the insertion of a small static icon picture. The image should reside in the images directory."""
        option_str = self.opt_to_str(options)
        data = "<img border=0 src=/flag/images/%s %s />" % (path, option_str)
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
                
    def notebook(self,names=[],context="notebook",callbacks=[],descriptions=[]):
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
            cbfunc=callbacks[names.index(context_str)]
        except (ValueError,KeyError):
            cbfunc=callbacks[0]
            context_str=names[0]

#        out='\n<table border=0 cellspacing=0 cellpadding=0 width="100%"><tr><td colspan=50><img height=20 width=1 alt=""></td></tr><tr>'
        out='\n<div id="notebook"><ul id="topmenu">'
        
        for i in names:
            q=query.clone()
            tmplink=self.__class__()
            del q[context]
            q[context]=i
            tmplink.link(i,q, options={'class':"tab"})

            if(i==context_str):
##                out+="<td width=15>&nbsp;</td><td bgcolor=#3366cc align=center nowrap><font color=#ffffff size=-1><b>%s</b></font></td>" % i
                out+="<li><a class='tabactive'>%s</a></li>\n" % i
            else:
##                out+='<td width=15>&nbsp;</td><td id=1 bgcolor=#efefef align=center nowrap><font size=-1>%s</font></td>' % (tmplink)
                out+="<li>%s</li>\n" % tmplink

        out+="</ul>"
##        out+="<td colspan=50>&nbsp;</td></tr><tr><td colspan=50 bgcolor=#3366cc><img width=1 height=1 alt=""></td></tr>"
        
        #Now draw the results of the callback:
        result=self.__class__(self)
        cbfunc(query,result)
##        out+="<tr><td colspan=50><table border=1 width=\"100%%\"><tr><td>%s</td></tr></table></td></tr></table>" % result
        out+="</div><div class='clearfloat'></div><div class='content'>%s</div>\n" % result
        self.result+=out
