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
#  Version: FLAG $Name:  $ $Date: 2004/10/22 08:34:33 $
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
import pyflag.Theme
import cStringIO,csv

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
    binary=0
    
    def __init__(self,default = None):
        self.result = ''
        
        if default != None:
            self.form_parms = default.form_parms
            self.defaults = default.defaults
        else:
            import pyflag.FlagFramework as FlagFramework
            self.form_parms =FlagFramework.query_type(())
            self.defaults = FlagFramework.query_type(())
            
        self.table_depth = 0
        self.type = "text/html"
        self.previous = None
        self.next = None
        self.pageno = 0
        self.meta = ''
        self.color=None
        self.font = None
        self.text_var = ''
        self.text_line_count = 0
        self.nav_query = None
        
    def display(self):
        if self.binary:
            return self.result
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
        try:
            theme=pyflag.Theme.factory(q['theme'])
        except KeyError:
            theme=pyflag.Theme.factory()
        return theme.render(q,meta=self.meta,data=self.__str__(),next=self.next , previous=self.previous , pageno=self.pageno)
    
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

    def image(self,image,**options):
        """ Plots the current image inside the UI.

        @arg image: An instance of the Image class.
        """
        opt = self.opt_to_str(**options)
        
        #Create a new UI for the graph:
        tmp = self.__class__()
        ## Negotiate a prefered format with the graph
        format = image.SetFormat(config.GRAPHFORMAT)
        
##        if format == 'png' or format == 'jpeg':
##            out_format = 'png'
##            ct = 'image/png'
###            embed = '<img src="f?draw_stored=%%s" %s />' % opt
##            embed = '<object type="image/png" data="f?draw_stored=%%s" %s />' % opt
##        elif format == 'svg':
##            out_format = 'svg'
##            ct = 'image/svg+xml'
##            embed = '<object type="image/svg+xml" data="f?draw_stored=%s" width=100%% height=100%% > </object>'
        
        #Ask the image whats its ct:
        tmp.result = image.display()
        tmp.type = image.GetContentType()
        #Redefine our display method to just dump the binary object back
        tmp.binary=True
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
            #Replace \n in column with <br>\n:
            import re
            column = re.sub(r"([^>])\n",r"\1<br>\n",str(column))

            self.result += "<%s %s>%s</%s>" % (type,self.opt_to_str(td_opts),column,type)

        self.result+="</tr>\n"

    def end_table(self):
        self.table_depth -= 1
        self.result += "</table>\n"

    def pre(self,string):
        self.result += "<pre>%s</pre>" % string

    def link(self,string,target=FlagFramework.query_type(()),**target_options):
        q=target.clone()
        if target_options:
            for k,v in target_options.items():
                del q[k]
                q[k]=v

        self.result+="<a href='blah?%s'>%s</a>" % (q,string)

    def popup(self,callback, label,icon=None,toolbar=0, menubar=0, **options):
        """ This method presents a button on the screen, which when clicked will open a new window and use the callback to render in it.

        The new UI will be based on the current UI.
        @arg callback: A callback function to render into the new UI
        """
        cb = self.store_callback(callback)
        self.result+="""<script language=javascript>  var client; function open_%s_window() {  client=window.open('%s&callback_stored=%s','client','toolbar=%s,menubar=%s,HEIGHT=600,WIDTH=600,scrollbars=yes'); client.moveto(0,0);  }; </script><abbr title=%r>""" % (cb,self.defaults,cb,toolbar,menubar,label)
        if icon:
            self.result+="""<a  onclick=\"open_%s_window()\"><img alt=%s border=0 src=images/%s></a>""" % (cb,label,icon)
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
#        for i in q.keys():
#            if i.startswith('where_'):
#                del q[i]
        
        q['__target__']=target
        try:
            q['__mark__']=options['mark']
        except KeyError:
            pass
        
        if target_format:
            q[target]=target_format

        return q

    def tree(self,tree_cb = None, pane_cb=None, branch = ('/')):
        """ A tree widget.

        This widget works by repeatadly calling the call back function for information about entries in the current tree. The format of the callback is:

        >>> def tree_cb(branch):

        The call back function is a generator which is expected to yield (name,value,state) tuples representing the entries under the requested branch:
              - name: The name of the tree branch. This name will be used to access the tree branches and may have limitations on the characters that may be present.
              - value: A string or a UI object that will be displayed at that position in the tree
              - state: Indicates if this is a \"branch\" (i.e. can be opened up) or a leaf.

        @Note: If you do not want to use generators you must return a list of (name,value,state) tuples from the call back function. (Its effectively the same thing).

        @Note: It is very important to stress that the call back is a generator, therefore it must yield results rather than return them.

        Also since multiple instances of the generator function may be called simultaneously, it is _imperative_ that the call back function not modify variables outside its scope, or serious locking issues may arise. In particular, it is imperative that database handles be created inside the local scope.

        @arg tree_cb: Call back registered to build the tree
        @arg branch: A list representing a branch to have initially expanded. Each item in the list represents a branch at its respective depth in the tree. e.g.

        >>> /usr/share/local = ('usr','share','local')
        
        """
        if not self.defaults: raise UIException, "Must have default query for tree widget"
        query = self.defaults

        #This is needed if we want to have more than one tree per page. FIXME - this is not currently implemented.
        self.tree_id += 1
        
        #Read in the current branch that needs to be opened from the open_tree parameter
        if query.has_key('open_tree'):
            open = query['open_tree']
            branch = [ d for d in open.split('/') ]

        #Start building the tree using the branch.
        def draw_branch(depth,tree_array):
            """ This is a recursive function used to build the tree. Complicating matters is the need to omit rows which are further than config.MAXTREESIZE away from the selected item. This is done in order to speed up browsing through a browser (its not needed for GTKUI for example).

            @note: We are using the callback as a generator here to ensure we do not need to parse potentially thousands of entries.
        
            @arg tree_array: This function builds tree_array as it goes to represent the final tree HTML structure.
            @arg depth: The current depth to calculate - an int pointing into the branch array
            """
            found =0
            tmp = []
            #We search through all the items until we find the one that matches the branch for this depth, then recurse into it.
            branch_array=branch[:depth] 
            for k,v,t in tree_cb(branch_array):
                if not k: return
                if not t: continue
                tmp.append((depth,k,v,t))
                try:
                    #We are further than config.MAXTREESIZE after the tree item that will matched, we can quit now after placing an arrow
                    if found and len(tmp)>config.MAXTREESIZE:
                        tree_array += tmp
                        if len(tmp) > config.MAXTREESIZE:
                            tree_array.append((depth,tmp[-1][1],'<img src=/flag/images/down.png> ...','special'))
                        return

                    #Do we find the current item in the list?
                    if k == branch[depth]:
                        match_pos = len(tmp)
                        
                        #Now slice the tmp array to append it to the tree array
                        if match_pos-config.MAXTREESIZE < 0:
                            start = 0
                        else:
                            start = match_pos - config.MAXTREESIZE
                            tree_array.append((depth,tmp[start-1][1],'<img src=/flag/images/up.png> ...','special'))
                        
                        tree_array += tmp[start:]

                        tmp = []
                        found = 1
                        #Recurse into the next level in the tree
                        draw_branch(depth+1,tree_array)
                                                
                except IndexError,e:
                    #This is triggered when there is no deeper level in the tree
                    if len(tmp) > config.MAXTREESIZE:
                        break

            #We get here if we exhausted all the items within config.MAXTREESIZE or did not find the requested branch in the tree
            split =  tmp[:config.MAXTREESIZE]
            tree_array += split
            if len(split) == config.MAXTREESIZE:
                tree_array.append( (depth,split[-1][1],'<img src=/flag/images/down.png> ...','special'))

        #### End draw_branch

        link = query.clone()
        tree_array = []

        #The first item in the tree is the first one provided in branch
        tree_array.append((0,branch[0],branch[0],'branch'))

        #Build the tree_array
        draw_branch(1,tree_array)       

        del link['open_tree']
        link['open_tree'] = "%s" % '/'.join(branch[:-1])
        tmp = self.__class__()
        tmp.link("Up\n",link)
        self.text(tmp)

        import pyflag.FlagFramework as FlagFramework

        left=self.__class__()

        #Now we draw the stuff saved in tree_array according to its classification
        for depth,k,v,t in tree_array:
            del link['open_tree']
            link['open_tree'] = "/".join(branch[:depth] + [k])
            open_tree = FlagFramework.urlencode(link['open_tree'])
            if t =='branch':
                left.result+="%s%s%s<br>\n" % ("<img src=/flag/images/spacer.png width=20 height=20>" * depth , "<a name=%s href=f?%s#%s><img  border=0 height=16 src=/flag/images/folder.png width=20 height=20></a>  " % (open_tree,link,open_tree) , str(v) )
            elif t == 'special':
                left.result+="%s%s<br>\n" % ("<img src=/flag/images/spacer.png width=20 height=20>" * depth , "<a name=%s href=f?%s#%s>%s</a>  " % (open_tree,link,open_tree, str(v) ))
            else:
                left.result+="%s%s%s<br>\n" % ("<img src=/flag/images/spacer.png width=20 height=20>" * depth , "<a name=%s /><img border=0 height=16 src=/flag/images/corner.png width=20 height=20>  " % open_tree, v )
        #right=self.__class__()
        right=self.__class__(self)
        try:
            ## Get the right part:
            pane_cb(query['open_tree'].split('/'),right)
        except KeyError:
            pass
        
        ## Now draw the left part
        self.row(left,right,valign='top')
                
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
        
        #First work out what is the query string:
        query_str = sql;
        query = self.defaults
        
        #The new_query is the same one we got minus all the UI specific commands. The following section, just add UI specific commands onto the clean sheet
        new_query = query.clone()
        del new_query['dorder']
        del new_query['order']
        del new_query['limit']

        select_clause=[]
        new_names=[]
        new_columns=[]
        #find the group by clause. If the caller of this widget set their own group by, we cant use the users group by instructions.
        if not groupby:
             #If we have a group by, we actually want to only show a count and those columns that are grouped by, so we over ride columns and names... We do not however nuke the original names and columns until _after_ we calculate our where conditions.
             #Mask contains those indexes for which names array matches the group_by clause
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
            select_clause= [ k+ " as `" +v+"`" for (k,v) in zip(columns,names) ]
            
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
                condition_text_array.append(condition_text)

        having_str = " and ".join(having)

        if where:
            where_str= " where (%s) and (%s) " %(where,having_str)
        elif having:
            where_str=" where %s " % having_str

        query_str+=where_str
        ## At this point we can add the group by calculated above, and replace the names and columns arrays from the group by

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

        ## This is used to render things in the popups. The query string here is naked without order by clauses
        query_str_basic = query_str
        query_str+= " order by %s " % order

        #Calculate limits
        if not query.has_key('limit'):
            query['limit'] = "0"

        self.previous = int(query['limit']) - config.PAGESIZE
        self.next = int(query['limit']) + config.PAGESIZE
        self.pageno =  int(query['limit']) /config.PAGESIZE
                
        query_str+=" limit %u, %u" % (int(query['limit']) , config.PAGESIZE)

        dbh = DB.DBO(case)

        #Do the query, and find out the names of all the columns
        dbh.execute(query_str,())

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
            self.popup(table_groupby_popup,'Graph',icon='pie.png',toolbar=1,menubar=1)

        ## Write the conditions at the top of the page:
        if conditions:
            self.start_table()
            self.row("The following filter conditions are enforced")
            for i in conditions:
                self.row(i)
            self.row("Click any of the above links to remove this condition")
            self.end_table()
            self.start_table()

        ## Draw a popup to allow the user to save the entire table in CSV format:
        def save_table(query,result):
            result.display=result.__str__
            result.type = "text/x-comma-separated-values"
##            result.type = "text/plain"
            data = cStringIO.StringIO()
            cvs_writer = csv.DictWriter(data,names)
            dbh.execute(query_str_basic + " order by %s" % order,())
            for row in dbh:
                ## If there are any callbacks we respect those now.
                for k,v in row.items():
                    try:
                        row[k]=callbacks[k](v)
                    except (KeyError,Exception):
                        pass
                cvs_writer.writerow(row)

            data.seek(0)
            result.result = "#Pyflag Table widget output\n#Query was %s.\n#Fields: %s\n""" %(query," ".join(names))
            if condition_text_array:
                result.result += "#The following conditions are in force\n"
                for i in condition_text_array:
                    result.result += "# %s\n" % i
            result.result += data.read()
                
        self.popup(save_table,'Save Table',icon="floppy.png")

        tmp_links = []
        for d in names:
            #instatiate a whole lot of UI objects (based on self) for the table header
            tmp = self.__class__(self)

            #Create links to the current query as well as an ordering parameter - note the addition of parameters we get by using the new query's str method, and the addition of parameters by using named args...
            try:
                assert(query['dorder'] == d)
                tmp.link(d,target=new_query,order=d)
            except (KeyError,AssertionError):
                tmp.link(d,target=new_query,dorder=d)


            #If the current header label is the same one in ordered_col, we highlight it to show the user which column is ordered:
            if names[ordered_col] == d:
                tmp2=self.__class__(self)
                tmp2.start_table()
                tmp2.row(tmp,bgcolor=config.HILIGHT)
                tmp = tmp2
                
            tmp_links.append(tmp)

        #This array keeps track of each column width
        width = [ len(d) for d in names ]

        #output the table header
        self.row(*tmp_links)

        #This is used to keep track of the lines with a common sorting key: common = (bgcolor state, last value)
        common = [False,0]
        count =0
        
        #output the rest of the lines in a table:
        while 1:
            row = dbh.cursor.fetchone()
            if not row: break

            #Form a row of strings
            row_str = [ "%s" % d for d in row ]

            #Update the maximum width of each column
            for d in range(len(width)):
                if width[d] < len(row_str[d]):
                    width[d] = len(row_str[d])

            #Work through the row and create entry uis for each of them.
            for i in range(len(row_str)):
                value=row_str[i]

                ## Check if the user specified a callback for this column
                if callbacks.has_key(names[i]):
                    value=callbacks[names[i]](value,result=self)

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
            if common[1] != row[ordered_col]:
                common[1] = row[ordered_col]
                common[0] = not common[0]

            options = {}
            if common[0]:
                bgcolor1=config.BGCOLOR
                bgcolor=config.BGCOLOR1
            else:
                bgcolor1=config.BGCOLOR1
                bgcolor=config.BGCOLOR
                
            options['bgcolor'] = bgcolor
            options['onmouseover']="setPointer(this,%u,'over',%r,%r,%r);" % (count,bgcolor,config.HILIGHT,config.SELECTED)
            options['onmouseout']="setPointer(this,%u,'out',%r,%r,%r);" % (count,bgcolor,config.HILIGHT,config.SELECTED)
            options['onmousedown']="setPointer(this,%u,'click',%r,%r,%r);" % (count,bgcolor,config.HILIGHT,config.SELECTED)

            count += 1
            #Add the row in
            self.row(*row_str,**options)

        if opts.has_key('simple'):
            return

        if not groupby:
            self.row("click here to group by column",colspan=50,align='center')

            #Insert the group by links at the bottom of the table
#            del new_query['group_by']
            tmp_links = []
            for d in names:
                tmp = self.__class__(self)
                tmp.link(d,target=new_query,group_by=d)
                tmp_links.append(tmp)
                
            self.row(*tmp_links)
            
        self.row("Enter a term to filter on field (% is wildcard)",colspan=50,align='center')

        #Clear off any query objects starting with where_.... Do we want to do this? it might be useful to continually drill down with a number of conditions...
#        for k in new_query.keys():
#            if k.startswith('where_'):
#                del new_query[k]

        #Now create a row with input boxes for each parameter
        tmp_links=[]
        for d in range(len(names)):
            tmp = self.__class__(self)
            #It doesnt make sense to search for columns with callbacks, so we do not need to show the form.
            if callbacks.has_key(names[d]):
                try:
                    cb_result=callbacks[names[d]](query['where_%s' % names[d]])
                    new_q=query.clone()
                    del new_q['where_%s' % names[d]]
                    tmp.link(cb_result,new_q)
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
        self.row(*names)

        #If our row count is smaller than the page size, then we dont have another page, set next page to None
        if count < config.PAGESIZE:
            self.next = None

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
            if options.has_key('color') and options['color'] != self.color:
                format += "</font><font color=%r>" %(options['color'])
                self.color = options['color']
       
            if options.has_key('font') and options['font'] != self.font:
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

            self.result += "%s%s" % (format,d)

        for d in cuts:
            self.text_var += str(d)
            if options.has_key('wrap') and options['wrap'] == 'full':
                try:
                    while self.text_var:
                        index = self.text_var.find("\n")
                        
                        if index<0 or index>self.text_var.find("\r"):
                            index = self.text_var.find("\r")
                            
                        if index<0:
                            index=len(self.text_var)
                            
                        if index > wrap:
                            do_options(self.text_var[0:wrap],options)
                            self.text_var = self.text_var[wrap:]
                            self.result+="<img src='/flag/images/next_line.png'>\n"
                        else:
                            do_options("%s\n" % self.text_var[:index],options)
                            self.text_var = self.text_var[index+1:]
                except ValueError:
                    pass
                
            else:
                do_options(self.text_var,options)
                self.text_var = ''

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
            ## If additional was not specified, we take the default from the current value of name
            import cgi
            try:
                default = cgi.escape(self.defaults[name],quote=True)
            except KeyError:
                pass
            
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
            ## If additional was not specified, we take the default from the current value of name
            import cgi
            try:
                default = cgi.escape(self.defaults[name],quote=True)
            except KeyError:
                pass
            
            ## And remove if from the form
            if self.form_parms.has_key(name):
                del self.form_parms[name]
        
        option_str = self.opt_to_str(options)
        left = description
        right = "<textarea name='%s' %s>%s</textarea>" % (name,option_str,default)
        self.row(left,right,valign="top")
        
    def tooltip(self,message):
        message = message.replace("\n"," ")
        self.result = "<abbr title=%r>%s</abbr>" % (message,self.result)
        
    def start_form(self,target, **hiddens):
        """ start a new form with a local scope for parameters.

        @arg target: A query_type object which is the target to the form. All parameters passed through this object are passed to the form's action.
        """
        self.form_parms=target.clone()
        #Append the hidden params to the object
        for k,v in hiddens:
            self.form_parms[k]=v

        self.result += "<form method=get action='/f'>\n"

    def end_form(self,name='Submit'):
        for k,v in self.form_parms:
            self.result += "<input type=hidden name='%s' value='%s'>\n" % (k,v)

        if name:
            self.result += "<input type=submit value='%s'></form>\n" % name 

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
        
    def refresh(self,interval,query):
        self.meta += "<META HTTP-EQUIV=Refresh Content=\"%s; URL=/f?%s\">" % (interval,query)

    def icon(self, path, **options):
        """ This allows the insertion of a small static icon picture. The image should reside in the images directory."""
        option_str = self.opt_to_str(options)
        self.result += "<img src=/flag/images/%s %s />" % (path, option_str)

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

        out='\n<table border=0 cellspacing=0 cellpadding=0 width=100%><tr><td colspan=50><img height=20 width=1 alt=""></td></tr><tr>'
        
        for i in names:
            q=query.clone()
            tmplink=self.__class__()
            del q[context]
            q[context]=i
            tmplink.link(i,q)

            if(i==context_str):
                out+="<td width=15>&nbsp;</td><td bgcolor=#3366cc align=center nowrap><font color=#ffffff size=-1><b>%s</b></font></td>" % i
            else:
                out+='<td width=15>&nbsp;</td><td id=1 bgcolor=#efefef align=center nowrap><font size=-1>%s</font></td>' % (tmplink)

        out+="<td colspan=50>&nbsp;</td></tr><tr><td colspan=50 bgcolor=#3366cc><img width=1 height=1 alt=""></td></tr>"
        
        #Now draw the results of the callback:
        cb=cbfunc(query)
	if not self.binary:
	        out+="<tr><td colspan=50><table border=1 width=100%%><tr><td>%s</td></tr></table></td></tr></table>" % cb
       		self.result+=out
