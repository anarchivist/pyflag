import pyflag.HTMLUI as HTMLUI
import pyflag.DB as DB
import pyflag.conf
import pyflag.logging as logging
import pyflag.FlagFramework as FlagFramework
config=pyflag.conf.ConfObject()
import cgi

class AJAXUI(HTMLUI.HTMLUI):
    """ An AJAX driven web framework for PyFlag """
    preamble='<script> PyFlag_Session=%s</script>'
    
    def const_selector(self,description,name,keys,values,**options):
        if options:
            opt_str = self.opt_to_str(options)
        else: opt_str = ''

        ## Convert the keys and values to json:
        def const_selector_cb(query,result):
            out = [ [k,v] for k,v in zip(keys,values) ]
            result.decoration='raw'
            result.result = "%s" % out

        cb = self.store_callback(const_selector_cb)
        
        tmp = '<input name=\"%s\" dojoType="combobox" style="width: 300px;" autocomplete="true" %s maxListLength="15" dataUrl="f?callback_stored=%s" />\n' % (name,opt_str,cb);

        #Remove this from the form_parms
        if self.form_parms.has_key(name):
            del self.form_parms[name]
            
        #Draw in a nice table format
        self.row(description,tmp)

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

        def tab(query,result):
            result.decoration = "raw"
            result.content_type = "text/html"

            try:
                index = int(query['tab'])
            except (ValueError,KeyError):
                index=0

            del query['callback_stored']
            del query['right_pane_cb']
            
            callbacks[index](query,result)

        t=self.store_callback(tab)

        out = '''<div
        id="mainTabContainer"
        dojoType="TabContainer"
        style="width: 100%; height: 100%"
        executeScripts="true"
        selectedTab="0">\n'''

        del query['callback_stored']
        query['callback_stored'] = t
        for i in range(len(names)):
            del query['tab']
            query['tab']=i
            tmplink=self.__class__()
            out+='''<div id="%s"
            dojoType="ContentPane"
            href="f?%s"
            cacheContent="false" 
            executeScripts="true"
            style="display: none;"
            refreshOnShow="false"
            label="%s"></div>\n''' % (self.id, query,names[i])
        
        self.result+=out+"</div>"

    def make_branch(self, string):
        try:
            ## Get the right part:
            path = FlagFramework.normpath(string)
            branch=path.split('/')
        except KeyError:
            branch=['/']
        
        return branch

    def tree(self, tree_cb = None, pane_cb=None, branch = None, layout=None):
        """ A tree widget.

        This implementation uses javascript/iframes extensively.
        """            
        id = self.get_uniue_id()

        def right(query,result):
            result.decoration = "raw"
            result.content_type = "text/html"
            branch = self.make_branch(query['open_tree'])
            pane_cb(branch,result)

        def tree(query,result):
            result.decoration = "raw"
            result.content_type = "text/html"

            ## I think this is secure enough???
            data = eval(query['data'],{'__builtins__':None, 'true':True, 'false':False})
            path=FlagFramework.normpath(data['node']['objectId'])
            if path.startswith('/'): path=path[1:]
            branch=path.split("/")

            r=[]
            for x in tree_cb(branch):
                if len(x[0])==0: continue
                
                tmp = dict(title = x[0], objectId="/%s/%s" % (path,x[1]))
                if x[2]=='branch':
                    tmp['isFolder']='true'
                else:
                    tmp['isFolder']='false'
                r.append(tmp)

            result.result=r
         
        t=self.store_callback(tree)
        r=self.store_callback(right)
        query = self.defaults.clone()

        ## Calculate the default tree structure which is obtained from query['open_tree']
        branch = self.make_branch(query['open_tree'])
        
        def do_node(depth,path):
            if depth>=len(branch): return ''
            
            result=''
            for x in tree_cb(branch[:depth]):
                if len(x[0])==0: continue

                if x[2]=='branch':
                    isFolder='true'
                else:
                    isFolder='false'

                children=''
                opened='0'
                if x[1]==branch[depth]:
                    children = do_node(depth+1,path+'/'+branch[depth])
                    opened='1'
                    
                result+='<div dojoType="TreeNode" isFolder="%s" title="%s" objectId="%s" expandlevel="%s" >%s</div>' % (isFolder,x[0],'/'.join((path,x[1])),opened,children)
                
            return result

        tree_nodes='<div dojoType="TreeNode" isFolder="true" title="/" objectId="/" expandlevel="1">%s</div>' % do_node(1,'')

        ## Calculate the initial contents of the right pane:
        right_ui = self.__class__(self)
        right(query,right_ui)
        
        del query['open_tree']

        self.result+="""
        <div dojoType="SplitContainer"
	orientation="horizontal"
	sizerWidth="5"
	activeSizing="1"
        style="border: 0px ; width: 100%%; height: 100%%; overflow: auto;"
        >
        <div dojoType="ContentPane"
        cacheContent="false" 
        layoutAlign="client"
        id="treepane%(id)s"
        right_cb="%(r)s"
        sizeMin="20" sizeShare="80"
        style="border: 0px ; width: 25%%; height: 100%%; overflow: auto;"
        executeScripts="true">

        <dojo:TreeSelector widgetId="treeSelector%(id)s" eventNames="select:nodeSelected"></dojo:TreeSelector>
        <div dojoType="TreeLoadingController" RPCUrl="f?%(query)s&callback_stored=%(t)s" widgetId="treeController%(id)s" ></div>
            <div dojoType="Tree" toggle="fade" controller="treeController%(id)s" selector="treeSelector%(id)s" widgetId="tree%(id)s">
            %(tree_nodes)s
          </div>
        
	</div>

	<div dojoType="ContentPane"
        cacheContent="false" 
        id="rightpane%(id)s"
        executeScripts="true"
        style="border: 0px ; height: 100%%; overflow: auto;"
        sizeMin="50" sizeShare="50"> %(right_pane)s
	</div>
        </div>
        """ % {'query':query,'t':t,'id':id, 'r':r, 'right_pane': right_ui,
               'tree_nodes':tree_nodes}

        ## Populate the initial tree state: FIXME: This needs to be a
        ## lot more specific.
        self.result+="""<script>

        _container_.addOnLoad(function() {
		dojo.event.topic.subscribe("nodeSelected",
			 function(message) {
                         update_tree(\"%(r)s\",\"f?%(query)s&open_tree=\"+message.node.objectId,'%(id)s');
                         message.node.onTreeClick();
                         }
		);
                });
        </script>
        """ % {'r':r, 'query':query, 'id':id }

    def end_form(self,value='Submit',name='submit',**opts):
        for k,v in self.form_parms:
            self.result += "<input type=hidden name='%s' value='%s'>\n" % (k,v)

        if value:
            self.result += "<button dojoType='Button' onClick='javascript:submitForm(\"pyflag_form_%s\",\"form%s\");'>%s</button><div id=\"form%s\"></div>\n" % (self.depth, self.id, value, self.id)

        self.result+="</form>"

    def get_uniue_id(self):
        self.id+=1
        return self.id

    def table(self,sql="select ",columns=[],names=[],links=[],table='',where='',groupby = None,case=None,callbacks={},**opts):        
        names = list(names)
        columns = list(columns)

        def table_cb(query,result):
            id=self.get_uniue_id()

            result.result += '''
            <div id="tableContainer%s" dojoType="ContentPane"  cacheContent="false"  layoutAlign="client"
            style="overflow: auto;"
            executeScripts="true" >''' % (id)
            
            result.result += '''<div id="popup%s" >''' % id
            
            menus = []

            ## May only offer to group by if the report does not issue
            ## its own
            if not groupby:
                if query.has_key("group_by"):
                    q=query.clone()
                    del q['group_by']
                    menus.append('<div dojoType="MenuItem2" caption="Ungroup" onClick="update_container(\'tableContainer%s\',\'%s\');"></div>' % (id,q))
                else:
                    menus.append('<div dojoType="MenuItem2" caption="Group By Column" onClick="group_by(\'%s\')"></div>' % id)

            menus.append('<div dojoType="MenuItem2" caption="Filter Column" onClick="filter_column(\'%s\')"></div>' % id)
            menus.append('<div dojoType="MenuSeparator2"></div>')

            ## Now present the user with options of removing conditions:
            having=[]
            for d,v in query:
                if d.startswith('where_'):
                    #Find the column for that name
                    try:
                        index=names.index(d[len('where_'):])
                    except ValueError:
                    ## If we dont know about this name, we ignore it.
                        continue

                    condition_text = FlagFramework.make_sql_from_filter(v, having, columns[index],d[len('where_'):])

                    q=query.clone()
                    q.remove(d,v)
                    menus.append('<div dojoType="MenuItem2" caption=%r onClick="update_container(\'tableContainer%s\',\'%s\');"></div>' % (condition_text,id,q))


            result.result+='''
            <div dojoType="PopupMenu2" targetNodeIds="popup%s" toggle="explode">
            %s
            </div>
            ''' % (id,''.join(menus))


            ## If no ordering is specified we order by the first column
            if not query.has_key('order') and not query.has_key('dorder'):
                query['order']=names[0]
            
            dbh,new_query,new_names,new_columns,new_links = self._make_sql(
                sql,
                columns,
                names,
                links,
                table,
                where,
                groupby,
                case,
                callbacks,
                query)

            if not new_query.has_key('callback_stored'):
                new_query['callback_stored'] = cb

            result.result+='''<table dojoType="PyFlagTable" widgetId="Table%s" headClass="fixedHeader" tbodyClass="scrollContent" enableMultipleSelect="true" enableAlternateRows="true" rowAlternateClass="alternateRow" cellpadding="0" cellspacing="0" border="0" query="%s" global_id="%s">
            <thead><tr>''' % (id, new_query, id)

            ## Now make the table headers:
            for n in new_names:
                try:
                    if query['order']==n:
                        result.result+="<th id='%s' sort='1' >%s</th>\n" % (n,n)
                        continue

                except KeyError:
                    try:
                        if query['dorder']==n:
                            result.result+="<th id='%s' sort='0' >%s</th>\n" % (n,n)
                            continue
                    
                    except KeyError:
                        pass

                result.result+="<th id='%s' >%s</th>\n" % (n,n)
                    
            result.result+='''</tr></thead><tbody>'''

            ## Now the contents:
            for row in dbh:
                result.result+="\n<tr>"

                row_elements = []
                
                ## Render each row at a time:
                for i in range(len(new_names)):
                    value = row[new_names[i]].__str__()

                    ## Check if the user specified a callback for this column
                    if callbacks.has_key(new_names[i]):
                        value=callbacks[new_names[i]](value)
                    else:
                    ## Sanitise the value to make it HTML safe. Note that
                    ## callbacks are required to ensure they sanitise
                    ## their output if they need.
                        value=cgi.escape(value)

                    ## Now add links if they are required
                    try:
                        if new_links[i]:
                            q = new_links[i]
                            try:
                                q=q.clone()
                                q.FillQueryTarget(value)

                            #No __target__ specified go straight here
                            finally:
                                tmp = self.__class__(self)
                                tmp.link(value, q)
                                value=tmp

                    #links array is too short
                    except IndexError:
                        pass

                    if value==' ': value="&nbsp;"
                    result.result+="<td>%s</td>" % (value)
                    
                result.result+="</tr>"
            result.result+="</tbody></table></div></div>"

        cb=self.store_callback(table_cb)
        table_cb(self.defaults,self)

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

        if target.has_key("__pane__"):
            pane = "find_widget_type_above('ContentPane','Link%s')" % self.id
        else:
            pane = "'main'"

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
        base = '<a %s id="Link%s" onclick="update_container(%s, \'/f?%s\');" href="#">%s</a>' % (self.opt_to_str(options),self.id, pane, q,string)
            
        if tooltip:
            self.result+="<abbr title='%s'>%s</abbr>" % (tooltip,base)
        else:
            self.result+=base

    def toolbar(self,cb=None,text=None,icon=None,popup=True,tooltip=None,link=None):
        """ Create a toolbar button.

        When the user clicks on the toolbar button, a popup window is
        created which the callback function then uses to render on.
        """
        id = self.id

        if link:
            result="<script>\n add_toolbar_link('/images/%s','f?%s','dummy%s');\n</script><div id='dummy%s'></div>" % (icon, link, id,id)
                        
        elif cb:
            cb_key = self.store_callback(cb)
            result="<script>\n add_toolbar_callback('/images/%s','f?callback_stored=%s','dummy%s');\n</script><div id='dummy%s'></div>" % (icon, cb_key, id,id)

        ## Button is disabled:
        else:
            result="<script>\n add_toolbar_disabled('/images/%s','dummy%s');\n</script><div id='dummy%s'></div>" % (icon,id, id)

        self.result+=result

    def download(self,file):

        def Download_file(query,result):
            magic=FlagFramework.Magic(mode='mime')
            file.seek(0)
            data=file.read(1000)
            result.generator.content_type=magic.buffer(data)
            try:
                result.generator.headers=[("Content-Disposition","attachment; filename=%s" % file.inode),]
            except AttributeError:
                result.generator.headers=[("Content-Disposition","attachment; filename=%s" % file.name),]

            file.seek(0)
            result.generator.generator=file

        cb=self.store_callback(Download_file)
        
        self.result = "<a href='f?%s&callback_stored=%s'>Click to Download file</a>" % (self.defaults,cb)

    def refresh(self,interval,query,**options):
        pass
        
