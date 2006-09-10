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
    def __init__(self,default = None,query=None):
        HTMLUI.HTMLUI.__init__(self, default,query)
        self.floats = []

    def __str__(self):
        ## Ensure that floats occur _after_ everything else - this is
        ## required if they need to have forms later:
        result = HTMLUI.HTMLUI.__str__(self)

        if self.floats:
            result += "\n".join(self.floats)
            
        return result
        
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

        try:
            default = self.defaults[name]
        except:
            default = ''
        
        tmp = '<input name=\"%s\" dojoType="combobox" style="width: 300px;" autocomplete="true" %s maxListLength="15" dataUrl="f?callback_stored=%s" defaultValue=%r />\n' % (name,opt_str,cb, default);

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

    def tree(self, tree_cb = None, pane_cb=None, branch = None, layout=None):
        """ A tree widget.

        This implementation uses javascript/iframes extensively.
        """            
        id = self.get_uniue_id()

        def right(query,result):
            result.decoration = "raw"
            result.content_type = "text/html"
            
            try:
                path=FlagFramework.normpath(query['open_tree'])
            except KeyError:
                path='/'
                
            pane_cb(path,result)

        def tree(query,result):
            result.decoration = "raw"
            result.content_type = "text/html"

            ## I think this is secure enough??? This should really be
            ## json.parse but do we need to pull in a whole module
            ## just for this???
            data = eval(query['data'],{'__builtins__':None, 'true':True, 'false':False})
            path=FlagFramework.normpath(data['node']['objectId'])

            r=[]
            for x in tree_cb(path):
                if not x[0] or len(x[0])==0: continue
                
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
        try:
            branch = FlagFramework.splitpath(self.defaults['open_tree'])
        except KeyError:
            branch = ['']

        def do_node(depth,path):
            if depth>=len(branch): return ''
            
            result=''
            for x in tree_cb('/'+'/'.join(branch[:depth])):
                if len(x[0])==0: continue

                if not x[1]: continue

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

        tree_nodes='<div dojoType="TreeNode" isFolder="true" title="/" objectId="/" expandlevel="1">%s</div>' % do_node(0,'')

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
                         
    def start_form(self,target, **hiddens):
        """ start a new form with a local scope for parameters.

        @arg target: A query_type object which is the target to the form. All parameters passed through this object are passed to the form's action.
        """
        self.form_parms=target.clone()
        self.form_id=self.get_uniue_id()
        try:
            ## FIXME - this should be named to something better than "refresh"
            self.form_target = hiddens['refresh']
            del hiddens['refresh']
        except KeyError:
            self.form_target = 'self'

        #Append the hidden params to the object
        for k,v in hiddens.items():
            self.form_parms[k]=v

        self.result += '<form id="pyflag_form_%s" name="pyflag_form_%s" method=%s action="/f" enctype="multipart/form-data">\n' % (self.form_id,self.form_id, config.METHOD)

    def end_form(self,value='Submit',name='submit',**opts):
        for k,v in self.form_parms:
            ## If we want to refresh to our parent, we need to ensure
            ## that our callback does not propegate:
            if self.form_target=="parent" and k=="callback_stored": continue

            self.result += "<input type='hidden' name='%s' value='%s'>\n" % (k,v)

        if value:
            self.result += "<button dojoType='Button' onClick='javascript:submitForm(\"pyflag_form_%s\",\"form%s\");'>%s</button><div id=\"form%s\"></div>\n" % (self.form_id, self.form_id, value, self.form_id)

        self.result+="</form>"

    def get_uniue_id(self):
        self.id+=1
        return self.id

    def table(self,sql="select ",columns=[],names=[],links=[],table='',where='',groupby = None,case=None,callbacks={},**opts):        
        names = list(names)
        columns = list(columns)
        id=self.get_uniue_id()
            
        def table_cb(query,result):
            menus = []

            ## May only offer to group by if the report does not issue
            ## its own
            if not groupby:
                if query.has_key("group_by"):
                    q=query.clone()
                    del q['group_by']
                    menus.append('<div dojoType="MenuItem2" caption="Ungroup" onClick="update_container(\'tableContainer%s\',\'%s\');"></div>\n' % (id,q))
                else:
                    menus.append('<div dojoType="MenuItem2" caption="Group By Column" onClick="group_by(\'%s\')"></div>\n' % id)

            menus.append('<div dojoType="MenuItem2" caption="Filter Column" onClick="filter_column(\'%s\')"></div>\n' % id)
            menus.append('<div dojoType="MenuSeparator2"></div>\n')

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
                    menus.append('<div dojoType="MenuItem2" caption=%r onClick="update_container(\'tableContainer%s\',\'%s\');"></div>\n' % (condition_text,id,q))


            result.result +='''
            <div id="popup%s" dojoType="PopupMenu2" targetNodeIds="tableContainer%s" toggle="explode"  >
            %s
            </div>
            ''' % (id,id,''.join(menus))

            ## If no ordering is specified we order by the first column
            if not query.has_key('order') and not query.has_key('dorder'):
                query['order']=names[0]
                
            order = names[0]

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

            result.result+='''<table id="Table%s" query="%s" class="PyFlagTable" >
            <thead><tr>''' % (id, new_query)

            ## Now make the table headers:
            for n in new_names:
                try:
                    if query['dorder']==n:
                        result.result+="<th id='%s' sort='1' onclick=\"update_container('tableContainer%s','%s&order=%s')\" >%s<img src='/images/increment.png' /></th>\n" % (n,id, new_query,n,n)
                        order = query['dorder']
                        continue

                except KeyError:
                    try:
                        if query['order']==n:
                            result.result+="<th id='%s' sort='0' onclick=\"update_container('tableContainer%s','%s&dorder=%s')\" >%s<img src='/images/decrement.png' /></th>\n" % (n,id, new_query,n,n)
                            order = query['order']
                            continue
                    
                    except KeyError:
                        pass

                result.result+="<th id='%s' sort='1' onclick=\"update_container('tableContainer%s','%s&order=%s')\" >%s</th>\n" % (n,id, new_query,n,n)
                    
            result.result+='''</tr></thead><tbody class="scrollContent">'''

            ## Now the contents:
            old_sorted = None
            old_sorted_style = ''
            
            for row in dbh:
                row_elements = []
                tds = ''
                
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

                    ## If the value is the same as above we do not need to flip it:
                    if new_names[i]==order and value!=old_sorted:
                        old_sorted=value
                        if old_sorted_style=='':
                            old_sorted_style='alternateRow'
                        else:
                            old_sorted_style=''

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
                    if new_names[i]==order:
                        tds+="<td class='sorted-column' column='%s' table_id='%s'>%s</td>" % (new_names[i],id, value)
                    else:
                        tds+="<td column='%s'>%s</td>" % (new_names[i],value)
                    
                result.result+="<tr class='%s'> %s </tr>\n" % (old_sorted_style,tds)
            result.result+="</tbody></table>"

        cb=self.store_callback(table_cb)
        
        self.result += '''
        <div id="tableContainer%s" dojoType="ContentPane"  cacheContent="false"  layoutAlign="client"
        style="overflow: auto;"
        executeScripts="true"
        onunload="remove_popups(this);"
        >''' % (id)
        table_cb(self.defaults,self)

        self.result+="</div>"

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

        if self.defaults.has_key("__pane__"):
            pane = "%r" % self.defaults['__pane__']
        else:
            pane = "find_widget_type_above('ContentPane','Link%s')" % self.id

##       else:
##          pane = "'main'"
##        else:
##            pane = "find_widget_type_above('FloatingPane','Link%s')" % self.id
##        pane="dojo.widget.getWidgetById('Link%s')"% self.id

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
            if 'parent' in tmp:
                pane = "find_widget_type_above('ContentPane','Link%s')" % self.id
                del q['callback_stored']
                    
            elif 'popup' in tmp:
                options['onclick'] ="window.open('%s','client','HEIGHT=600,WIDTH=600,scrollbars=yes')" % q
                self.result+="<a href=# %s >%s</a>" %(self.opt_to_str(options),string)
                return
        except KeyError:
            pass

        ## If the user right clicked, we open in a new window
        base = '<a %s id="Link%s" onclick="set_url(%s, \'/f?%s\');" href="#">%s</a>' % (self.opt_to_str(options),self.id, pane, q,string)
            
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
        """ Refreshes the given content pane into the specified query in a certain time.

        if interval is 0 we do it immediately.
        """
        if options.has_key('parent'):
            del query['callback_stored']
            ## This is the pane we will try to refresh
            pane = "find_widget_type_above('ContentPane',_container_.widgetId)"
        ## Unless a specific pane is specified
        elif options.has_key('pane'):
            pane = "%r" % options['pane']
        else:
            pane = "_container_"
            
        ## Do we want to do this immediately?
        if interval==0:
            self.result+="""<script>
            update_container(%s,'%s');
            </script>""" % (pane, query)
        else:
            ## We mark the current container as pending an update, and
            ## then schedule an update fo it later on. If it has been
            ## updated by some other mechanism, it will be marked as
            ## not longer pending, and we ignore it.
            self.result+="""<script>
            _container_.pending = true;
            
            dojo.lang.setTimeout(function () {
            if(_container_.pending)
                 update_container(%s,'%s');
            } , %s);
            </script>""" % (pane,query, interval*1000)

    def add_to_top_ui(self, data):
        s = self
        while s.parent:
            s=s.parent

        s.floats.append(data)

    def popup(self,callback, label,icon=None,toolbar=0, menubar=0, tooltip=None, **options):
        if not tooltip: tooltip = label
        cb = self.store_callback(callback)
        self.add_to_top_ui('''<div widgetId="float%s" dojoType="FloatingPane" style="width: 640px; height: 400px; left: 100px; top: 100px;" windowState="minimized" displayMinimizeAction = "true"  hasShadow="true"  resizable="true"  executeScripts="true" title="%s"></div>''' % (self.id,tooltip))

        if icon:
            label = "<img alt=%r border=0 src='images/%s' />" % (label, icon)

        self.result+='''<a href="#" onclick="show_popup('float%s',%r)">%s</a>\n''' % (self.id, "%s&callback_stored=%s" % (self.defaults,cb), label)
