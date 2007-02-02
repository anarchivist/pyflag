import pyflag.HTMLUI as HTMLUI
import pyflag.DB as DB
import pyflag.conf
import pyflag.pyflaglog as pyflaglog
import pyflag.FlagFramework as FlagFramework
config=pyflag.conf.ConfObject()
import time,re
import pyflag.TableObj as TableObj
import pyflag.parser as parser

entities = { "&nbsp;": " ", "&lt;":"<", "&gt;":">", "&amp;":"&" }
def escape_entities(data):
    for k,v in entities.items():
        data = data.replace(v,k)

    return data

def unescape_entities(data):
    for k,v in entities.items():
        data = data.replace(k,v)

    return data

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

        out=''
        selectedTab = None
        
        for i in range(len(names)):
            id = "PagePane%s" % self.get_unique_id()
            if selectedTab==None: selectedTab=id
            try:
                if query['mode']==names[i]:
                    selectedTab = id
            except:
                pass
            
            new_query = query.clone()
            new_query['callback_stored'] = self.store_callback(callbacks[i])

            out+='''<div id="%s" widgetId="%s"
            dojoType="ContentPane"
            href="f?__pane__=%s&%s"
            cacheContent="false" 
            executeScripts="true"
            style="display: none; height: 100%%; overflow: auto;"
            refreshOnShow="false"
            label="%s"></div>\n''' % (id,id, id, new_query,names[i])
        
        self.result+='''<div
        id="mainTabContainer"
        widgetId="mainTabContainer"
        dojoType="TabContainer"
        selectedTab="%s"
        style="width: 100%%; height: 90%%"
        executeScripts="true"
        selectedTab="0">%s</div>''' % (selectedTab,out)

    def tree(self, tree_cb = None, pane_cb=None, branch = None, layout=None):
        """ A tree widget.

        This implementation uses javascript/iframes extensively.
        """            
        id = self.get_unique_id()

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
	activeSizing="0"
        style="border: 0px ; width: 100%%; height: 100%%; overflow: hidden;"
        >
        <div dojoType="ContentPane"
        cacheContent="false" 
        layoutAlign="left"
        id="treepane%(id)s"
        widgetId="treepane%(id)s"
        right_cb="%(r)s"
        sizeMin="20" sizeShare="80"
        style="border: 0px ; width: 25%%; min-height: 100%%; overflow: auto;"
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
        widgetId="rightpane%(id)s"
        executeScripts="true"
        layoutAlign="client"
        style="border: 0px ; width: 75%%; height: 100%%; overflow: auto;"
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
        self.form_id=self.get_unique_id()
        try:
            self.form_target = hiddens['pane']
            del hiddens['pane']
        except KeyError:
            self.form_target = 'self'

        #Append the hidden params to the object
        for k,v in hiddens.items():
            self.form_parms[k]=v

        self.result += '<form id="pyflag_form_%s" name="pyflag_form_%s" method=%s action="/f" enctype="multipart/form-data">\n' % (self.form_id,self.form_id, config.METHOD)

    def end_form(self,value='Submit',name='submit',**opts):
        pane = self._calculate_js_for_pane("Button%s" % self.form_id, target=self.form_parms, pane=self.form_target)

        for k,v in self.form_parms:
            ## If we want to refresh to our parent, we need to ensure
            ## that our callback does not propegate:
            if k=="submit" or k.startswith("__") or k.startswith("dojo."):
                continue

            self.result += "<input type='hidden' name='%s' value='%s'>\n" % (k,v)

        if value:
            self.result += "<button dojoType='Button' widgetId='Button%s' onClick=\"javascript:submitForm('pyflag_form_%s',%s);\">%s</button>\n" % (self.form_id, self.form_id, pane, value)

        self.result+="</form>"

    def filter_string(self,filter_str):
        ## Remove any HTML tags which may be present:
        filter_str = re.sub("<[^>]*>",'',filter_str)
        
        ## Unescape any entities:
        return unescape_entities(filter_str)

    ## This is a re-implementation of the table widget.
    def table(self,elements=[],table='',where='',groupby = None,case=None, **opts):
        """ The Table widget.

        In order to create a table, we need to accept a list of elements. The elements are objects derived from the ColumnType class:
        result.table(
            elements = [ ColumnType(name = 'TimeStamp',
                                    sql = 'from_unixtime(time)',
                                    link = query),
                         ColumnType('Data', 'data'),
                         ]
            table = 'TestTable',
            )
        """
        id = self.get_unique_id()
        
        def table_cb(query,result):
            ## Building up the args list in this way ensure that defaults
            ## can be specified in _make_sql itself and not be overwritten
            ## by our defaults.
            try:
                order = int(query.get('order',0))
            except: order=0

            try:    limit = int(query.get('limit',0))
            except: limit = 0

            args = dict( elements = elements, table = table, case=case,
                         groupby = groupby, order = order, limit = limit)

            if where: args['where'] = where

            try:    args['filter'] = self.filter_string(query['filter'])
            except: pass

            try:    args['direction'] = query['direction']
            except: pass

            sql = self._make_sql(**args)
            print sql
            
            result.result+='''<table id="Table%s" class="PyFlagTable" >
            <thead><tr>''' % (id)

            ## Make the table headers with suitable order by links:
            for e in range(len(elements)):
                new_query = query.clone()
                n = elements[e].name

                if order==e:
                    if query.get('direction','1')=='1':
                        del new_query['direction']
                        del new_query['order']
                        result.result+="<th id='th_%s' sort='1' onclick=\"update_container('tableContainer%s','%s&order=%s&direction=0')\" >%s<img src='/images/increment.png' /></th>\n" % (n,id, new_query,e, n)
                    else:
                        del new_query['direction']
                        del new_query['order']
                        result.result+="<th id='th_%s' sort='1' onclick=\"update_container('tableContainer%s','%s&order=%s&direction=1')\" >%s<img src='/images/decrement.png' /></th>\n" % (n,id, new_query,e,n)
                else:
                    del new_query['order']
                    del new_query['direction']
                    result.result+="<th id='th_%s' sort='1' onclick=\"update_container('tableContainer%s','%s&order=%s&direction=1')\" >%s</th>\n" % (n,id, new_query,e,n)
                    

            result.result+='''</tr></thead><tbody class="scrollContent">'''

            ## Now do the rows:
            dbh = DB.DBO(case)
            dbh.execute(sql)
            old_sorted = None
            old_sorted_style = ''
            
            ## Total number of rows
            row_count=0

            for row in dbh:
                row_elements = []
                tds = ''
                
                ## Render each row at a time:
                for i in range(len(elements)):
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
                        tds+="<td class='sorted-column' column='%s' table_id='%s'>%s</td>" % (elements[i].name,id , value)
                    else:
                        tds+="<td column='%s'>%s</td>" % (elements[i].name, value)
                    
                result.result+="<tr class='%s'> %s </tr>\n" % (old_sorted_style,tds)
                row_count += 1

            result.result+="</tbody></table>"

            new_id = self.get_unique_id()

            ## Now we add the paging toolbar icons
            ## The next button allows user to page to the next page
            if row_count<config.PAGESIZE:
                ## We could not fill a full page - means we ran out of
                ## rows in this table
                next_button = "add_toolbar_disabled('/images/stock_next-page.png', 'tableContainer%(id)s', 'next_button_%(new_id)s', 'tabletoolbar%(id)s');" % (
                    dict(id=id,
                         new_id=new_id));
            else:
                next_button = "add_toolbar_link('/images/stock_next-page.png','f?limit=%(limit)s&%(query)s', 'tableContainer%(id)s', 'tableContainer%(id)s', 'next_button_%(new_id)s', 'tabletoolbar%(id)s');" % (
                    dict(limit = limit + config.PAGESIZE,
                         query = query,
                         id=id,
                         new_id=new_id));
                result.tooltip('next_button_%s' % new_id, "Next Page (rows %s-%s)" % (limit,limit+config.PAGESIZE))

            ## The previous button goes back if possible:
            previous_limit = limit-config.PAGESIZE
            if previous_limit<0:
                previous_button = "add_toolbar_disabled('/images/stock_previous-page.png', 'tableContainer%(id)s', 'prev_button_%(new_id)s', 'tabletoolbar%(id)s');" % (
                    dict(id=id,
                         new_id=new_id));
            else:
                previous_button = "add_toolbar_link('/images/stock_previous-page.png','f?limit=%(limit)s&%(query)s', 'tableContainer%(id)s', 'tableContainer%(id)s', 'prev_button_%(new_id)s', 'tabletoolbar%(id)s');" % (
                    dict(limit = previous_limit,
                         query = query,
                         id=id,
                         new_id=new_id));
                
                result.tooltip('prev_button_%s' % new_id, "Previous Page (rows %s-%s)" % (previous_limit, previous_limit+config.PAGESIZE))

            result.result+='''<script>
            %s%s
            </script>''' % (previous_button, next_button)

            return

        cb=self.store_callback(table_cb)
        
        self.result += '''
        <div class="TableLayout" id="TableMain%(id)s" widgetId="TableMain%(id)s" dojoType="LayoutContainer"  cacheContent="false"
        layoutChildPriority='top-bottom'
        style="height: 90%%;"
        >
        <div dojoType="ToolbarContainer" layoutAlign="top" id="TableToolbarContainer%(id)s" widgetId="TableToolbarContainer%(id)s" layoutAlign="top">
        <div dojoType="Toolbar" id="tabletoolbar%(id)s" widgetId="tabletoolbar%(id)s"></div>
        </div>
        <div class="tableContainer" widgetId="tableContainer%(id)s" id="tableContainer%(id)s"
        dojoType="ContentPane"  cacheContent="false"
        layoutAlign="client"
        style="overflow-x: auto; overflow-y: hidden;"
        executeScripts="true"
        ></div>\n''' % {'id':id}

        ## This callback will render the filter GUI popup. There is some raw
        ## javascript in here to make life a little easier.
        def filter_gui(query, result):
            result.heading("Filter Table")
            try:
                filter_str = self.filter_string(query['filter'])
                result.para(filter_str)

                ## Check the current filter string for errors by attempting to parse it:
                try:
                    sql = parser.parse_to_sql(filter_str,elements)

                    ## This is good if we get here - lets refresh to it now:
                    if query.has_key('__submit__'):
                        result.refresh(0,query,pane='parent')
                        return
                    
                except Exception,e:
                    result.text('Error parsing expression: %s' % e, color='red')
                    result.text('\n',color='black')
                    
            except KeyError:
                pass

            result.start_form(query, pane="self")

            result.textarea("Search Query", 'filter')

            result.result += """<tr></tr>
            <tr><td colspan=2 align=center>The following can be used to insert text rapidly into the search string</td></tr>
            <tr><td>Column</td><td>
            <select name=filter_column>
            %s
            </select> <a href=# onclick='var t=dojo.widget.manager.getWidgetById("filter"); t.execCommand("inserthtml", document.getElementsByName("filter_column")[0].value);'>Insert </a></td></tr>
            """ % "\n".join(["<option value=' \"%s\" '>%s</option>" % (e.name,e.name) for e in elements])

            ## Round up all the possible methods from all colmn types:
            operators = {}
            for e in elements:
                for method in e.operators():
                    operators[method]=1

            methods = operators.keys()
            methods.sort()
            result.result+="""<tr><td>Operators</td><td>
            <select name=filter_operators>
            %s
            </select><a href=# onclick='var t=dojo.widget.manager.getWidgetById("filter"); t.execCommand("inserthtml", document.getElementsByName("filter_operators")[0].value);'>Insert </a></td></tr>
            """ % "\n".join(["<option value=' %s '>%s</option>" % (m,m) for m in methods])

            result.end_form()

        ## Add a toolbar icon for the filter:
        self.toolbar(toolbar="tabletoolbar%s" % id,
                     cb=filter_gui, pane='popup', icon='filter.png'
                     )

        ## Update the table with its initial view
        self.result+='''<script>
        _container_.addOnLoad( function() {
            set_url("tableContainer%s","f?%s&callback_stored=%s");
        });
        </script>''' % (id, self.defaults,cb)

    def xxxtable(self,sql="select ",columns=[],names=[],links=[],types={},table='',where='',groupby = None,case=None,callbacks={}, **opts):        
        names = list(names)
        columns = list(columns)
        id=self.get_unique_id()
        
        def table_cb(query,result):
            """ This callback is used to render the actual table in
            its requested pane
            """
            menus = []
            new_id = self.get_unique_id()

            ## May only offer to group by if the report does not issue
            ## its own
            if not groupby:
                if query.has_key("group_by"):
                    q=query.clone()
                    del q['group_by']
                    menus.append('<div dojoType="MenuItem2" caption="Ungroup" onClick="update_container(\'tableContainer%s\',\'%s\');"></div>\n' % (id,q))
                else:
                    pane = result._calculate_js_for_pane(None, None, "self")
                    menus.append('<div dojoType="MenuItem2" caption="Group By Column" onClick="group_by(\'Table%s\',%s)"></div>\n' % (id,pane))

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
            <div id="popup%s" widgetId="popup%s" dojoType="PopupMenu2" targetNodeIds="tableContainer%s" toggle="explode"  >
            %s
            </div>
            ''' % (id,id, id,''.join(menus))

            ## If no ordering is specified we order by the first column
            if not query.has_key('order') and not query.has_key('dorder'):
                query['order']=names[0]
                
            order = names[0]
            try:
                limit = int(query['limit'])
            except:
                limit = 0

            ## Clean up the filter string if possible:
            try:
                print "cleaning out filter string %s" % query['filter']
                filter_str = query['filter']
                del query['filter']
                query['filter'] = self.filter_string(filter_str)
                print "Got %s" % query['filter']
            except KeyError:
                pass

            dbh,new_query,new_names,new_columns,new_links = self._make_sql(
                sql=sql,
                columns=columns,
                names=names,
                links=links,
                table=table,
                where=where,
                groupby=groupby,
                case=case,
                callbacks=callbacks,
                limit = limit,
                types = types,
                query=query)

            if not new_query.has_key('callback_stored'):
                new_query['callback_stored'] = cb

            result.result+='''<table id="Table%s" query="%s" class="PyFlagTable" >
            <thead><tr>''' % (id, new_query)

            ## Now make the table headers:
            for n in new_names:
                try:
                    if query['dorder']==n:
                        result.result+="<th id='th_%s' sort='1' onclick=\"update_container('tableContainer%s','%s&order=%s')\" >%s<img src='/images/increment.png' /></th>\n" % (n,id, new_query,n,n)
                        order = query['dorder']
                        self.tooltip("th_%s" % n, "Sort by %s" % n)
                        continue

                except KeyError:
                    try:
                        if query['order']==n:
                            result.result+="<th id='th_%s' sort='0' onclick=\"update_container('tableContainer%s','%s&dorder=%s')\" >%s<img src='/images/decrement.png' /></th>\n" % (n,id, new_query,n,n)
                            order = query['order']
                            self.tooltip("th_%s" % n, "Reverse sort by %s" % n)
                            continue
                    
                    except KeyError:
                        pass

                result.result+="<th id='th_%s' sort='1' onclick=\"update_container('tableContainer%s','%s&order=%s')\" >%s</th>\n" % (n,id, new_query,n,n)
                self.tooltip("th_%s" %n, "Sort by %s" % n)
                    
            result.result+='''</tr></thead><tbody class="scrollContent">'''

            ## Now the contents:
            old_sorted = None
            old_sorted_style = ''
            ## Total number of rows
            row_count=0
            
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
                        value=escape_entities(value)

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
                row_count += 1
            result.result+="</tbody></table>"

            ## Add the various toolbar icons:
            ## The next button allows user to page to the next page
            if row_count<config.PAGESIZE:
                ## We could not fill a full page - means we ran out of
                ## rows in this table
                next_button = "add_toolbar_disabled('/images/stock_next-page.png', 'tableContainer%(id)s', 'next_button_%(new_id)s', 'tabletoolbar%(id)s');" % (
                    dict(id=id,
                         new_id=new_id));
            else:
                next_button = "add_toolbar_link('/images/stock_next-page.png','f?limit=%(limit)s&%(query)s', 'tableContainer%(id)s', 'tableContainer%(id)s', 'next_button_%(new_id)s', 'tabletoolbar%(id)s');" % (
                    dict(limit = limit + config.PAGESIZE,
                         query = query,
                         id=id,
                         new_id=new_id));
                result.tooltip('next_button_%s' % new_id, "Next Page (rows %s-%s)" % (limit,limit+config.PAGESIZE))

            ## The previous button goes back if possible:
            previous_limit = limit-config.PAGESIZE
            if previous_limit<0:
                previous_button = "add_toolbar_disabled('/images/stock_previous-page.png', 'tableContainer%(id)s', 'prev_button_%(new_id)s', 'tabletoolbar%(id)s');" % (
                    dict(id=id,
                         new_id=new_id));
            else:
                previous_button = "add_toolbar_link('/images/stock_previous-page.png','f?limit=%(limit)s&%(query)s', 'tableContainer%(id)s', 'tableContainer%(id)s', 'prev_button_%(new_id)s', 'tabletoolbar%(id)s');" % (
                    dict(limit = previous_limit,
                         query = query,
                         id=id,
                         new_id=new_id));
                
                result.tooltip('prev_button_%s' % new_id, "Previous Page (rows %s-%s)" % (previous_limit, previous_limit+config.PAGESIZE))

            result.result+='''<script>
            %s%s
            </script>''' % (previous_button, next_button)

        cb=self.store_callback(table_cb)
        
        self.result += '''
        <div class="TableLayout" id="TableMain%(id)s" widgetId="TableMain%(id)s" dojoType="LayoutContainer"  cacheContent="false"
        layoutChildPriority='top-bottom'
        style="height: 90%%;"
        >
        <div dojoType="ToolbarContainer" layoutAlign="top" id="TableToolbarContainer%(id)s" widgetId="TableToolbarContainer%(id)s" layoutAlign="top">
        <div dojoType="Toolbar" id="tabletoolbar%(id)s" widgetId="tabletoolbar%(id)s"></div>
        </div>
        <div class="tableContainer" widgetId="tableContainer%(id)s" id="tableContainer%(id)s"
        dojoType="ContentPane"  cacheContent="false"
        layoutAlign="client"
        style="overflow-x: auto; overflow-y: hidden;"
        executeScripts="true"
        ></div>\n''' % {'id':id}

        ## Work out the types:
        for n in names:
            if not types.has_key(n):
                types[n] = TableObj.ColumnType()

        ## This callback will render the filter GUI popup. There is some raw
        ## javascript in here to make life a little easier.
        def filter_gui(query, result):
            result.heading("Filter Table")
            try:
                filter_str = self.filter_string(query['filter'])
                result.para(filter_str)

                ## Check the current filter string for errors by attempting to parse it:
                try:
                    sql = parser.parse_to_sql(filter_str,types)

                    ## This is good - lets refresh to it now:
                    if query.has_key('__submit__'):
                        result.refresh(0,query,pane='parent')
                        return
                    
                except Exception,e:
                    result.text('Error parsing expression: %s' % e, color='red')
                    result.text('\n',color='black')
                    
            except KeyError:
                pass

            result.start_form(query, pane="self")

            result.textarea("Search Query", 'filter', cols=60, rows=5)

            result.result += """<tr></tr>
            <tr><td colspan=2 align=center>The following can be used to insert text rapidly into the search string</td></tr>
            <tr><td>Column</td><td>
            <select name=filter_column>
            %s
            </select> <a href=# onclick='var t=dojo.widget.manager.getWidgetById("filter"); t.execCommand("inserthtml", document.getElementsByName("filter_column")[0].value);'>Insert </a></td></tr>
            """ % "\n".join(["<option value=' \"%s\" '>%s</option>" % (n,n) for n in names])

            ## Round up all the possible methods from all colmn types:
            operators = {}
            for t in types.values():
                for method in t.operators():
                    operators[method]=1

            methods = operators.keys()
            methods.sort()
            result.result+="""<tr><td>Operators</td><td>
            <select name=filter_operators>
            %s
            </select><a href=# onclick='var t=dojo.widget.manager.getWidgetById("filter"); t.execCommand("inserthtml", document.getElementsByName("filter_operators")[0].value);'>Insert </a></td></tr>
            """ % "\n".join(["<option value=' %s '>%s</option>" % (m,m) for m in methods])

            result.end_form()

        ## Add a toolbar icon for the filter:
        self.toolbar(toolbar="tabletoolbar%s" % id,
                     cb=filter_gui, pane='popup', icon='filter.png'
                     )

        self.result+='''<script>
        _container_.addOnLoad( function() {
            set_url("tableContainer%s","f?%s&callback_stored=%s");
        });
        </script>''' % (id, self.defaults,cb)

    def _calculate_js_for_pane(self, element_id=None, target=None, pane="'main'"):
        """ Returns the JS string required to facilitate opening in the requested pane

        Modifies query to remove stored callbacks if needed.

        element_id: The ID of the element we are trying to
        create. This will be used to calculate the container we are
        in, if that was not supplied.

        target: The query we should link to. We will delete callbacks from it if needed.

        pane: Where we want to open the link can be:
        main (default): refresh to the main pane (default).
        parent: refresh to the pane that contains this pane. (useful for popups etc).
        popup: open a new popup window and draw the target in that.
        self: refresh to the current pane (useful for internal links in popups etc).
        """
        ## Open to the container we live in
        if pane=='parent':
            if target:
                target.poparray('callback_stored')
                
            if self.defaults.has_key("__pane__"):
                pane = "find_widget_type_above('ContentPane',%r)" % self.defaults['__pane__']
            else:
                pane = '"main"'

        # open to the current container:
        elif pane=='self':
            if self.defaults.has_key("__pane__"):
                pane = "'%s'" % self.defaults['__pane__']
            elif element_id:
                pane = "find_widget_type_above('ContentPane',%r)" % element_id
            else:
                pane="'main'"

        elif pane=='main':
            if target:
                target.poparray('callback_stored')
                
            pane = "'main'"

        elif pane=='popup':
            popup_id = self.get_unique_id()
            self.add_to_top_ui('''<div widgetId="float%s" dojoType="FloatingPane" style="display: none; width: 640px; height: 400px; left: 100px; top: 100px;" windowState="minimized" displayMinimizeAction = "true"  hasShadow="true"  resizable="true"  executeScripts="true"></div>''' % (popup_id))

            pane = "'float%s'" % (popup_id)
            
        return pane

    def link(self,string,target=None,options=None,icon=None,tooltip='',pane='main', **target_options):
        """ The user can specify which pane the link will open in by using the pane variable:

        pane can be:

        main (default): refresh to the main pane (default).
        parent: refresh to the pane that contains this pane. (useful for popups etc).
        popup: open a new popup window and draw the target in that.
        self: refresh to the current pane (useful for internal links in popups etc).
        """
        ## If the user specified a URL, we just use it as is:
        try:
            self.result+="<a href='%s'>%s</a>" % (target_options['url'],string)
            return
        except KeyError:
            pass

        ## The target query can over ride the pane specification
        try:
            pane = target['__targetpane__']
            del target['__targetpane__']
        except:
            pass
        
        if target==None:
            target=FlagFramework.query_type(())

        if not options:
            options={}
            
        q=target.clone()
        if target_options:
            for k,v in target_options.items():
                del q[k]
                q[k]=v

        pane = self._calculate_js_for_pane("Link%s" % self.id, target=q, pane=pane)

        if icon:
            tmp = self.__class__(self)
            tmp.icon(icon,tooltip=string+tooltip,border=0)
            string=tmp

        if pane=='popup':
            def popup_cb(query, result):
                self.refresh(0, target)
                
            self.popup(popup_cb, string, icon=icon, tooltip=tooltip)
            return
        
        else:
            ## This has a valid href so that it is possible to right
            ## click and open in new tab or save the link in a normal
            ## bookmark
            base = '<a %s id="Link%s" onclick="update_container(%s, \'/f?%s\'); return false;" href="/f?%s&__pane__=main">%s</a>' % (self.opt_to_str(options),self.id, pane, q, q,  string)
            if tooltip:
                self.tooltip("Link%s" % self.id, tooltip)

        self.result+=base

    def icon(self, path, tooltip=None, **options):
        id = self.get_unique_id()
        option_str = self.opt_to_str(options)
        self.result += "<img id='img%s' border=0 src='images/%s' %s />" % (id, path, option_str)
        if tooltip:
            self.tooltip("img%s" % id, tooltip)

    def _dojo_delayed_execution(self,string):
        self.result+='''<script>
        _container_.addOnLoad( function() {
        %s
        });
        </script>''' % string
        

    def new_toolbar(self):
        """ Creates a new toolbar in the current UI to allow private
        buttons to be added to it

        Returns the toolbar ID which may be used as an option for
        toolbar().
        """
        id = "Toolbar%s" % self.get_unique_id()
        self.result+='''<div dojoType="LayoutContainer"
        cacheContent="false" layoutChildPriority="top-bottom" >'''
        self.result+='''<div dojoType="ToolbarContainer" id="container%(id)s" widgetId="container%(id)s" layoutAlign="top">
        <div dojoType="Toolbar" id="%(id)s"></div>
        </div>
        <div dojoType="ContentPane"
        layoutAlign="top"
        executeScripts="true"
        cacheContent="false">
        ''' % dict(id=id)

        self.add_to_top_ui("</div></div>")
        return id

    def toolbar(self,cb=None,text='',icon=None,popup=True,tooltip='',
                link=None, pane="'main'", toolbar="toolbar"):
        """ Create a toolbar button.

        When the user clicks on the toolbar button, a popup window is
        created which the callback function then uses to render on.

        pane specifies the target of the toolbar's action:
        main (default): refresh to the main pane (default).
        parent: refresh to the pane that contains this pane. (useful for popups etc).
        popup: open a new popup window and draw the target in that.
        self: refresh to the current pane (useful for internal links in popups etc).

        toolbar is the name of the toolbar we want to add to. Its normally left as the default main toolbar.
        """
        id = self.id

        ## Find out the value of the current container we are at
        try:
            container = "'%s'" % self.defaults['__pane__']
        except:
            container = "'main'"


        ## We delay execution to add_toolbar* functions in case a
        ## local toolbar was created
        if link:
            pane = self._calculate_js_for_pane(target=link, pane=pane)
            self._dojo_delayed_execution("add_toolbar_link('/images/%s','f?%s',%s, %s, 'toolbarbutton%s', %r);" % (icon, link, pane, container, id, toolbar))
                        
        elif cb:
            cb_key = self.store_callback(cb)
            target = self.defaults.clone()
            #target.poparray('callback_stored')
            target['callback_stored'] = cb_key
            pane = self._calculate_js_for_pane(target=target, pane=pane)
            self._dojo_delayed_execution("add_toolbar_link('/images/%s','f?%s',%s, %s, 'toolbarbutton%s', %r);" % (icon, target, pane, container, id, toolbar))

        ## Button is disabled:
        else:
            pane = self._calculate_js_for_pane(pane=pane)
            self._dojo_delayed_execution("add_toolbar_disabled('/images/%s',%s, %s, %r);" % (icon, pane, container, toolbar))

        ## FIXME: This needs to be done using js so it can be delayed
        ## until the delayed execution clauses are done.
#        if tooltip or text:
#            self.tooltip("toolbarbutton%s" % id, tooltip+text)

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

    def refresh(self,interval,query, pane='self', **options):
        """ Refreshes the given content pane into the specified query in a certain time.

        if interval is 0 we do it immediately.
        """
        pane = self._calculate_js_for_pane(None, query, pane)
        
        ## Do we want to do this immediately?
        if interval==0:
            self.result+="""<script>
            update_container(%s,'%s');
            </script>""" % (pane, query)
        else:
            ## We mark the current container as pending an update, and
            ## then schedule an update to it later on. If it has been
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

    def tooltip(self, widget, text):
        """ Inserts a tooltip on a widgetId. Mostly used from within AJAXUI """
        self.add_to_top_ui('''<span dojoType="tooltip" connectId="%s" >%s</span>\n''' % (widget, text))
        
    def popup(self,callback, label,icon=None,toolbar=0, menubar=0, tooltip=None, **options):
        if not tooltip: tooltip = label
        image_id = self.get_unique_id()
        cb = self.store_callback(callback)
        self.add_to_top_ui('''<div widgetId="float%s" dojoType="FloatingPane" style="width: 640px; height: 400px; left: 100px; top: 100px;" windowState="minimized" displayMinimizeAction = "true"  hasShadow="true"  resizable="true"  executeScripts="true" title="%s"></div>''' % (image_id,tooltip))
        
        if icon:
            label = "<img alt=%r border=0 src='images/%s' />" % (label, icon)

        if tooltip:
            self.tooltip("popup%s" % image_id, tooltip)

        self.result+='''<a href="#" id="popup%s" onclick="show_popup('float%s',%r)">%s</a>\n''' % (image_id,image_id, "%s&callback_stored=%s" % (self.defaults,cb), label)


    def date_selector(self, description, variable):
        try:
            date = self.defaults[variable]
        except KeyError:
            date = time.strftime("%Y-%m-%d")
        text = '<div dojoType="dropdowndatepicker" date="%s" containerToggle="fade" displayFormat="dd/MM/yyyy" name=%r></div>\n' % (date,variable)
        self.row(description, text)
        ## And remove if from the form
        if self.form_parms.has_key(variable):
            del self.form_parms[variable]

    def wizard(self,names=[],context="wizard",callbacks=[],title=''):
        tmp = []
        for i in range(len(names)):
            tmp.append('<div widgetId="page%s" dojoType="WizardPane" label="%s"></div>' % (i,names[i]))

        self.result+='''<div id="wizard1" dojoType="WizardContainer"
        style="width: 100%%; height: 200px;"
        nextButtonLabel="next >>"
        previousButtonLabel="<< previous"
        cancelFunction="cancel"
         >%s</div>''' % '\n'.join(tmp)

        cb = [ self.store_callback(c) for c in callbacks ]

        self.result+='''<script>
        _container_.addOnLoad( function() {
            set_url("page0","f?%s&callback_stored=%s");
        });
        </script>''' % (self.defaults, cb[0])

    def textarea(self,description,name, **options):
        """ Draws a text area with the default content

        This is very similar to the textfield above.
        """
        try:
            default = self.sanitise_data(self.defaults[name])
        except (KeyError,AttributeError):
            default =''
            
        ## And remove if from the form
        if self.form_parms.has_key(name):
            del self.form_parms[name]
        
#        option_str = self.opt_to_str(options)
        left = description
        right='''<div name="%s" dojoType="RichText" widgetId="%s" height=60 focusOnLoad="true" style="border: 3px outset black;">%s</div>''' % (name, name, default)

        self.row(left,right,valign="top")

