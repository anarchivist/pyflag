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
        
        tmp = '<select name=\"%s\" dojoType="combobox" style="width: 300px;" autocomplete="false" %s maxListLength="15">\n' % (name,opt_str);

        for k,v in zip(keys,values):
            tmp +="<option value='%s'>%s</option>\n" % (k,v)

        tmp+="</select>\n"
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
            out+='''<div
            dojoType="LinkPane"
            href="f?%s"
            executeScripts="true"
            refreshOnShow="false"
            label="%s"></div>\n''' % (query,names[i])
        
        self.result+=out+"</div>"
                 

    def tree(self, tree_cb = None, pane_cb=None, branch = None, layout=None):
        """ A tree widget.

        This implementation uses javascript/iframes extensively.
        """            
        def right(query,result):
            result.decoration = "raw"
            result.content_type = "text/html"
            try:
            ## Get the right part:
                branch=query['open_tree'].split('/')
            except KeyError:
                branch=['/']

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
        r = self.store_callback(right)

        query = self.defaults.clone()
        del query['open_tree']
        
        self.result+="""
        <div dojoType="SplitContainer"
	orientation="horizontal"
	sizerWidth="5"
	activeSizing="0"
        style="border: 0px ; width: 100%%; height: 100%%; overflow: auto;"
        >
        <div dojoType="ContentPane"
        layoutAlign="client"
        id="treepane"
        sizeMin="20" sizeShare="80"
        style="border: 0px ; width: 40%%; height: 100%%; overflow: auto;"
        executeScripts="true">

        <dojo:TreeSelector widgetId="treeSelector" eventNames="select:nodeSelected"></dojo:TreeSelector>
        <div dojoType="TreeLoadingController" RPCUrl="f?%s&callback_stored=%s" widgetId="treeController" ></div>
            <div dojoType="Tree" toggle="fade" controller="treeController" selector="treeSelector" widgetId="firstTree">
            <div dojoType="TreeNode" isFolder="true" title="/" objectId="/"></div>
          </div>
        
	</div>
	<div dojoType="ContentPane"
        id="rightpane"
        executeScripts="true"
        style="border: 0px ; width: 60%%; height: 100%%; overflow: auto;"
        sizeMin="50" sizeShare="50">
	</div>
        </div>
        """ % (query,t)

        ## Populate the initial tree state:
        self.result+="""<script>

        _container_.addOnLoad(function() {
		dojo.event.topic.subscribe("nodeSelected",
			 function(message) { update_tree("%s","f?%s&open_tree="+message.node.objectId); }
		);
                });
        </script>
        """ % (r, query )


    def end_form(self,value='Submit',name='submit',**opts):
        for k,v in self.form_parms:
            self.result += "<input type=hidden name='%s' value='%s'>\n" % (k,v)

        if value:
            self.result += "<button dojoType='Button' onClick='javascript:submitForm(\"pyflag_form_%s\");'>%s</button>\n" % (self.depth, value)

        self.result+="</form>"

    def get_uniue_id(self):
        self.id+=1
        return self.id

    def table(self,sql="select ",columns=[],names=[],links=[],table='',where='',groupby = None,case=None,callbacks={},**opts):        

        def table_cb(query,result):
            id=self.get_uniue_id()

            print id
            
            result.result += '''
            <div id="tableContainer%s" dojoType="ContentPane" layoutAlign="client"
            style="overflow: auto; wrap: full"
            executeScripts="true" >''' % (id)
            
            menus = []
            
            if query.has_key("group_by"):
                q=query.clone()
                del q['group_by']
                menus.append('<div dojoType="MenuItem2" caption="Ungroup" onClick="update_container("tableContainer%s","%s")"></div>' % (id,q))
#                menus.append('<div dojoType="MenuItem2" caption="Ungroup""></div>')
            else:
                menus.append('<div dojoType="MenuItem2" caption="Group By Column" onClick="group_by(%s)"></div>' % id)
#                menus.append('<div dojoType="MenuItem2" caption="Group By Column"></div>')


            result.result+='''
            <div dojoType="PopupMenu2" targetNodeIds="Table%s" toggle="explode">
            %s
            </div>
            ''' % (id,''.join(menus))


            del query['callback_stored']

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

            result.result+='''<table dojoType="PyFlagTable" widgetId="Table%s" headClass="fixedHeader" tbodyClass="scrollContent" enableMultipleSelect="true" enableAlternateRows="true" rowAlternateClass="alternateRow" cellpadding="0" cellspacing="0" border="0" query="%s&callback_stored=%s">
            <thead><tr>''' % (id, new_query, cb)

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
                    
            result.result+='''</tr></thead><tbody style="height: 100%;">'''

            ## Now the contents:
            for row in dbh:
                result.result+="\n<tr>"
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

                    if value==' ': value="&nbsp;"
                    result.result+="<td>%s</td>" % (value)
                result.result+="</tr>"
            result.result+="</tbody></table></div>"

        cb=self.store_callback(table_cb)
        table_cb(self.defaults,self)
