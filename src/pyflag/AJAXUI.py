import pyflag.HTMLUI as HTMLUI
import pyflag.DB as DB
import pyflag.conf
import pyflag.logging as logging
import pyflag.FlagFramework as FlagFramework
config=pyflag.conf.ConfObject()

class AJAXUI(HTMLUI.HTMLUI):
    """ An AJAX driven web framework for PyFlag """
    preamble='%s'
    
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
        style="width: 100%; height: 70%"
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
                cb = link['callback_stored']
                del link['callback_stored'] 
                del link['right_pane_cb']
               
                link['open_tree'] = FlagFramework.normpath("/".join(branch[:depth] + [name]))
                open_tree = FlagFramework.urlencode(link['open_tree'])
                sv=value.__str__().replace(' ','&nbsp;')
                
                if state=="branch":
                    result.result+="<a href=\"javascript:update_tree('%s','%s','f?%s')\"><img border=0 src=\"/images/folder.png\"></a>" % (cb,query['right_pane_cb'],link)
                else:
                    result.result+="<a href=\"javascript:update_tree('%s','%s','f?%s')\"><img border=0 src=\"/images/corner.png\"></a>" % (cb,query['right_pane_cb'],link)

                result.result+="&nbsp;%s</td></tr>\n" % str(sv)
                result.result+="\n"

                try:
                ## Draw any opened branches
                    if name == branch[depth]:
                        draw_branch(depth+1,query, result)
                except IndexError:
                    pass

        def left(query,result):
            result.decoration = "raw"
            result.content_type = "text/html"

            #The first item in the tree is the first one provided in branch
            link = query.clone()
            del link['callback_stored']
            del link['right_pane_cb']
            
            result.result+="<a href=\"javascript:update_tree('%s','%s','f?%s')\"><img border=0 src=\"/images/folder.png\"></a>" % (query['callback_stored'],query['right_pane_cb'],link)
            
            result.result+="&nbsp;/<br>\n"

            result.result+="<table width=100%>"
            draw_branch(1,query, result)
            result.result+="</table>"
            
        def right(query,result):
            result.decoration = "raw"
            result.content_type = "text/html"
            try:
            ## Get the right part:
                branch=query['open_tree'].split('/')
            except KeyError:
                branch=['/']

            pane_cb(branch,result)

        l = self.store_callback(left)
        r = self.store_callback(right)
        
        self.result+="""
        <div dojoType="SplitContainer"
	orientation="horizontal"
	sizerWidth="5"
	activeSizing="0"
        style="border: 0px ; width: 100%; height: 100%; overflow: auto;"
        >
        <div dojoType="ContentPane"
        layoutAlign="client"
        id="treepane"
        sizeMin="20" sizeShare="80"
        style="border: 0px ; width: 100%; height: 100%; overflow: auto;"
        executeScripts="true">
        left
	</div>
	<div dojoType="ContentPane"
        id="rightpane"
        executeScripts="true"
        style="border: 0px ; width: 100%; height: 100%; overflow: auto;"
        sizeMin="50" sizeShare="50">
        right
	</div>
        </div>
        """

        ## Populate the initial tree state:
        self.result+="""<script>

        function tree_init() {
        update_tree("%s","%s","f?%s");
        };

        _container_.addOnLoad(tree_init);
        </script>
        """ % (l,r,self.defaults)
