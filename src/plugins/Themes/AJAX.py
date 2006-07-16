""" An AJAX based theme """
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FlagFramework as FlagFramework
import pyflag.Registry as Registry
import pyflag.Theme as Theme
import pyflag.DB as DB
from plugins.Themes.Menus import Menu

class AJAX(Menu):
    header='''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
        <html>
        <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>%s</title>
        <link rel="stylesheet" type="text/css" href="images/pyflag.css" />
        <script type="text/javascript">
        var djConfig = { isDebug: true, baseScriptUri: "javascript/" };
        </script>
        <script type="text/javascript" src="/javascript/dojo.js"></script>
        <script type="text/javascript" src="/javascript/functions.js"></script>
 
        <script type="text/javascript">
        dojo.require("dojo.widget.ComboBox");
        dojo.require("dojo.widget.SplitContainer");
	dojo.require("dojo.widget.ContentPane");
        dojo.require("dojo.widget.TabContainer");
	dojo.require("dojo.widget.LinkPane");
	dojo.require("dojo.widget.LayoutContainer");
        dojo.require("dojo.widget.Tree");
        dojo.require("dojo.widget.TreeSelector");
        dojo.require("dojo.widget.TreeLoadingController");
        dojo.require("dojo.widget.Menu2");
	dojo.require("dojo.widget.Button");
        dojo.require("dojo.widget.PyFlagTable");
        
        function update_tree(rightcb,url) {
        var rightpane = dojo.widget.getWidgetById("rightpane");
        rightpane.setUrl(url+"&callback_stored="+rightcb);
        };

        function update_main(url) {
          var main = dojo.widget.getWidgetById("main");
          main.setUrl(url);
        };

        function submitForm(form_name) {

        
        var kw = {
          url:	   "/f",
          formNode:dojo.byId(form_name),
          load:	   function(type, data)	{
                  var main = dojo.widget.getWidgetById("main");
                  main.setContent(data);
                },
          error:   function(type, error)	{ alert(String(type)+ String(error)); },
          method:  "POST",
        };
        
        dojo.io.bind(kw);
	}

        </script>

        <style type="text/css">
        body {
	font-family : sans-serif;
        }
        
        .dojoTabPaneWrapper {
        padding : 10px 10px 10px 10px;
        }

		/***
			The following is just an example of how to use the table.
			You can override any class names to be used if you wish.
		***/

		table {
			font-family:Lucida Grande, Verdana;
			font-size:0.8em;
			width:100%%;
			border:1px solid #ccc;
			cursor:default;
		}

		* html div.tableContainer {	/* IE only hack */
			width:95%%;
			border:1px solid #ccc;
			height: 285px;
			overflow-x:hidden;
			overflow-y: auto;
		}

		table td,
		table th{
			border-right:1px solid #999;
			padding:2px;
			font-weight:normal;
		}
		table thead td, table thead th {
			background:#94BEFF;
		}
		
		* html div.tableContainer table thead tr td,
		* html div.tableContainer table thead tr th{
			/* IE Only hacks */
			position:relative;
			top:expression(dojo.html.getFirstAncestorByTag(this,'table').parentNode.scrollTop-2);
		}
		
		html>body tbody.scrollContent {
			height: 262px;
			overflow-x:hidden;
			overflow-y: auto;
		}

		tbody.scrollContent td, tbody.scrollContent tr td {
			background: #FFF;
			padding: 2px;
		}

		tbody.scrollContent tr.alternateRow td {
			background: #e3edfa;
			padding: 2px;
		}

		tbody.scrollContent tr.selected td {
			background: yellow;
			padding: 2px;
		}
		tbody.scrollContent tr:hover td {
			background: #a6c2e7;
			padding: 2px;
		}
		tbody.scrollContent tr.selected:hover td {
			background: #ff3;
			padding: 2px;
		}

                tbody.scrollContent td.sorted-column {
                        background: pink;
                }

        </style>
        </head>
        <body link=blue vlink=blue bgcolor="#FFFFFF">
        
        <div dojoType="LayoutContainer"
	layoutChildPriority='top-bottom'
	style="width: 100%%; height: 70%%;">
        '''

    footer="</div>"
    def make_menu_javascript(self,query):
        """ Creates the javascript required to generate the menu """
        ## Find all families:
        module_list = Registry.REPORTS.get_families()
        Theme.order_families(module_list)
        menus = []

        result = '''<style>
	/* group multiple buttons in a row */
	.box {
		display: block;
		text-align: center;
	}
	.box .dojoButton {
		float: left;
		margin-right: 10px;
	}
	.dojoButton .dojoButtonContents {
		font-size: small;
	}

	/* make the menu style match the buttons */
	.dojoPopupMenu2, .dojoPopupMenu2Client, .dojoMenuItem2,
		.dojoMenuItem2Label, 
		.dojoMenuItem2Accel {
		color: black;
		background-color: #B9D4FE;
		border:1px solid #b8d4fe;
	}
	
	body .dojoMenuItem2.dojoMenuItem2Hover,
		.dojoMenuItem2.dojoMenuItem2Hover .dojoMenuItem2Label, 
		.dojoMenuItem2.dojoMenuItem2Hover .dojoMenuItem2Accel,
		.dojoMenuItem2.dojoMenuItem2Hover .dojoMenuItem2Icon {
			background-color: white;
                        border-color: white;
	}

	/* todo: find good color for disabled menuitems, and teset */
	.dojoMenuItem2Disabled .dojoMenuItem2Label span,
	.dojoMenuItem2Disabled .dojoMenuItem2Accel span {
		color: ThreeDShadow;
	}
	
	.dojoMenuItem2Disabled .dojoMenuItem2Label span span,
	.dojoMenuItem2Disabled .dojoMenuItem2Accel span span {
		color: ThreeDHighlight;
	}

        html, body{	
           width: 100%;	/* make the body expand to fill the visible window */
           height: 100%;
           overflow: hidden;	/* erase window level scrollbars */
           padding: 0 0 0 0;
           margin: 0 0 0 0;
        }


        </style>'''

        for k in module_list:
            submenu_text = ''
            ## Add the reports in the family:
            report_list = Registry.REPORTS.family[k]
            for r in report_list:
                if r.hidden: continue

                submenu_text+='''<div dojoType="MenuItem2" caption="%s" onClick="update_main('%s');"></div>\n''' % (r.name,FlagFramework.query_type((),family=k,report=r.name))

            if len(submenu_text)>0:
                menus.append('<div dojoType="PopupMenu2" id="%s" toggle="wipe">%s</div> <button dojoType="dropdownButton" menuId="%s">%s</button>' % (k,submenu_text,k,k))


        return result+'''<div dojoType="ContentPane" layoutAlign="top" style="color: black; text-color: black;">
		<div class="box">%s</div>
	</div>''' % (''.join(menus))

    def naked_render(self,data='',ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % FlagFramework.flag_version):
        """ Render the ui with minimal interventions """
        if not ui.toolbar_ui:
            toolbar_str='&nbsp;&nbsp;'
        else:
            toolbar_str=ui.toolbar_ui.__str__()

        return " ".join(
            (self.header % (title),
             data))

    def render(self, query=FlagFramework.query_type(()), meta='',data='',next=None,previous=None,pageno=None,ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % FlagFramework.flag_version):
        return data
        result="""<style>
        div.main {
           border: 5px;
           width: 100%;
           height: 100%;
           overflow-x: scroll;
           overflow-y: auto;
        };
        </style>
        """+data

#        print result
        return result
        
    def menu(self,flag,query):
        result=flag.ui()
        
        self.menu_javascript = self.make_menu_javascript(query)
        title="FLAG - Forensic Log Analysis GUI. %s" % FlagFramework.flag_version

        data="<img src='images/logo.png>"
        
        result.result+=" ".join(
            (self.header % (title),self.menu_javascript,
             '<div dojoType="ContentPane" id="toolbar">\n</div>\n',
             '<div dojoType="ContentPane" id="main" style="border: 5px">\n %s</div>\n'% data,
             self.footer))

        return result
