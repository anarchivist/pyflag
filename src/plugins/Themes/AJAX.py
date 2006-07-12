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

        function update_tree(leftcb,rightcb,url) {
        var treepane = dojo.widget.getWidgetById("treepane");
        var rightpane = dojo.widget.getWidgetById("rightpane");
        
        treepane.setUrl(url+"&callback_stored="+leftcb+"&right_pane_cb=" + rightcb);
        rightpane.setUrl(url+"&callback_stored="+rightcb);
        };

        </script>

        <style>
        all.clsMenuItemNS, .clsMenuItemIE{text-decoration: none; font: bold 12px Arial; color: white; cursor: hand; z-index:100}
        #MainTable A:hover {color: yellow;}
        </style>
        <style type="text/css">
        body {
	font-family : sans-serif;
        }
        .dojoTabPaneWrapper {
        padding : 10px 10px 10px 10px;
        }
        </style>
        </head>
        <body link=blue vlink=blue bgcolor="#FFFFFF">
        <script>
        var keepstatic=1 //specify whether menu should stay static 0=non static (works only in IE4+)
        var menucolor="black" 
        var submenuwidth=150
        </script>
        <script type="text/javascript" src="/javascript/menu.js" language="javascript"></script>
        '''
