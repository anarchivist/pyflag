""" A more advanced menu based theme """
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FlagFramework as FlagFramework
import pyflag.Registry as Registry
import pyflag.Theme as Theme
import pyflag.DB as DB

class Menu(Theme.BasicTheme):
    """ Class to implement the Menus theme """
    hilight_bar = '''
    <script>        
        showToolbar();

           
        function UpdateIt(){
        if (ie&&keepstatic&&!opr6)
        document.all["MainTable"].style.top = document.body.scrollTop;
        setTimeout("UpdateIt()", 200);
        }
        UpdateIt();
    </script>
    <table cellspacing=0 cellpadding=0 width="100%%" background="flag/images/topfill.jpg" border=0> <tbody>
    <tr><td align=left>%s</td>
    <td height=25>
    <div align="right">%s PyFlag</div>
    </td>
    
    </tr>
    </tbody>
    </table>'''

    header='''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
        <html>
        <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>%s</title>
        <link rel="stylesheet" type="text/css" href="images/pyflag.css" />
        <script src="images/functions.js" type="text/javascript" language="javascript"></script>
        <style>
        all.clsMenuItemNS, .clsMenuItemIE{text-decoration: none; font: bold 12px Arial; color: white; cursor: hand; z-index:100}
        #MainTable A:hover {color: yellow;}
        </style>

        </head>
        <body link=blue vlink=blue bgcolor="#FFFFFF">
        <script>
        var keepstatic=1 //specify whether menu should stay static 0=non static (works only in IE4+)
        var menucolor="black" 
        var submenuwidth=150
        </script>
        <script type="text/javascript" src="menu.js" language="javascript"></script>'''

    def make_menu_javascript(self,query):
        """ Creates the javascript function required to generate the menu """
        result = '''<script language="javascript">
        function showToolbar() {
        menu = new Menu();'''
        
        ## Find all families:
        module_list = Registry.REPORTS.get_families()
        Theme.order_families(module_list)

        for k in module_list:
            submenu_text = ''
            ## Add the reports in the family:
            report_list = Registry.REPORTS.family[k]
            for r in report_list:
                if r.hidden: continue
                ## Only propegate if we stay within the same family:
                try:
                    if query['family']==k:
                        submenu_text+='menu.addSubItem("%s", "%s","%s","f?%s","");' % (k,r.name,r.name,Theme.propegate(query,FlagFramework.query_type((),family=k,report=r.name)))
                        continue
                except KeyError:
                    pass
                
                submenu_text+='menu.addSubItem("%s", "%s","%s","f?%s","");' % (k,r.name,r.name,FlagFramework.query_type((),family=k,report=r.name))

            if len(submenu_text)>0:
                result+='menu.addItem("%s","%s","%s",null,null);\n' % (k,k,k) + submenu_text

        return result+"menu.showMenu(); }</script>"

    def menu(self,flag,query):
        """ We just draw the main page for the database here """
        result=flag.ui()
        result.heading("PyFlag - Forensic and Log Analysis GUI")
        left = result.__class__(result)
        tmp = result.__class__(result)
        tmp.icon("logo.png")
        left.link(tmp,url="http://pyflag.sourceforge.net/")
        right = result.__class__(result)
        right.text("PyFlag is a GPL Project maintained at http://pyflag.sourceforge.net/ . \nThis is %s" % FlagFramework.flag_version ,color="red",font="bold")
        result.row(tmp,right,align="center")
        return result

    def naked_render(self,data='',ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % FlagFramework.flag_version):
        """ Render the ui with minimal interventions """
        if not ui.toolbar_ui:
            toolbar_str='&nbsp;&nbsp;'
        else:
            toolbar_str=ui.toolbar_ui.__str__()

        return " ".join(
        (self.header % (title),
         '''&nbsp </tr></table>\n''',
         self.hilight_bar % (toolbar_str,''),
         "<table><tr><td>%s</td></tr></table>" % (data),
         self.hilight_bar % (toolbar_str,''),self.footer))

    def render(self, query=FlagFramework.query_type(()), meta='',data='',next=None,previous=None,pageno=None,ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % FlagFramework.flag_version):

        self.menu_javascript = self.make_menu_javascript(query)
        self.query=query

        if not ui.toolbar_ui:
            toolbar_str='&nbsp;&nbsp;'
        else:
            toolbar_str=ui.toolbar_ui.__str__()

        try:
            case = "Case %s - " % query['case']
        except:
            case =''

        return " ".join(
            (self.header % (title),self.menu_javascript,
             meta,
             '''&nbsp </tr></table>\n''',
             self.hilight_bar % (toolbar_str,case),
             "<table><tr><td>%s</td></tr></table>" % (data),
             self.hilight_bar % (toolbar_str,case),self.footer))
