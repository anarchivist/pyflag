""" A more advanced menu based theme """
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FlagFramework as FlagFramework
import pyflag.Registry as Registry
import pyflag.Theme as Theme
import pyflag.DB as DB

class Menu(Theme.BasicTheme):
    """ Class to implement the Menus theme """
    preamble = "<script src='/javascript/functions.js'></script>\n"

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
    
    <div class=PyFlagHeader>
      <div class=Toolbar>
      </div><div class="Logo"> PyFlag</div>
    </div>    
    <div class=PyFlagPage>
    '''
    header='''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
        <html>
        <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>%s</title>
        <link rel="stylesheet" type="text/css" href="images/pyflag.css" />
        <script src="/javascript/functions.js" type="text/javascript" language="javascript"></script>

        </head>
        <body link=blue vlink=blue bgcolor="#FFFFFF">
        <script>
        var keepstatic=1 //specify whether menu should stay static 0=non static (works only in IE4+)
        var menucolor="black" 
        var submenuwidth=150
        </script>
        <script type="text/javascript" src="/javascript/menu.js" language="javascript"></script>'''

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

    def raw_render(self,data='',ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % FlagFramework.flag_version):
        return data

    def naked_render(self,data='',ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % FlagFramework.flag_version):
        """ Render the ui with minimal interventions """
        if not ui.toolbar_ui:
            toolbar_str='&nbsp;&nbsp;'
        else:
            toolbar_str=ui.toolbar_ui.__str__()

        return " ".join(
        ('<link rel="stylesheet" type="text/css" href="images/pyflag.css" />',
         self.preamble,
         "<table><tr><td>%s</td></tr></table>" % (data),
         ))

    def render(self, ui=None, data='', title="FLAG - Forensic Log Analysis GUI. %s" % FlagFramework.flag_version):
        self.menu_javascript = self.make_menu_javascript(ui.defaults)

        if not ui.toolbar_ui:
            toolbar_str='&nbsp;&nbsp;'
        else:
            toolbar_str=ui.toolbar_ui.__str__()

        try:
            case = "Case %s - " % ui.defaults['case']
        except:
            case =''

        result = '''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
        <html>
          <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            <title>%s</title>
            <link rel="stylesheet" type="text/css" href="images/pyflag.css" />
            <script src="/javascript/functions.js" type="text/javascript" language="javascript"></script>
          </head>
        <body link=blue vlink=blue bgcolor="#FFFFFF">
        <script>
        var keepstatic=1 //specify whether menu should stay static 0=non static (works only in IE4+)
        var menucolor="black" 
        var submenuwidth=150
        if(!window.name) window.name="main";
        </script>
        <script type="text/javascript" src="/javascript/menu.js" language="javascript"></script>''' % title

        result += self.menu_javascript
        result += '''<script>
        if(window.name=="main") {
           showToolbar();
        };
        </script>'''

        result += '''<div class=PyFlagHeader>
        <div class=Toolbar> %s
        </div><div class="Logo"> PyFlag</div>
        </div>    
        <div class=PyFlagPage>
        ''' % toolbar_str

        result += data
        result += "</div>" + self.footer

#        print result
        return result
