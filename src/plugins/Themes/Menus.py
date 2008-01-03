""" A more advanced menu based theme """
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FlagFramework as FlagFramework
import pyflag.Registry as Registry
import pyflag.Theme as Theme
import pyflag.DB as DB

class Menu(Theme.BasicTheme):
    """ Class to implement the Menus theme """
    def make_menu_javascript(self,query):
        """ Creates the javascript function required to generate the menu """
        result = '''<table class=MenuBar><tr>'''
        submenus = ''
        
        ## Find all families:
        module_list = Registry.REPORTS.get_families()
        Theme.order_families(module_list)

        for k in module_list:
            items = 0
            submenu_text = '\n<table class=PopupMenu id="PopupMenu%s">' % k
            ## Add the reports in the family:
            report_list = Registry.REPORTS.family[k]
            for r in report_list:
                if r.hidden: continue
                submenu_text+="<tr class='MenuItem' onclick='SelectMenuItem(\"f?report=%s&family=%s\")'><td>%s</td></tr>\n" % (r.name, k, r.name)
                items += 1
                continue

            if items > 0:
                result += "\n<td class=MenuBarItem id='MenuBarItem%s' onmouseover='displaySubMenu(\"%s\")'>%s</td>" % (k,k,k.replace(" ","&nbsp;"))
                submenus += submenu_text + "</table>"

        return result + "<td style='width=100%'></td></tr></table>" + submenus
    
    def menu(self,flag,query, result):
        """ We just draw the main page for the database here """
        result.heading("PyFlag - Forensic and Log Analysis GUI")
        left = result.__class__(result)
        tmp = result.__class__(result)
        tmp.icon("logo.png")
        left.link(tmp,url="http://www.pyflag.net/")
        right = result.__class__(result)
        right.text("PyFlag is a GPL Project maintained at http://www.pyflag.net/ . \nThis is version %s" % config.VERSION ,style="red",font="bold")
        result.row(tmp,right,align="center")

        return result

    def raw_render(self,data='',ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % config.VERSION):
        return data

    def naked_render(self,data='',ui=None,title=None):
        """ Render the ui with minimal interventions.

        We put a toolbar here only if we need it. We will only need it
        if some of our UIs need to draw a toolbar icon - otherwise it
        would be lost.
        """
        if ui.toolbar_ui:
            toolbar_str = ui.toolbar_ui.__str__ ()
        else:
            toolbar_str = ''

        result = '''<html>
        <head>
        <link rel="stylesheet" type="text/css" href="images/pyflag.css" />
        </head>
        <body style="overflow: auto;">
        <!--[if lt IE 7.]>
        <script defer src="javascript/pngfix.js" type="text/javascript" language="javascript"></script>
        <![endif]-->
        <script src="javascript/functions.js" type="text/javascript" language="javascript"></script>'''
        if toolbar_str:
            result += '''<div class=PyFlagHeader>
            <div class=Toolbar> %s </div>
            </div>
            <div class="PyFlagPage" id="PyFlagPage" onmouseover="hideSubMenus()">
            ''' % (toolbar_str)
            
        result += data
        
##        result +="</div><script>AdjustHeightToPageSize('PyFlagPage'); bug_check();</script></body>"
        result +="</div><script>AdjustHeightToPageSize('PyFlagPage');</script></body>"

        return result
    
    def render(self, ui=None, data='', title="FLAG - Forensic Log Analysis GUI. %s" % config.VERSION):
        self.menu_javascript = self.make_menu_javascript(ui.defaults)

        if not ui.toolbar_ui:
            toolbar_str='&nbsp;&nbsp;'
        else:
            toolbar_str=ui.toolbar_ui.__str__()

        case_selector = ui.__class__(ui)
        try:
            case_selector.case_selector()
        except:pass

        result = '''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
        <html>
          <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            <title>%s</title>
            <link rel="stylesheet" type="text/css" href="images/pyflag.css" />
            <script src="javascript/functions.js" type="text/javascript" language="javascript"></script>
            <!--[if lt IE 7.]>
            <script defer type="text/javascript" src="javascript/pngfix.js"></script>
            <![endif]-->
            <script> window.__pyflag_parent = "main"; window.__pyflag_name = "main"; </script>
          </head>
        <body>\n''' % title

        result += self.menu_javascript

        result += '''<div class=PyFlagHeader>
        <div class=Toolbar> %s </div><div class="CaseSelector"><form class=CaseSelector id=CaseSelector>%s</form></div>
        </div>
        <div class="PyFlagPage" id="PyFlagPage" onmouseover="hideSubMenus()">
        ''' % (toolbar_str,case_selector)

        result += data
        result += "</div><script>AdjustHeightToPageSize('PyFlagPage'); </script>" + self.footer

#        print result
        return result
