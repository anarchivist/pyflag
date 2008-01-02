# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.85 Date: Fri Dec 28 16:12:30 EST 2007$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************

""" This module provides the necessary HTML to impose a theme on the UI. Note that all themes must be derived from BasicTheme. """

import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FlagFramework as FlagFramework
import pyflag.Registry as Registry

def propegate(query,new_query):
    """ This copies certain parameters from query into new_query if they exist in query """
    propegated = ['case','fsimage','iosubsys']
    for i in propegated:
        try:
            del new_query[i]
            new_query[i]=query[i]
        except KeyError:
            pass

    return new_query


## This places approximate order on families
dynasty = {
    "Case Management": 10,
    "Load Data":20,
    }

def order_families(families):
    """ orders the list of the provided families based of the dynasty.

    If a family is not in the dynasty it gets a score of 100. Note, list is ordered in place.
    """
    def sort_function(x,y):
        try:
            xscore=dynasty[x]
        except KeyError:
            xscore=ord(x[0])

        try:
            yscore=dynasty[y]
        except KeyError:
            yscore=ord(y[0])
            
        if xscore<yscore:
            return -1
        elif xscore==yscore: return 0
        return 1

    families.sort(sort_function)
    
class BasicTheme:
    """ Basic default theme """
    footer = "</body></html>"
    header='''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
        <html>
        <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>%s</title>
        </head>
        <body link=blue vlink=blue bgcolor="#FFFFFF"><script src="images/functions.js" type="text/javascript" language="javascript"></script>'''
    banner = '''<table width="100%%">
        <tbody> 
        <tr>
        <td align=left width=10><img src="images/pyflag.png" alt="flag_heading" border="0"></td><td align=center> ''' 

    def naked_render(self,data='',ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % config.VERSION):
        """ Render the ui with minimal interventions """
        return " ".join((self.header % title,data,self.footer))
    
    def menu(self,flag,query, result):
        """ Draws the menu for the current family.

        @arg flag: A Flag object containing the appropriate dispatcher
        @arg query: The user query
        """
        family = query['family']
        family_block = flag.ui()
        family_block.start_table()

        module_list = Registry.REPORTS.get_families()
        order_families(module_list)
        
        for m in module_list:
            link = flag.ui()
            link.link(m,family=m)
            family_block.row(link)
            
        report_block = flag.ui()
        if family and family != 'None':
            report_block.start_table()
            report_list = Registry.REPORTS.family[family]
            for r in report_list:
                if r.hidden: continue
                link = flag.ui()
                link.link(r.name,target=propegate(query,FlagFramework.query_type()),report=r.name,tooltip=r.__doc__)

                report_block.row(link,colspan=2)
                report_block.row(" ",r.description)

        result = flag.ui()
        result.heading("Flag Main Menu")
        result.start_table()
        result.row(family_block,report_block,valign="top")
        return result

    def navbar(self,query=FlagFramework.query_type(()),next=None,previous=None,pageno=None):
        """ Returns the HTML for the navigation bar. """
        if not query.has_key('family'):
            query['family']=''
            
        if next:
            #Make a link
            q=query.clone()
            q.FillQueryTarget(next)
            next = '<a href="f?%s"><img src="images/forward.png" border="0"></a>' % (str(q))
        else:
            next = '<img src="images/g_forward.png" border="0">'

        if previous<0:
            previous =  '<img src="images/g_back.png" border="0">'
        else:
            q=query.clone()
            q.FillQueryTarget(previous)
            previous = '<a href="f?%s"><img src="images/back.png"  border="0"></a>' %  (str(q))

        bar = {'family': propegate(query,FlagFramework.query_type()),'back': previous,'case': query.get('case',''),'pageno':  pageno,'next': next,'reset': str(query)+'&reset=1','stop': str(query)+'&stop=1'}

        toolbar = '''<table><tr>
        <td valign="bottom"><a href="f?family=%(family)s"><img src="images/home.png" border="0"></a></td><td valign="bottom">%(back)s</td>%(case)s - page %(pageno)s<td valign="bottom">%(next)s</td> <td valign="bottom">
        <td valign="bottom"><a href="flag?%(reset)s"><img src="images/reset.png" border="0"></a></td>	  
        <td valign="bottom"><a href=flag?%(stop)s><img src="images/stop.png" border="0"></a></td></tr></table>''' % bar

        return toolbar

    def render(self, query=FlagFramework.query_type(()), meta='',data='',next=None,previous=None,pageno=None,ui=None):
        toolbar=self.navbar(query=query , next=next , previous=previous , pageno=pageno)
        try:
            toolbar_str=ui.toolbar_ui.__str__()
        except:
            toolbar_str=''

        return " ".join((self.header,self.banner,meta,"<td align=left>%s</td><td align=center>"%toolbar_str,toolbar,'''</td><td width=10><center><img src="images/logo.png"><br><font size="+1"><a href="http://www.gnu.org/copyleft/gpl.html"> &copy;GPL</a></font></center></td></tr></tbody></table> </tr></table>\n''', data ,"<table width=100%%><tr><td></td></tr><tr><td align=center>%s</td></tr></table>"%(toolbar),self.footer))


def get_theme(query):
    try:
        return Registry.THEMES.themes[query['theme']]()
    except KeyError:
        try:
            return Registry.THEMES.themes[config.THEME]()
        except KeyError:
            return BasicTheme()

