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
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 11:21:40 EST 2005$
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
    propegated = ['family','case','fsimage','iosubsys']
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
        <title>FLAG - Forensic Log Analysis GUI - Version %s</title>
        </head>
        <body link=blue vlink=blue bgcolor="#FFFFFF"><table width="100%%">
        <tbody> <script src="images/functions.js" type="text/javascript" language="javascript"></script>
        <tr>
        <td align=left width=10><img src="/flag/images/flag.png" alt="flag_heading" border="0"></td><td align=center> ''' % FlagFramework.flag_version

    def menu(self,flag,query):
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
                link.link(r.name,propegate(query,FlagFramework.query_type()),report=r.name)

                #Add the module doc as a tooltip
                link.tooltip(r.__doc__)

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
            next = '<a href="f?%s"><img src="/flag/images/forward.png" border="0"></a>' % (str(q))
        else:
            next = '<img src="/flag/images/g_forward.png" border="0">'

        if previous<0:
            previous =  '<img src="/flag/images/g_back.png" border="0">'
        else:
            q=query.clone()
            q.FillQueryTarget(previous)
            previous = '<a href="f?%s"><img src="/flag/images/back.png"  border="0"></a>' %  (str(q))

        bar = {'family': propegate(query,FlagFramework.query_type()),'back': previous,'case': query['case'],'pageno':  pageno,'next': next,'reset': str(query)+'&reset=1','stop': str(query)+'&stop=1'}

        toolbar = '''<table><tr>
        <td valign="bottom"><a href="f?family=%(family)s"><img src="/flag/images/home.png" border="0"></a></td><td valign="bottom">%(back)s</td>%(case)s - page %(pageno)s<td valign="bottom">%(next)s</td> <td valign="bottom">
        <td valign="bottom"><a href="flag?%(reset)s"><img src="/flag/images/reset.png" border="0"></a></td>	  
        <td valign="bottom"><a href=flag?%(stop)s><img src="/flag/images/stop.png" border="0"></a></td></tr></table>''' % bar

        return toolbar

    def render(self, query=FlagFramework.query_type(()), meta='',data='',next=None,previous=None,pageno=None):
        toolbar=self.navbar(query=query , next=next , previous=previous , pageno=pageno)
        return " ".join((self.header,meta,toolbar,'''</td><td width=10><center><img src="/flag/images/logo.png"><br><font size="+1"><a href="http://www.gnu.org/copyleft/gpl.html"> &copy;GPL</a></font></center></td></tr></tbody></table> </tr></table>\n''', data ,"<table width=100%%><tr><td></td></tr><tr><td align=center>%s</td></tr></table>"%toolbar,self.footer))

class BlueTheme(BasicTheme):
    """ This class encapsulates the theme elements. The results from this class really depend on the UI used - for example the HTMLUI will expect HTML to come back from here. """

    header='''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
        <html>
        <head>
        <title>FLAG - Forensic Log Analysis GUI - Version %s</title>
        </head>
        <body link=blue vlink=blue bgcolor="#FFFFFF"><table width="100%%">
        <tbody> <script src="images/functions.js" type="text/javascript" language="javascript"></script>
        <tr>
        <td align=left width=10><img src="/flag/images/pyflag.png" alt="flag_heading" border="0"></td><td align=center> ''' % FlagFramework.flag_version

    hilight_bar = '''<table cellspacing=0 cellpadding=0 width="100%%" background="flag/images/topfill.jpg" border=0> <tbody>
    <tr><td height=25 width=30%%>&nbsp;</td>
    <td height=25>%s</td>
    <td height=25>
    <div align="right"><font face="Arial, Helvetica, sans-serif" size="2"><font face="Geneva, Arial, Helvetica, san-serif"><b><font face="Georgia, Times New Roman, Times, serif"><i><font face="Verdana, Arial, Helvetica, sans-serif">F</font></i></font></b><font face="Verdana, Arial, Helvetica, sans-serif"><i>orensics 
    and <b>L</b>og <b>A</b>nalysis <b>G</b>UI</i></font></font></font></div>
    </td>
    
    </tr>
    </tbody>
    </table>'''

    def navbar(self,query=None,next=None,previous=None,pageno=None):
        """ Returns the HTML for the navigation bar. """
        if query==None: query=FlagFramework.query_type(())
        
        if not query.has_key('family'):
            query['family']=''
            
        if next:
            #Make a link
            q=query.clone()
            q.FillQueryTarget(next)
            next = '<a href="f?%s"><img height=25 src="/flag/images/forward.png" border="0"></a>' % (str(q))
        else:
            next = '<img src="/flag/images/arrow_right_grey.gif" height=25 border="0">'

        if previous<0:
            previous =  '<img src="/flag/images/arrow_left_grey.gif" height=25 border="0">'
        else:
            q=query.clone()
            q.FillQueryTarget(previous)
            previous = '<a href="f?%s"><img height=25 src="/flag/images/back.png"  border="0"></a>' %  (str(q))

        bar = {'family':propegate(query,FlagFramework.query_type()),'back': previous,'case': query['case'],'pageno':  pageno,'next': next,'reset': str(query)+'&reset=1','stop': str(query)+'&stop=1'}

        toolbar = '''<table><tr>
        <td valign="bottom"><a href="%(family)s"><img height=25 src="/flag/images/home_grey.png" border="0"></a></td><td valign="bottom">%(back)s</td><td>%(case)s - page %(pageno)s</td><td valign="bottom">%(next)s</td> <td valign="bottom">
        <td valign="bottom"><a href="flag?%(reset)s"><img height=25 src="/flag/images/reset_grey.png" border="0"></a></td></tr></table>''' % bar

        return toolbar

    def render(self, query=FlagFramework.query_type(()), meta='',data='',next=None,previous=None,pageno=None):
        toolbar=self.navbar(query=query , next=next , previous=previous , pageno=pageno)
        return " ".join((self.header,meta,'''</td><td width=10><img src="/flag/images/logo.png"></td></tr></tbody></table> </tr></table>\n''',self.hilight_bar % (toolbar), data ,self.hilight_bar % (toolbar),self.footer))

    def menu(self,flag,query):
        """ Draws the menu for the current family.

        @arg flag: A Flag object containing the appropriate dispatcher
        @arg query: The user query
        """
        family = query['family']
        module_list = Registry.REPORTS.get_families()
        order_families(module_list)
        
        result=flag.ui()

        result.result='''<table cellspacing=0 cellpadding=0 width="100%" border=0 
                  hspace="0" vspace="0" height="300">
              <tbody> 
              <tr> 
                <td width=5><img height=22 alt="table corner" 
                        src="flag/images/metbarleft.gif" 
                        width=5></td>
                <td width="918"> 
                  <table cellspacing=0 cellpadding=0 width="100%" 
                        background="flag/images/metbarfill.gif" 
                        border=0 hspace="0" vspace="0">

                    <tbody>                    <tr> 
                      <td height=22> 
                        <div align="left"><font 
                              face="Verdana, Arial, Helvetica, sans-serif" 
                              size=2></font><font 
                              face="Verdana, Arial, Helvetica, sans-serif"><b><font size="2">Main 
                          Menu</font></b></font></div>
                      </td>
                    </tr>                    </tbody> 
                  </table>
                </td>
                <td width=10><img height=22 alt="table corner" 
                        src="flag/images/metbarend.gif" 
                        width=8></td>

              </tr>              <tr> 
                <td width=5 
                      background="flag/images/sidebarleft.gif">&nbsp;</td>
                <td valign=top width="918"> 
                  <p><font size="+1" face="Arial, Helvetica, sans-serif">'''
        
        for k in module_list:
            link = flag.ui()
            link.link(k,family=k)
            result.result+='''&nbsp;&nbsp;%s<br />\n''' % link

            if family==k:
                report_list = Registry.REPORTS.family[family]
                for r in report_list:
                    if r.hidden: continue
                    link = flag.ui()
                    link.link(r.name,propegate(query,FlagFramework.query_type()),report=r.name)
                    
                    ## Add the module doc as a tooltip
                    link.tooltip(r.__doc__)
                    
                    result.result+="&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong><big>&middot;</big></strong>&nbsp;%s <br />\n" % link
                result.result+="<br/>"

        result.result+='''                    </font></p>
                </td>
                <td width=10 
                      background="flag/images/sidebarrgt.gif">&nbsp;</td>

              </tr>
              <tr> 
                <td width=5><img height=22 alt="table corner" 
                        src="flag/images/greenbarleft.gif" 
                        width=5></td>
                <td width="918"> 
                  <table cellspacing=0 cellpadding=0 width="100%" 
                        background="flag/images/greenbarfill.gif" 
                        border=0>
                    <tbody> 
                    <tr> 
                      <td height=22>&nbsp;</td>
                    </tr>
                    </tbody> 
                  </table>

                </td>
                <td width=10><img height=22 alt="table corner" src="flag/images/greenbarrgt.gif" width=8></td>
              </tr>
              </tbody> 
            </table>
            '''

        return result

default=None
    
def factory(theme=None):
    """ Produce an object of the requested theme. 

    @arg theme: name of theme to produce. If theme=None we return the default theme. This is decided in the following way:
           - If a theme was previously chosen, we return that
           - Consult the config file for the default theme.
    @return: A theme object """
    try:
        try:
            if theme:
                pyflag.Theme.default=theme
                return pyflag.Theme.__dict__[theme]()
            elif pyflag.Theme.default:
                return pyflag.Theme.__dict__[pyflag.Theme.default]()
        except KeyError:
            pass

        for i in dir(pyflag.Theme):
            try:
                if issubclass(pyflag.Theme.__dict__[i],BasicTheme):
                    if i==config.THEME:
                        return pyflag.Theme.__dict__[i]()
            except TypeError:
                pass
        return BasicTheme()
    except AttributeError:
        return BasicTheme()
