""" These are the standard themes that come with Pyflag. """
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FlagFramework as FlagFramework
import pyflag.Registry as Registry
import pyflag.Theme as Theme

class BlueTheme(Theme.BasicTheme):
    """ This class encapsulates the theme elements. The results from this class really depend on the UI used - for example the HTMLUI will expect HTML to come back from here. """

    hilight_bar = '''<table cellspacing=0 cellpadding=0 width="100%%" background="/images/topfill.jpg" border=0> <tbody>
    <tr><td align=left>%s</td>
    <td height=25 align=center>%s</td>
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
            next = '<a href="f?%s"><img height=25 src="/images/forward.png" border="0"></a>' % (str(q))
        else:
            next = '<img src="/images/arrow_right_grey.gif" height=25 border="0">'

        if previous<0:
            previous =  '<img src="/images/arrow_left_grey.gif" height=25 border="0">'
        else:
            q=query.clone()
            q.FillQueryTarget(previous)
            previous = '<a href="f?%s"><img height=25 src="/images/back.png"  border="0"></a>' %  (str(q))

        bar = {'family': Theme.propegate(query,FlagFramework.query_type()),'back': previous,'case': query['case'],'pageno':  pageno,'next': next,'reset': str(query)+'&reset=1','stop': str(query)+'&stop=1'}

        toolbar = '''<table><tr>
        <td valign="bottom"><a href="%(family)s"><img height=25 src="/images/home_grey.png" border="0"></a></td><td valign="bottom">%(back)s</td><td>%(case)s - page %(pageno)s</td><td valign="bottom">%(next)s</td> <td valign="bottom">
        <td valign="bottom"><a href="flag?%(reset)s"><img height=25 src="/images/reset_grey.png" border="0"></a></td></tr></table>''' % bar

        return toolbar

    def render(self, query=FlagFramework.query_type(()), meta='',data='',next=None,previous=None,pageno=None,ui=None,title="FLAG - Forensic Log Analysis GUI. %s" % config.VERSION):

        if not ui.toolbar_ui:
            toolbar_str='&nbsp;&nbsp;'
        else:
            toolbar_str=ui.toolbar_ui.__str__()

        toolbar=self.navbar(query=query , next=next , previous=previous , pageno=pageno)
        return " ".join((self.header % title,self.banner,meta,'''</td><td width=10><img src="/images/logo.png"></td></tr></tbody></table> </tr></table>\n''',self.hilight_bar % (toolbar_str,toolbar), data ,self.hilight_bar % (toolbar_str,toolbar),self.footer))

    def menu(self,flag,query, result):
        """ Draws the menu for the current family.

        @arg flag: A Flag object containing the appropriate dispatcher
        @arg query: The user query
        """
        family = query['family']
        module_list = Registry.REPORTS.get_families()
        Theme.order_families(module_list)
        
        result=flag.ui()

        result.result='''<table cellspacing=0 cellpadding=0 width="100%" border=0 
                  hspace="0" vspace="0" height="300">
              <tbody> 
              <tr> 
                <td width=5><img height=22 alt="table corner" 
                        src="images/metbarleft.gif" 
                        width=5></td>
                <td width="918"> 
                  <table cellspacing=0 cellpadding=0 width="100%" 
                        background="images/metbarfill.gif" 
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
                        src="images/metbarend.gif" 
                        width=8></td>

              </tr>              <tr> 
                <td width=5 
                      background="images/sidebarleft.gif">&nbsp;</td>
                <td valign=top width="918"> 
                  <p><font size="+1" face="Arial, Helvetica, sans-serif">'''
        
        for k in module_list:
            link = flag.ui()
            link.link(k,family=k)
            result.result+='''&nbsp;&nbsp;%s<br />\n''' % (link,)

            if family==k:
                report_list = Registry.REPORTS.family[family]
                for r in report_list:
                    if r.hidden: continue
                    link = flag.ui()
                    link.link(r.name,target=Theme.propegate(query,FlagFramework.query_type()),tooltip=r.__doc__,report=r.name)
                    
                    result.result+="&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong><big>&middot;</big></strong>&nbsp;%s <br />\n" % link
                result.result+="<br/>"

        result.result+='''                    </font></p>
                </td>
                <td width=10 
                      background="images/sidebarrgt.gif">&nbsp;</td>

              </tr>
              <tr> 
                <td width=5><img height=22 alt="table corner" 
                        src="images/greenbarleft.gif" 
                        width=5></td>
                <td width="918"> 
                  <table cellspacing=0 cellpadding=0 width="100%" 
                        background="images/greenbarfill.gif" 
                        border=0>
                    <tbody> 
                    <tr> 
                      <td height=22>&nbsp;</td>
                    </tr>
                    </tbody> 
                  </table>

                </td>
                <td width=10><img height=22 alt="table corner" src="images/greenbarrgt.gif" width=8></td>
              </tr>
              </tbody> 
            </table>
            '''

        return result

default=None
