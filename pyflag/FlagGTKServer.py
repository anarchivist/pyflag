#!/usr/bin/python2.3
# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG 0.4 (12-02-2004)
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

""" This is the GTK Server. Runs the flag framework together with the GTK UI. """
import gtk
import sys
import cgi

import pyflag.GTKUI as UI
import pyflag.Theme

window=None
subwindow=None


def list_modules(flag):
    """ Lists the modules taking their order into account """
    def module_cmp(a,b):
        """ Sort function for modules """
        return cmp(a[1],b[1])

    #Produce the module list
    module_list = flag.dispatch.modules.items()
    module_list.sort(module_cmp)
    return [ k for k,v in module_list ]

def list_reports(flag,family):
    """ Lists all reports in a given module with regard to the order of the reports """
    def report_cmp(a,b):
        """ Sort comparator. a,b are reports """
        return cmp(a[1].order,b[1].order)

    report_list = flag.dispatch.family[family].items()
    report_list.sort(report_cmp)
    report_list = [ (k,v) for k,v in report_list if not v.hidden ]
    return report_list

def draw_menu(flag,query):
    query['family'] = None
    family=query['family']
    ## Build the menu - FIXME - put into application menus
    result=flag.ui()
    family_block = flag.ui()
    family_block.start_table()

    module_list = list_modules(flag)

    for k in module_list:
        link = flag.ui()
        link.link(k,family=k)
        family_block.row(link)

    report_block = flag.ui()

    if family:
        report_block.start_table()
        report_list = list_reports(flag,family)
        for k,v in report_list:
            link = flag.ui()
            link.link(v.name,case=query['case'],family=family,report=k)

            #Add the module doc as a tooltip
            link.tooltip(v.__doc__)

            report_block.row(link,colspan=2)
            report_block.row(" ",v.description)

    result = flag.ui()
    result.heading("Flag Main Menu")
    result.start_table()
    result.row(family_block,report_block,valign="top")
    return result

def change(self,query_str):
    """ Callback function used to redraw the results of the processing on the main window """
    global subwindow,scrolled_window,flag
    if not scrolled_window: return
    print query_str
    import cgi
    import FlagFramework

    query = query_str
    scrolled_window.remove(subwindow)
    if not query.has_key('family') or not query.has_key('report'):
        c=draw_menu(flag,query)
    else:
        c =  flag.process_request(query)
    subwindow = c.display()
    scrolled_window.add(subwindow)
    scrolled_window.show_all()
    
if __name__ == "__main__":
    import FlagFramework

    #Create the main GTK window
    window = gtk.Window(gtk.WINDOW_TOPLEVEL)
    window.connect('destroy', lambda w: gtk.main_quit())
    window.set_default_size(600, 400)
    scrolled_window = gtk.ScrolledWindow()
    scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
    scrolled_window.set_shadow_type(gtk.SHADOW_IN)
    window.add(scrolled_window)
    
    #Initialise the flag framework
    flag = FlagFramework.Flag(ui=UI.GTKUI)
    flag.ui = UI.GTKUI
   
    #Install the GTK callback
    flag.ui.link_callback = change
    
    #Start off with an empty query string
    query = FlagFramework.query_type(())
    try:
        if not query.has_key('family') or not query.has_key('report'):
            result=draw_menu(flag,query)
        else:
            result = flag.process_request(query)              
    except Exception,e:
        result = flag.ui()
        result.defaults = query
        result.heading("Error")
        import traceback,sys
        import cStringIO
        
        a = cStringIO.StringIO()
        traceback.print_tb(sys.exc_info()[2], file=a)
        a.seek(0)
        result.para("%s: %s" % (sys.exc_info()[0],sys.exc_info()[1]))
        result.text(a.read())
        a.close()

    subwindow=result.display()
    scrolled_window.add(subwindow)

    window.show_all()
    gtk.main()
