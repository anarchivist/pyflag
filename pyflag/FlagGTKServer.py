#!/usr/bin/env python
# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# David Collett <daveco@users.sourceforge.net>
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG xxx (xx-xx-xxxx)
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

import pygtk
pygtk.require('2.0')
import gtk

import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.GTKUI as UI
import pyflag.TypeCheck as TypeCheck
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry

# global windows where UI renders stuff
subwindow=None

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

def navigate_cb(action):
    pass

def execute_report_cb(action):
    """ Execute a report based on the clicked action item """
    print 'executing report %s' % action.get_name()
    global subwindow,scrolled_window,flag
    if subwindow:
        scrolled_window.remove(subwindow)
    family, report = action.get_property('tooltip').split('|')
    query = FlagFramework.query_type((),family=family,report=report,case='pyflag')
    result = flag.process_request(query)
    subwindow=result.display()
    scrolled_window.add(subwindow)
    scrolled_window.show_all()

def change(self,query_str):
    """ Callback function used to redraw the results of the processing on the main window """
    global subwindow,scrolled_window,flag
    if not scrolled_window: return
    print query_str

    query = query_str
    scrolled_window.remove(subwindow)
    if not query.has_key('family') or not query.has_key('report'):
        c=draw_menu(flag,query)
    else:
        c =  flag.process_request(query)
    subwindow = c.display()
    scrolled_window.add(subwindow)
    scrolled_window.show_all()

def build_flag_menu(window, uimanager):
    # Create an actiongroup
    actions = gtk.ActionGroup('menu_actions')

    # Build the UI XML    
    ui = '<menubar name="MenuBar">\n'
    family_list = Registry.REPORTS.get_families()
    order_families(family_list)
    for family in family_list:
        ui += '\t<menu action="%s">\n' % family
        actions.add_actions([(family, None, family)])
        report_list = Registry.REPORTS.family[family]
        for r in report_list:
            if r.hidden: continue
            ui += '\t\t<menuitem action="%s"/>\n' % r.name
            actions.add_actions([(r.name, None, r.name, None, "%s|%s" % (family,r.name), execute_report_cb)])
        ui += '\t</menu>\n'

    # Add the Navigation Toolbar
    ui += '</menubar>\n'
    ui += """<toolbar name="NaviBar">
               <toolitem action="Prev Page"/>
               <separator/>
               <toolitem action="Next Page"/>
               <separator/>
             </toolbar>"""
    actions.add_actions([('Prev Page', gtk.STOCK_GO_BACK, '_Prev Page', 
                            None, 'Navigate to Previous Page', execute_report_cb),
                         ('Next Page', gtk.STOCK_GO_FORWARD, '_Next Page', 
                            None, 'Navigate to Next Page', execute_report_cb)])
    
    # Add the actions to the uimanager
    uimanager.insert_action_group(actions, 0)
    
    # Add a UI description
    uimanager.add_ui_from_string(ui)

#### BEGIN MAIN ####

# initialize flag
flag = FlagFramework.Flag()
FlagFramework.GLOBAL_FLAG_OBJ =flag
flag.ui = UI.GTKUI

# create main window
window = gtk.Window()
window.connect('destroy', lambda x: gtk.main_quit())
vbox = gtk.VBox()
window.add(vbox)

# Create a UI Manager
uimanager = gtk.UIManager()

# Add the accelerator group to the toplevel window
window.add_accel_group(uimanager.get_accel_group())

# build the report menu and navigation bar
build_flag_menu(window, uimanager)

# Create a MenuBar for the reports menu
menubar = uimanager.get_widget('/MenuBar')
vbox.pack_start(menubar, False)

# Create a toolbar for navigation
toolbar = uimanager.get_widget('/NaviBar')
vbox.pack_start(toolbar, False)

# Render reports in a scrolled window
scrolled_window = gtk.ScrolledWindow()
scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
scrolled_window.set_shadow_type(gtk.SHADOW_IN)
vbox.pack_start(scrolled_window)

#Install the GTK callback
flag.ui.link_callback = change

# do it!
window.show_all()
gtk.main()
