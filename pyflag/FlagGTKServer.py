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
import pyflag.DB as DB

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

def case_selector():
    combobox = gtk.combo_box_new_text()
    combobox.append_text('Select Case')
    dbh = DB.DBO(config.FLAGDB)
    dbh.execute('select value from meta where property=\'flag_db\'',())
    while 1:
        row = dbh.cursor.fetchone()
        if not row: break
        combobox.append_text(row[0])
    combobox.set_active(0)
    return combobox

def navigate_cb(action):
    pass

def close_tab_cb(action):
    global notebook
    notebook.remove_page(notebook.get_current_page())

def execute_report_cb(action, family, report):
    """ Execute a report based on the clicked action item """
    print 'executing report %s' % report
    global notebook,flag
    query = FlagFramework.query_type((),family=family,report=report,case='pyflag')
    result = flag.process_request(query)
    scroll = gtk.ScrolledWindow()
    scroll.set_policy(gtk.POLICY_AUTOMATIC,gtk.POLICY_AUTOMATIC)
    scroll.add_with_viewport(result.display())
    idx = notebook.append_page(scroll, gtk.Label(report))
    notebook.show_all()
    notebook.set_current_page(idx)

def change(self,query_str):
    """ Callback function used to redraw the results of the processing on the main window """
    print "change called"
    global notepad,flag
    result =  flag.process_request(query_str)
    
    # use a scrolled window to hold the results
    scroll = gtk.ScrolledWindow()
    scroll.add_with_viewport(result.display())
    scroll.set_policy(gtk.POLICY_AUTOMATIC,gtk.POLICY_AUTOMATIC)

    idx = notebook.get_current_page()
    oldscroll = notebook.get_nth_page(idx)
    cur_report = notebook.get_tab_label_text(oldscroll)

    if (cur_report == query_str['report']):
        # reuse existing page if report is unchanged    
        notebook.remove_page(idx)
        notebook.insert_page(scroll, gtk.Label(query_str['report']), idx)
    else:
        # add a new page
        idx = notebook.append_page(scroll, gtk.Label(query_str['report']))
    
    # show results
    notebook.show_all()
    notebook.set_current_page(idx)

def build_flag_menu(window, uimanager):
    # Create an actiongroup
    actions = gtk.ActionGroup('menu_actions')

    # Build the basic Menu UI
    ui = """<menubar name="MenuBar">
                <menu action="Flag">
                    <menuitem action="Create new case"/>
                    <menuitem action="Open Existing Case"/>
                    <menuitem action="Reset Case"/>
                    <menuitem action="Remove case"/>
                    <menuitem action="Close"/>
                    <menuitem action="Quit"/>
                </menu>
                <menu action="Edit">
                    <menuitem action="Preferences"/>
                </menu>
                <menu action="View">
                </menu>
         """
    actions.add_actions([('Flag', None, '_Flag'),])
    actions.add_actions([('Create new case', None, 'Create new case', None, 'Create new case', execute_report_cb)], ('Case Management','Create new case'))
    actions.add_actions([('Open Existing Case', None, 'Open Existing Case', None, 'Open Existing Case', execute_report_cb)], ('Case Management','Open Existing Case'))
    actions.add_actions([('Reset Case', None, 'Reset Case', None, 'Reset Case', execute_report_cb)], ('Case Management', 'Reset Case'))
    actions.add_actions([('Remove case', None, 'Remove case', None, 'Remove case', execute_report_cb)], ('Case Management','Remove case'))
    actions.add_actions([('Close', gtk.STOCK_CLOSE, '_Close', 
                            None, 'Close Current Tab', execute_report_cb),
                         ('Quit', gtk.STOCK_QUIT, '_Quit', 
                            None, 'Quit pyFLAG', execute_report_cb),
                         ('Edit', None, '_Edit'),
                         ('Preferences', gtk.STOCK_PREFERENCES, '_Preferences'),
                         ('View', None, 'View')])
    
    # Add the Reports
    ui += '<menu action="Reports">\n'
    actions.add_actions([('Reports', None, '_Reports')])
    family_list = Registry.REPORTS.get_families()
    order_families(family_list)
    for family in family_list:
        ui += '\t<menu action="%s">\n' % family
        actions.add_actions([(family, None, family)])
        report_list = Registry.REPORTS.family[family]
        for r in report_list:
            if r.hidden: continue
            ui += '\t\t<menuitem action="%s"/>\n' % r.name
            actions.add_actions([(r.name, None, r.name, None, r.name, execute_report_cb)], (family,r.name))
        ui += '\t</menu>\n'
    ui += '</menu>'
    ui += """<menu action="Help">
                <menuitem action="Contents"/>
                <menuitem action="About"/>
             </menu>"""
    actions.add_actions([('Help', None, '_Help'),
                         ('Contents', gtk.STOCK_HELP, '_Contents'),
                         ('About', gtk.STOCK_DIALOG_INFO, '_About')])
    ui += '</menubar>\n'
    # Add the Navigation Toolbar
    ui += """<toolbar name="NaviBar">
               <toolitem action="Prev Page"/>
               <separator/>
               <toolitem action="Next Page"/>
               <separator/>
               <toolitem action="Close Tab"/>
               <separator/>
             </toolbar>"""
    actions.add_actions([('Prev Page', gtk.STOCK_GO_BACK, '_Prev Page', 
                            None, 'Navigate to Previous Page', execute_report_cb),
                         ('Next Page', gtk.STOCK_GO_FORWARD, '_Next Page', 
                            None, 'Navigate to Next Page', execute_report_cb),
                         ('Close Tab', gtk.STOCK_CLOSE, '_Close Tab', 
                            None, 'Close current Tab', close_tab_cb)])
    
    # Add the actions to the uimanager
    uimanager.insert_action_group(actions, 0)
    
    # Add a UI description
    #print ui
    uimanager.add_ui_from_string(ui)

#### BEGIN MAIN ####

# initialize flag
flag = FlagFramework.Flag()
FlagFramework.GLOBAL_FLAG_OBJ =flag
flag.ui = UI.GTKUI

# create main window
window = gtk.Window()
window.set_title('PyFLAG')
window.set_icon_from_file('%s/pyflag_logo.png' % config.IMAGEDIR)
window.set_default_size(500,500)
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
hbox = gtk.HBox()
combobox = case_selector()

toolbar = uimanager.get_widget('/NaviBar')
hbox.pack_start(combobox, False)
hbox.pack_start(toolbar)
vbox.pack_start(hbox, False)

# use a notebook for multiple reports
notebook = gtk.Notebook()
vbox.pack_start(notebook)

# add a status bar
statusbar = gtk.Statusbar()
vbox.pack_end(statusbar, False)

#Install the GTK callback
flag.ui.link_callback = change

# do it!
window.show_all()
gtk.main()
