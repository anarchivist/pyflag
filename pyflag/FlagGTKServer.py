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
#  Version: FLAG ($Version: $)
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
        

class GTKServer(gtk.Window):
    """ A class which represents the main GTK server window """

    class FlagNotebook(gtk.Notebook):
        """ A Flag notebook class
        This is used because we store a bunch of toolbar related stuff with the notebook"""
        
        def __init__(self, uimanager):
            gtk.Notebook.__init__(self)
            self.uimanager = uimanager
            self.cur_merge_id = None
            self.cur_page = None
            self.cur_action_grp = None
            self.toolbar_uis = {}
            self.toolbar_actions = {}
            self.connect("switch-page", self.switch)

        def rem_toolbar(self, page):
            if self.cur_merge_id:
                self.uimanager.remove_ui(self.cur_merge_id)
            if self.toolbar_actions.has_key(page):
                self.uimanager.remove_action_group(self.toolbar_actions[page])

        def add_toolbar(self, page):
            if self.toolbar_actions.has_key(page):
                self.uimanager.insert_action_group(self.toolbar_actions[page], -1)
                self.cur_action_grp = self.toolbar_actions[page]
            if self.toolbar_uis.has_key(page):
                self.cur_merge_id = self.uimanager.add_ui_from_string(self.toolbar_uis[page])
            
        def switch(self, notebook, page, pagenum):
            """ tab switch callback, update toobar """
            print "SWITCH TABS"
            self.rem_toolbar(pagenum)    
            self.add_toolbar(pagenum)
            self.cur_page = pagenum

        def close_tab(self, action=None, page=None):
            """ close current tab """
            if not page:
                page = self.get_current_page()
            self.remove_page(page)
            try:
                self.rem_toolbar(page)
                del self.toolbar_uis[page]
                del self.toolbar_actions[page]
            except KeyError:
                pass

        def add_page(self, result, label):
            """ add result (a GTKUI object) as a new tab with given label """
            # each new page goes in a scrolled window
            scroll = gtk.ScrolledWindow()
            scroll.add_with_viewport(result.display())
            scroll.set_policy(gtk.POLICY_AUTOMATIC,gtk.POLICY_AUTOMATIC)
            
            idx = self.get_current_page()
            if idx != -1:
                oldscroll = self.get_nth_page(idx)
                cur_report = self.get_tab_label_text(oldscroll)
            else:
                cur_report = ''
        
            if (cur_report == label):
                # reuse existing page if report is unchanged
                self.close_tab(page=idx)
                self.insert_page(scroll, gtk.Label(label), idx)
            else:
                # add a new page
                idx = self.append_page(scroll, gtk.Label(label))

            # set toolbar vars
            try:
                self.rem_toolbar(idx)
                del self.toolbar_uis[idx]
                del self.toolbar_actions[idx]
            except KeyError:
                pass

            if result.toolbar_items:
                self.toolbar_actions[idx] = gtk.ActionGroup('ReportActions')
                self.toolbar_uis[idx] = '<toolbar name="Toolbar"><placeholder name="ReportTools">'
                for t in result.toolbar_items:
                    self.toolbar_uis[idx] += '<toolitem action="%s"/>' % t.name
                    self.toolbar_actions[idx].add_actions([(t.name, None, t.name, None, t.name, t.callback)])
                self.toolbar_uis[idx] += '</placeholder></toolbar>'

                # FIXME: have to put icons on toolbuttons but cant retrieve widget until added to ui in switch
                # this is going to have to be jumbled around...
            
            # show results, should fire the switch cb which will actually populate the uimanager
            self.show_all()
            self.set_current_page(idx)            

    def __init__(self):
        """ GTKServer Main Function
        Initialise framework and draw main window """
        gtk.Window.__init__(self)
        
        # initialize flag
        self.flag = FlagFramework.Flag()
        FlagFramework.GLOBAL_FLAG_OBJ = self.flag
        self.flag.ui = UI.GTKUI

        # set some window properties
        self.set_title('PyFLAG')
        self.set_icon_from_file('%s/pyflag_logo.png' % config.IMAGEDIR)
        self.set_default_size(500, 500)
        self.connect('destroy', lambda x: gtk.main_quit())

        # these are the MAIN ELEMENTS of the GTKServer
        self.vbox = gtk.VBox()
        self.uimanager = gtk.UIManager()
        self.notebook = GTKServer.FlagNotebook(self.uimanager)
        ## have to build the ui at this point...
        self.build_flag_menu()        
        self.menubar = self.uimanager.get_widget('/Menubar')
        self.toolbar = self.uimanager.get_widget('/Toolbar')
        self.statusbar = gtk.Statusbar()

        # pack these to arrange the UI
        self.add_accel_group(self.uimanager.get_accel_group())
        self.add(self.vbox)
        self.vbox.pack_start(self.menubar, False)
        
        # but the toolbar in a HBox with a case selector
        hbox = gtk.HBox()
        combobox = self.case_selector()
        self.toolbar = self.uimanager.get_widget('/Toolbar')
        hbox.pack_start(combobox, False)
        hbox.pack_start(self.toolbar)

        self.vbox.pack_start(hbox, False)
        self.vbox.pack_start(self.notebook)
        self.vbox.pack_end(self.statusbar, False)
                
        # install the main UI callback
        self.flag.ui.link_callback = self.add_page

        # show it
        self.show_all()

    def order_families(self, families):
        """ orders the list of the provided families based of the dynasty.

        If a family is not in the dynasty it gets a score of 100. Note, list is ordered in place.
        """
        dynasty = {
            "Case Management": 10,
            "Load Data":20,
            }

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

    def case_selector(self):
        """ helper function to draw a case selector """
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

    def error_popup(self, text,error_msg="Error Occured"):
        """ Draw the text in an error message box """
        dialog=gtk.Window()
        frame=gtk.Frame(error_msg)
        box=gtk.VBox()
        textview=gtk.TextView()
        b=textview.get_buffer()
        iter=b.get_iter_at_offset(0)
        b.insert(iter,text)
        box.add(textview)
        frame.add(box)
        dialog.add(frame)
        dialog.show_all()

    def add_page(self, query):
        """ Add a new notebook page, or redraw existing page """
        try:
            result = self.flag.process_request(query)
        except Exception,e:
            import traceback,sys
            import cStringIO

            a = cStringIO.StringIO()
            traceback.print_tb(sys.exc_info()[2], file=a)
            a.seek(0)
            error_msg="%s: %s\n%s" % (sys.exc_info()[0],sys.exc_info()[1],a.read())
            a.close()
            self.error_popup(error_msg)
            return

        self.notebook.add_page(result, query['report'])

    def execute_report_cb(self, action, family, report):
        """ Execute a report based on the clicked action item """
        query = FlagFramework.query_type((),family=family,report=report,case='pyflag')
        self.add_page(query)
        
    def build_flag_menu(self):
        # Create an actiongroup
        actions = gtk.ActionGroup('menu_actions')

        # Build the basic Menu UI
        # make a special case for a case mgmt reports by
        # hard coding them into the Flag menu for usability
        ui = """<menubar name="Menubar">
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
        actions.add_actions([('Create new case', None, 'Create new case', None, 'Create new case', self.execute_report_cb)], ('Case Management','Create new case'))
        actions.add_actions([('Open Existing Case', None, 'Open Existing Case', None, 'Open Existing Case', self.execute_report_cb)], ('Case Management','Open Existing Case'))
        actions.add_actions([('Reset Case', None, 'Reset Case', None, 'Reset Case', self.execute_report_cb)], ('Case Management', 'Reset Case'))
        actions.add_actions([('Remove case', None, 'Remove case', None, 'Remove case', self.execute_report_cb)], ('Case Management','Remove case'))
        actions.add_actions([('Close', gtk.STOCK_CLOSE, '_Close', 
                                None, 'Close Current Tab', self.execute_report_cb),
                             ('Quit', gtk.STOCK_QUIT, '_Quit', 
                                None, 'Quit pyFLAG', self.execute_report_cb),
                             ('Edit', None, '_Edit'),
                             ('Preferences', gtk.STOCK_PREFERENCES, '_Preferences'),
                             ('View', None, 'View')])

        # Add the Reports
        ui += '<menu action="Reports">\n'
        actions.add_actions([('Reports', None, '_Reports')])
        family_list = Registry.REPORTS.get_families()
        self.order_families(family_list)
        for family in family_list:
            ui += '\t<menu action="%s">\n' % family
            actions.add_actions([(family, None, family)])
            report_list = Registry.REPORTS.family[family]
            for r in report_list:
                if r.hidden: continue
                ui += '\t\t<menuitem action="%s"/>\n' % r.name
                actions.add_actions([(r.name, None, r.name, None, r.name, self.execute_report_cb)], (family,r.name))
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
        ui += """<toolbar name="Toolbar">
                   <toolitem action="Prev Page"/>
                   <toolitem action="Next Page"/>
                   <separator/>
                   <placeholder name="ReportTools">
                   </placeholder>
                   <separator/>
                   <toolitem action="Close Tab"/>
                   <separator/>
                 </toolbar>"""
        actions.add_actions([('Prev Page', gtk.STOCK_GO_BACK, '_Prev Page', 
                                None, 'Navigate to Previous Page', self.execute_report_cb),
                             ('Next Page', gtk.STOCK_GO_FORWARD, '_Next Page', 
                                None, 'Navigate to Next Page', self.execute_report_cb),
                             ('Close Tab', gtk.STOCK_CLOSE, '_Close Tab', 
                                None, 'Close current Tab', self.notebook.close_tab)])

        # Add the actions to the uimanager
        self.uimanager.insert_action_group(actions, 0)

        # Add a UI description
        #print ui
        self.uimanager.add_ui_from_string(ui)

        # gray out the nav buttons for now
        button = self.uimanager.get_widget('/Toolbar/Next Page')
        button.set_sensitive(gtk.FALSE)
        button = self.uimanager.get_widget('/Toolbar/Prev Page')
        button.set_sensitive(gtk.FALSE)

### BEGIN MAIN ####

main = GTKServer()
gtk.main()
