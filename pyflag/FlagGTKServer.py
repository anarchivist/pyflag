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
import gtk,gtk.gdk

import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.GTKUI
import pyflag.TypeCheck as TypeCheck
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry
import pyflag.DB as DB
import threading

def error_popup(e):
    """ Draw the text in an error message box

    @arg e: The exception object to print
    """
    dialog=gtk.Window()
    result=pyflag.GTKUI.GTKUI()
    FlagFramework.get_traceback(e,result)
    frame=gtk.Frame(result.title)
    result.title=None
    box=gtk.VBox()
    box.add(result.display())
    frame.add(box)
    dialog.add(frame)
    dialog.show_all()

class GTKServer(gtk.Window):
    """ A class which represents the main GTK server window """

    class FlagNotebook(gtk.Notebook):
        """ A Flag notebook class
        This is used because we store a bunch of toolbar related stuff with the notebook"""

        def __init__(self, toolhbox):
            gtk.Notebook.__init__(self)
            self.toolhbox = toolhbox
            self.toolbars = {}
            self.connect("switch-page", self.switch)
            
        def switch(self, notebook, page, pagenum):
            """ tab switch callback, update toobar """
            child = self.toolhbox.get_child()
            if child:
                self.toolhbox.remove(child)
            if self.toolbars.has_key(pagenum):
                self.toolhbox.add(self.toolbars[pagenum])
            self.toolhbox.show_all()

        def close_tab(self, action=None, page=None):
            """ close current tab """
            if not page:
                page = self.get_current_page()
            child = self.toolhbox.get_child()
            self.toolhbox.remove(child)
            self.remove_page(page)

        def add_page(self, result, query):
            """ add result (a GTKUI object) as a new tab with given label """
            
            # each new page goes in a scrolled window
            scroll = gtk.ScrolledWindow()
            try:
                scroll.add_with_viewport(result.display())
            except Exception,e:
                error_popup(e)
                raise
            scroll.set_policy(gtk.POLICY_AUTOMATIC,gtk.POLICY_AUTOMATIC)
            
            idx = self.get_current_page()
            if idx != -1:
                oldscroll = self.get_nth_page(idx)
                oldlabelbox = self.get_tab_label(oldscroll)
                oldlabel = oldlabelbox.get_children()[0]
                cur_report = oldlabel.get_text()
            else:
                cur_report = ''
        
            if (cur_report == query['report']):
                # reuse existing page if report is unchanged
                self.close_tab(page=idx)
                self.insert_page(scroll, position=idx)
            else:
                # add a new page
                idx = self.append_page(scroll)
                self.check_resize()

            # build a label for the tab
            button = gtk.Button()
            image = gtk.Image()
            image.set_from_file( "%s/button_delete.xpm" % config.IMAGEDIR )
            image.set_from_pixbuf( image.get_pixbuf().scale_simple(9, 9, 2) )
            button.add( image )
            button.set_relief(gtk.RELIEF_HALF)
            button.set_border_width(0)
            button.connect('clicked', self.close_tab)
            result.tooltips.set_tip(button, 'Close Tab')

            hbox = gtk.HBox()
            hbox.pack_start(gtk.Label(query['report']))
            hbox.pack_start(button, False, False)
            hbox.show_all()
            self.set_tab_label(scroll, hbox)

            
            # add toolbar to UI
            self.toolbars[idx] = result.toolbar_ui

            self.show_all()
            self.set_current_page(idx)            

    def __init__(self):
        """ GTKServer Main Function
        Initialise framework and draw main window """

        self.form_dialog=None
        gtk.Window.__init__(self)
        
        # initialize flag
        self.flag = FlagFramework.Flag()
        FlagFramework.GLOBAL_FLAG_OBJ = self.flag

        import pyflag.GTKUI

        self.flag.ui = pyflag.GTKUI.GTKUI

        # set some window properties
        self.set_title('PyFLAG')
        self.set_icon_from_file('%s/pyflag_logo.png' % config.IMAGEDIR)
        self.set_default_size(800,600)
        self.connect('destroy', lambda x: gtk.main_quit())

        # these are the MAIN ELEMENTS of the GTKServer
        self.vbox = gtk.VBox()
        self.uimanager = gtk.UIManager()
        self.toolhbox = gtk.HandleBox()
        self.notebook = GTKServer.FlagNotebook(self.toolhbox)
        ## have to build the ui at this point...
        self.build_flag_menu()        
        self.menubar = self.uimanager.get_widget('/Menubar')
        self.statusbar = gtk.Statusbar()

        # pack these to arrange the UI
        self.add_accel_group(self.uimanager.get_accel_group())
        self.add(self.vbox)
        self.vbox.pack_start(self.menubar, False)
        
        # put the toolbar in a HBox with a case selector
        hbox = gtk.HBox()
        combobox = self.case_selector()
        hbox.pack_start(combobox, False)
        hbox.pack_start(self.toolhbox)

        self.vbox.pack_start(hbox, False)
        self.vbox.pack_start(self.notebook, True, True)
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

    def delete_form(self,widget):
        self.form_dialog=None

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

    def run_progress(self,query):
        family=query['family']
        report=query['report']
        report = Registry.REPORTS.dispatch(family,report)(self.flag,ui=self.flag.ui)
        if self.form_dialog:
            child=self.form_dialog.get_child()
            self.form_dialog.remove(child)
        else:
            self.form_dialog=gtk.ScrolledWindow()
            self.form_dialog.set_transient_for(self)
            #self.form_dialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
            self.form_dialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)
            #self.form_dialog.set_default_size(500,500)
            self.form_dialog.connect('destroy',self.delete_form)

        box=gtk.VBox()
        self.form_dialog.add_with_viewport(box)
        result = self.flag.ui(server=self)
        try:
            report.progress(query,result)
        except Exception,e:
            error_popup(e)
            raise
        
        box.add(result.display())
        self.form_dialog.show_all()
        
    def run_analysis(self,report,query):
        """ Run the analysis """
        try:
            canonical_query = self.flag.canonicalise(query)
            thread_name = threading.currentThread().getName()
            print "Current thread is %s" % thread_name
            try:
                report.analyse(query)
                print "analysed report"
            except Exception,e:
                gtk.gdk.threads_enter()
                error_popup(e)
                gtk.gdk.threads_leave()
                return
            
            dbh = DB.DBO(query['case'])
            dbh.execute("insert into meta set property=%r,value=%r",('report_executed',canonical_query))
            ## This thread must never touch GTK stuff or dead lock will occur. We must signal the other threads that we have finished analysis.
            del self.running_threads[query.__str__()]
            return
        except Exception:
            pass

    ## A class variable to record currently running threads
    running_threads ={} 
    def draw_form(self,query):
        family=query['family']
        report=query['report']
        report = Registry.REPORTS.dispatch(family,report)(self.flag,ui=self.flag.ui)
        ## Check to see if we have all the parameters we need:
        if report.check_parameters(query):
            print "Parameters ok - we can go ahead"
            ##Check to see if the report is cached in the database:
            if self.flag.is_cached(query):
                self.add_page(query)
                self.form_dialog.destroy()
                self.form_dialog=None
                return
            else:
                self.running_threads[query.__str__()] = "ready"
                ## Report is not cached - we shall analyse it in a seperate thread:
                t = threading.Thread(target=self.run_analysis,args=(report,query))
                t.start()
                print "Analysing report"
                import time

                def progress_thread(t,query):
                    """ This function is called to refresh the progress window """
                    ## Ensure to tear down the progress window if the analysis thread is no longer running
                    if not self.running_threads.has_key(query.__str__()):
                        self.add_page(query)
                        self.form_dialog.destroy()
                        self.form_dialog=None
                        return
                    print "progress thread"
                    if self.form_dialog:
                        print "drawing progress"
                        self.run_progress(query)
                        gtk.timeout_add(1000,progress_thread,t,query)
                    else:
                        print "finished progressing"
                        return

                ## Run the progress cycle in a seperate thread
                print "Calculating progress"
                gtk.timeout_add(1000,progress_thread,t,query)
                return

        else:
            if self.form_dialog:
                child=self.form_dialog.get_child()
                self.form_dialog.remove(child)
            else:
                self.form_dialog=gtk.Window()
                self.form_dialog.set_transient_for(self)
                #self.form_dialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
                self.form_dialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)
                #self.form_dialog.set_default_size(500,500)
                self.form_dialog.connect('destroy',self.delete_form)
            box=gtk.VBox()
            self.form_dialog.add(box)
            result = self.flag.ui(server=self)
            result.start_form(query)
            print report
            try:
                report.form(query,result)
            except Exception,e:
                error_popup(e)
                raise
            
            ## Set the callback to ourselves:
            result.link_callback = self.draw_form
            result.end_form()
            box.add(result.display())
            self.form_dialog.show_all()

    def add_page(self, query):
        """ Add a new notebook page, or redraw existing page """
        family=query['family']
        report=query['report']
        report = Registry.REPORTS.dispatch(family,report)(self.flag,ui=self.flag.ui)
        result=self.flag.ui(query=query,server=self)
        report.display(query,result)
        self.notebook.add_page(result, query)

    def execute_report_cb(self, action, family, report):
        """ Execute a report based on the clicked action item """
        query = FlagFramework.query_type((),family=family,report=report,case='pyflag')
        self.draw_form(query)
#        self.add_page(query)
        
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

        # Add the actions to the uimanager
        self.uimanager.insert_action_group(actions, 0)

        # Add a UI description
        self.uimanager.add_ui_from_string(ui)

### BEGIN MAIN ####
if __name__ == "__main__":
    main=GTKServer()

    import gtk.gdk
    gtk.gdk.threads_init()
    gtk.main()
