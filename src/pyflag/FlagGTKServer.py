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
#  Version: FLAG ($Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$)
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
import pyflag.GTKUI as GTKUI
from GTKUI import FlagNotebook,FlagToolbar
import pyflag.TypeCheck as TypeCheck
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry
import pyflag.DB as DB
import threading

class FlagServerToolbar(FlagToolbar):
    def __init__(self,canvas):
        self.tchildren=[]
        self.canvas = canvas
        gtk.HBox.__init__(self)
        self.tchildren = []

    def destroy_toolbar(self):
        pass

    def redraw(self):
        ## We need to initiate a redraw of our children now:
        self.canvas.foreach(self.canvas.remove)
        self.install(self.canvas)
        self.canvas.show_all()
        self.show_all()

class FlagServerNotebook(FlagNotebook):
    """ Essentially the same as GTKUI FlagNotebook, but with a tab delete button """

    def close_tab(self, action=None, page_id=None):
        """ close current tab """
        ## We need to find out which page was clicked on, we do this
        ## by searching the pages for their page_ids:
        page=self.get_page_with_id(page_id)  
        self.remove_page(page)
        # cleanup
        del self.queries[page_id]
        del self.toolbars[page_id]
        del self.views[page_id]
        del self.callbacks[page_id]
    
    def add_page(self, name, callback, query):
        page=FlagNotebook.add_page(self, name, callback, query)
        
        delete_image = gtk.Image()
        delete_image.set_from_file( "%s/button_delete.xpm" % config.IMAGEDIR )
        delete_image.set_from_pixbuf( delete_image.get_pixbuf().scale_simple(9, 9, 2) )

        delete_button = gtk.Button()
        delete_button.add(delete_image)
        delete_button.connect('clicked', self.close_tab, page)
        print "adding page %s" % (page)
        
        hbox = gtk.HBox()
        hbox.pack_start(gtk.Label(name))
        hbox.pack_start(delete_button, False, False)
        hbox.show_all()
        child = self.get_nth_page(self.get_page_with_id(page))
        self.set_tab_label(child, hbox)
        self.set_current_page(self.get_n_pages()-1)
        return page
            
class GTKServer(gtk.Window):
    """ A class which represents the main GTK server window """

    def __init__(self):
        """ GTKServer Main Function
        Initialise framework and draw main window """

        self.form_dialog=None
        gtk.Window.__init__(self)
        
        # initialize flag
        self.flag = FlagFramework.Flag()
        FlagFramework.GLOBAL_FLAG_OBJ = self.flag
        
        self.flag.ui = GTKUI.GTKUI

        # set some window properties
        self.set_title('PyFLAG')
        self.set_icon_from_file('%s/pyflag_logo.png' % config.IMAGEDIR)
        self.set_default_size(800,600)
        self.connect('destroy', lambda x: gtk.main_quit())

        # these are the MAIN ELEMENTS of the GTKServer
        self.vbox = gtk.VBox()
        self.uimanager = gtk.UIManager()
        self.toolhandlebox = gtk.HandleBox()
        self.toolhbox = gtk.HBox()
        self.toolhandlebox.add(self.toolhbox)
        self.ftoolbar = FlagServerToolbar(self.toolhbox)
        self.notebook = FlagServerNotebook(self.flag.ui(server=self,ftoolbar=self.ftoolbar))
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
        self.case_selector_combo = self.case_selector()
        hbox.pack_start(self.case_selector_combo, False)
        hbox.pack_start(self.toolhandlebox)
        self.toolhbox.show_all()

        self.vbox.pack_start(hbox, False)
        self.vbox.pack_start(self.notebook, True, True)
        self.vbox.pack_end(self.statusbar, False)
                
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
        print query
        if self.form_dialog:
            child=self.form_dialog.get_child()
            if child:
                self.form_dialog.remove(child)
        else:
            self.form_dialog=gtk.ScrolledWindow()
            self.form_dialog.set_transient_for(self)
            self.form_dialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
            #self.form_dialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)
            #self.form_dialog.set_default_size(500,500)
            self.form_dialog.connect('destroy',self.delete_form)

        box=gtk.VBox()
        self.form_dialog.add(box)
        toolbar=FlagServerToolbar(box)
        result = self.flag.ui(server=self,ftoolbar=toolbar)
        try:
            report.progress(query,result)
        except Exception,e:
            self.error_popup(e)
            raise
        
        box.add(result.display())
        self.form_dialog.show_all()
        
    def run_analysis(self,report,query):
        """ Run the analysis """
        print query

        try:
            canonical_query = self.flag.canonicalise(query)
            thread_name = threading.currentThread().getName()
            print "Current thread is %s" % thread_name
            try:
                report.analyse(query)
                print "analysed report"
            except Exception,e:
                gtk.gdk.threads_enter()
                self.error_popup(e)
                gtk.gdk.threads_leave()
                return
            
            dbh = DB.DBO(query['case'])
            dbh.execute("insert into meta set property=%r,value=%r",('report_executed',canonical_query))
            ## This thread must never touch GTK stuff or dead lock
            ## will occur. We must signal the other threads that we
            ## have finished analysis.
            del self.running_threads[query.__str__()]
            return
        except Exception:
            pass

    ## A class variable to record currently running threads
    running_threads ={}
    
    def draw_form(self,query,report):
        print "Drawing form for %s %s" % (query,self.form_dialog)
        if self.form_dialog:
            child=self.form_dialog.get_child()
            if child:
                self.form_dialog.remove(child)
        else:
            self.form_dialog=gtk.Window()
            self.form_dialog.set_transient_for(self)
            self.form_frame=gtk.Frame("%s" % report.name) 
            self.form_dialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
            #self.form_dialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)
            #self.form_dialog.set_default_size(500,500)
            self.form_dialog.connect('destroy',self.delete_form)

        box=gtk.VBox()
        toolbar=FlagServerToolbar(box)
        result = self.flag.ui(server=self,query=query,ftoolbar=toolbar)
        result.start_form(query)
        try:
            report.form(query,result)
        except FlagFramework.DontDraw,e:
            return
        except Exception,e:
            self.error_popup(e)
            raise

        result.end_form(toplevel_window=self.form_dialog)

        if self.form_frame.get_child():
            self.form_frame.remove(self.form_frame.get_child())

        self.form_frame.add(result.display())
        self.form_dialog.add(self.form_frame)
        self.form_dialog.show_all()
        print "shown form_dialog"

    def draw_about_help(self,action):
        """ Draws an about page """
        result=GTKUI.GTKUI(server=main,ftoolbar=main.ftoolbar)
        result.heading("PyFlag - Forensic and Log Analysis GUI")
        result.text("""
        Version: $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
        Copyright 2004-2005:
           David Collett <daveco@users.sourceforge.net>
           Michael Cohen <scudette@users.sourceforge.net>
           """,font='bold',wrap='none')
        self.create_window(result.display(),'logo.png')

    def draw_report_help(self,action):
        current_page = self.notebook.get_current_page()
        result=GTKUI.GTKUI(server=main,ftoolbar=main.ftoolbar)
        if current_page<0:
            result.text("Error:\n",color='red',font='heading')
            result.text("No report is currently displayed. Select a report first from the main menu",color='black')
            self.create_window(result.display(),gtk.STOCK_DIALOG_WARNING)
        else:
            ## Find the report drawn on the current page:
            p = self.notebook.get_nth_page(current_page)
            query=self.notebook.queries[p.get_data('page_id')]
            report_name=query['report']
            family=query['family']
            report = Registry.REPORTS.dispatch(family,report_name)(self.flag,ui=self.flag.ui)
            result.heading("Help on %s" % report.name)
            result.text(report.description)
            self.create_window(result.display(),gtk.STOCK_DIALOG_INFO)

    def process_query(self,query):
        """ This is the main entry point for processing queries.

        If the query is incomplete, we draw a form, if its complete, we check that the report has not been run before. If its cached, we open a new page for it. Else we manage the progress/analyse threads.
        """
        try:
            family=query['family']
            report=query['report']
            report = Registry.REPORTS.dispatch(family,report)(self.flag,ui=self.flag.ui)
            print "processing query %s" % query
            ## Check to see if we have all the parameters we need:
            if report.check_parameters(query):
                print "Parameters ok - we can go ahead %s" % query
                ##Check to see if the report is cached in the database:
                if self.flag.is_cached(query):
                    if self.form_dialog:
                        self.form_dialog.destroy()
                        self.form_dialog=None

                    ## Add this page to our main notebook
                    self.add_page(query,report)
                    return
                else:
                    self.running_threads[query.__str__()] = "ready"
                    ## Report is not cached - we shall analyse it in a seperate thread:
                    t = threading.Thread(target=self.run_analysis,args=(report,query))
                    t.start()
                    print "Analysing report"
                    import time

                    def progress_thread(t,query):
                        """ This function is called to refresh the progress window

                        This callback is invoked every few seconds in the same thread as the display. It is up to this function to detect when the analysis method finished.
                        """
                        ## Ensure to tear down the progress window if the
                        ## analysis thread is no longer running. This has
                        ## to be done here because it seems very dangerous
                        ## to do gtk stuff in another thread - it seems
                        ## that gtk is at present single threaded or we
                        ## get a nasty lockup. Hence its important to
                        ## ensure that the analysis thread makes _no_ gtk
                        ## calls at all!!!
                        if not self.running_threads.has_key(query.__str__()):
                            if self.form_dialog:
                                self.form_dialog.destroy()
                                self.form_dialog=None
                            self.add_page(query,report)
                            return

                        if self.form_dialog:
                            print "drawing progress"
                            self.run_progress(query)
                            ## Ensure we get invoked again to monitor the progress
                            gtk.timeout_add(1000*config.REFRESH,progress_thread,t,query)
                        else:
                            print "finished progressing"
                            self.process_query(query)

                    ## The first check the progress of the analysis is
                    ## only quite short- this allows trivial analyses
                    ## methods to complete quickly
                    gtk.timeout_add(100,progress_thread,t,query)
                    return

            ## We do not have all the parameters we need:
            else:
                ## Draw the form
                self.draw_form(query,report)
        except Exception,e:
            self.error_popup(e)
            raise

    def add_page(self, query,report):
        """ Add a new notebook page, or redraw existing page """
        page=self.notebook.add_page(query['report'], report.display, query)

    def get_current_case(self):
        """ Gets the current case and returns it.

        @return: current case as selected in the toolbar selector or FLAGDB if none selected
        """
        model = self.case_selector_combo.get_model()
        active = self.case_selector_combo.get_active()
        if active==0:
            return config.FLAGDB
        else: return model[active][0]
        
    def execute_report_cb(self, action, family, report):
        """ Execute a report based on the clicked action item """
        ## Get the case from the case_selector_combo:
        print self.get_current_case()
        query = FlagFramework.query_type((),family=family,report=report,case=self.get_current_case())
        self.process_query(query)
        
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
                    <menuitem action="Current Report"/>
                    <menuitem action="About"/>
                 </menu>"""
        actions.add_actions([('Help', None, '_Help'),
                             ('Contents', gtk.STOCK_HELP, '_Contents'),
                             ('Current Report', gtk.STOCK_HELP, '_Report',None,'Current Report',self.draw_report_help),
                             ('About', gtk.STOCK_DIALOG_INFO, '_About',None,'About',self.draw_about_help)])
        ui += '</menubar>\n'

        # Add the actions to the uimanager
        self.uimanager.insert_action_group(actions, 0)

        # Add a UI description
        self.uimanager.add_ui_from_string(ui)

    def create_window(self,widget,icon=None):
        """ Creates a new window and puts widget in it """
        vbox=gtk.VBox(False,8)
        button=gtk.Button("Dismiss")
        dialog=gtk.Window()
#        dialog.modify_bg(gtk.STATE_NORMAL,'white')
        dialog.add(vbox)
        if icon:
            hbox=gtk.HBox(False,8)

            ## Is it an image we specified?
            if icon.endswith(".png"):
                stock=gtk.Image()
                stock.set_from_file( "%s/%s" % (config.IMAGEDIR,icon ))
            else:
                stock = gtk.image_new_from_stock(
                    icon,
                    gtk.ICON_SIZE_DIALOG)
                
            hbox.pack_start(stock, False, False, 0)
            hbox.pack_start(widget,True,True, 0)
            vbox.pack_start(hbox,True,True, 0)
        else:
            vbox.pack_start(widget,True,True,0)
        vbox.pack_end(button,False,False,0)
        button.connect("clicked",lambda x: dialog.destroy())
        dialog.set_default_size(400,300)
        dialog.show_all()
        return dialog

    def error_popup(self,e):
        """ Draw the text in an error message box

        @arg e: The exception object to print
        """
        result=GTKUI.GTKUI(server=main,ftoolbar=main.ftoolbar)
        FlagFramework.get_traceback(e,result)    
        self.create_window(result.display(),gtk.STOCK_DIALOG_ERROR)


### BEGIN MAIN ####
if __name__ == "__main__":
    main=GTKServer()

    import gtk.gdk
    gtk.gdk.threads_init()
    gtk.main()
