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
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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

""" An example of a test plugin """

import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.DB as DB

import os,os.path,sys

description = "Test Class"
#Remove this line to ensure this appears in the menu
active = False

class TemplateReport(Reports.report):
    """ A sample report.

    Note that all reports must inherit from Reports.report and should override the methods and attributes listed below.
    """
    parameters = {'a':'numeric','b':'alphanum'}
    hidden = False
    name = "Test report"
    family = "Test"
    
    def display(self,query,result):
        result.heading("I am calling the display method")
        branch = ['/']

        #We are testing the tree widget. Note this could have been
        #written as a generator for faster performance...
        def tree_cb(branch):
            path ='/'+'/'.join(branch)  + '/'
            print path,branch
            
            try:
                files = []
                dirs = []
                for d in os.listdir(path):
                    if os.path.isdir(os.path.join(path,d)):
                        dirs.append((d,d,'branch'))
                    else:
                        files.append((d,d,'leaf'))

                files.sort()
                dirs.sort()
                return dirs + files 
            except OSError: return [(None,None,None)]

        def pane_cb(branch,result):
            """ A callback for rendering the right pane.

            @arg branch: A list indicating the currently selected item in the tree
            @arg result: A UI object to draw on
            """
            result.text("You clicked on %s" % str(branch))
            print "Called back for %s" % (branch,)

        result.xtree(tree_cb = tree_cb,pane_cb = pane_cb ,branch = branch )
    
    def form(self,query,result):
        result.defaults = query
        result.case_selector()
        result.heading("I am calling the form method")
        result.const_selector("This is a selector","select",('1st','2nd','3rd'),('1st','2nd','3rd'))
        result.textfield('a parameter','a',size='5')
        result.textfield('b parameter','b',size='10')

    def progress(self,query,result):
        result.heading("Im progressing along nicely")

class SomeClass:
    """ A private class that lives within the plugin.

    This class will not be added as a report because it does not inherit from the Reports.report class """
    pass
    
def mod_fun(a,b):
    """ A module private function. """
    return b

class test2(Reports.report):
    """ A sample report.
    
    Note that all reports must inherit from Reports.report and should override the methods and attributes listed below.
    """
    hidden = False
    name = "Test report2"
    family = "Test"
    def display(self,query,result):
        result.start_table()
        result.row("e","f")
        result.row("a","b","c","d")
        result.end_table()
        result.start_table()
        result.row("absabsdajhdfsfds skjsdfkljdfs fdsalkj fdsalkjsfd lkjfdsa lfskdj sfdalkj fdsalkj fdsalkjsfd lksfdj sfdalkj sfdlkjfsda lkfsdaj lksfdaj dfsalkj fdsalk jsfdalkj sdaflkj fsdalk jsfdalk jdsfalk jdfsalk jsfdalkjsfdalk jdfsalk jfdsalkj fdsalk jfsda")
        result.end_table()

import time

class Refresher(Reports.report):
    """ What is the time? """
    parameters = {}
    family = "Test"
    name = "Refresher"
    def display(self,query,result):
        result.heading("At the sound of the tone the time will be:")
        result.text(time.ctime())
        result.refresh(2,query)
