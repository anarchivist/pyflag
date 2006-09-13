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

""" This is a test plugin for the GUI.

It is designed to push the GUI to its limits, but can also be used to demonstrate how to use the abstracted UI to write reports.
"""
import pyflag.Reports as Reports
from pyflag.FlagFramework import query_type
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.DB as DB

import os,os.path,sys

description = "Test Class"
#Remove this line to ensure this appears in the menu
#active = False

#We are testing the tree widget. Note this could have been
#written as a generator for faster performance...
def tree_cb(path):
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
        
        ## Just for testing we limit the number of nodes
        return dirs[:10] + files[:10]
    except OSError: return [(None,None,None)]

def pane_cb(branch,result):
    """ A callback for rendering the right pane.

    @arg branch: A list indicating the currently selected item in the tree
    @arg result: A UI object to draw on
    """
    result.text("You clicked on %s" % str(branch))
    print "Called back for %s" % (branch,)



class TreeTest(Reports.report):
    """ A sample report.

    Note that all reports must inherit from Reports.report and should override the methods and attributes listed below.
    """
    parameters = {}
    hidden = False
    name = "Tree Test"
    family = "Test"
    
    def display(self,query,result):
        result.heading("I am calling the display method")
        branch = ['/']

        result.tree(tree_cb = tree_cb,pane_cb = pane_cb ,branch = branch )

class InputTest(Reports.report):
    """ Tests the type checking on input parameters """
    parameters = {'a':'numeric','b':'alphanum'}
    name = "Input Test"
    family = "Test"

    def form(self,query,result):
        result.const_selector("This is a selector","select",('1st','2nd','3rd'),('1st','2nd','3rd'))
        result.textfield('numeric parameter','a',size='5')
        result.textfield('alphanumeric parameter','b',size='10')

class LayOutTest(Reports.report):
    """ A sample report.
    
    Note that all reports must inherit from Reports.report and should override the methods and attributes listed below.
    """
    hidden = False
    name = "LayOut Test"
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

class PopUpTest(Refresher):
    """ Tests the ability to use popups in the UI """
    name = "PopUpTest"
    def display(self, query,result):
        result.heading("Popup Test")
        
        def popup_cb1(query,result):
            result.heading("I am a popup")
            result.text("This floating pane will be closed in 5 seconds!!!")
            result.refresh(5, query, parent=True)

        result.popup(popup_cb1, "Click Me", tooltip="This will pop a new window up")

        def popup_form_cb(query, result):
            result.heading("A form popup test")
            result.start_form(query, refresh="parent")
            result.textfield("Type something here","something")
            result.end_form()

        result.popup(popup_form_cb, "Form popup Test", tooltip="Tryout the form in the popup")

        def popup_link_cb(query,result):
            result.heading("Tests links within popups")
            try:
                result.text("link is %s" % query['link'])
            except KeyError:
                pass

            del query['link']
            query['link'] = "Internal link"
            result.link("Internal popup link", target=query, pane='self')

            new_query = query.clone()
            del new_query['something']
            new_query['something'] = "Data from popup"
            result.link("back to parent link", target=new_query, pane='parent')

        result.popup(popup_link_cb, "Popup Links test", tooltip="Try links in the popup")
        try:
            result.para("Something is %s" % query['something'])
        except:
            pass

class ToolTipTest(PopUpTest):
    """ Demonstrates some of the tooltip capabilities """
    name = "ToolTipTest"
    def display(self, query, result):
        result.heading("Tooltip Test")

        def popup_cb(query,result):
            result.heading("I am a popup")

        result.popup(popup_cb, "Launch popup", tooltip="I am a tooltip on a popup launcher")

        tmp = result.__class__(result)
        tmp.heading("A heavy tooltip")
        tmp.para("This tooltip is a fully blown UI object")

        result.link("Go to self",target=query, tooltip=tmp)

class LinkTest(PopUpTest):
    """ Tests linking """
    name = "LinkTest"

    def display(self, query, result):
        result.heading("Link tests")

        result.link("Simple link to this page!", target=query, icon="floppy.png")
        
        def popup_cb(query,result):
            result.heading("This is a popup")

            try:
                i=int(query['internal'])
                result.para("Following %s internal links" % i)
            except:
                i=0

            target =query.clone()
            target['value'] = "Value from popup"
            result.link("Will open in our parent", target=target, pane='parent')

            target = query.clone()
            del target['internal']
            target['internal']=i+1
            result.link("This is an internal link", target=target, pane='self')

            result.link("Open to main", target=query, pane='main')

        result.popup(popup_cb, "Open a popup")

        try:
            result.para(query['value'])
        except:
            pass
