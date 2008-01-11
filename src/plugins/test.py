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
#  Version: FLAG $Version: 0.85 Date: Fri Dec 28 16:12:30 EST 2007$
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
active = False

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
        
        return dirs + files
    except OSError: return [(None,None,None)]

def pane_cb(branch,result):
    """ A callback for rendering the right pane.

    @arg branch: A list indicating the currently selected item in the tree
    @arg result: A UI object to draw on
    """
    result.text("You clicked on %s" % str(branch))
    result.link("Return to parent", result.defaults, pane='parent');
#    result.result += "<script> alert(window.opener)</script>"

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

        def pane1(query,result):
            def popup_cb1(query,result):
                result.heading("I am a popup")
                result.text("This floating pane will be closed in 5 seconds!!!")
                result.refresh(5, query, pane='parent')

            result.popup(popup_cb1, "Click Me", tooltip="This will pop a new window up")

        def pane2(query,result):
            def popup_form_cb(query, result):
                result.heading("A form popup test")
                result.start_form(query, pane="parent")
                result.textfield("Type something here","something")

                def second_level_cb(query,result):
                    result.para("Will set something to foo");
                    del query['something']
                    query['something'] = 'foo'
                    result.link("Return to parent", query, pane='parent');

                result.popup(second_level_cb, "Second popup")
                
                result.end_form()

            try:
                result.para("Something is %s" % query['something'])
            except:
                pass

            result.popup(popup_form_cb, "Form popup Test", tooltip="Tryout the form in the popup")

        def pane3(query,result):
            def popup_link_cb(query,result):
                result.heading("Tests links within popups")
                try:
                    result.text("link is %s" % query['link'])
                except KeyError:
                    pass

                del query['link']
                new_query = query.clone()

                query['link'] = "Internal link"
                result.link("Internal popup link", target=query, pane='self')

                del new_query['something']
                new_query['something'] = "Data from popup"
                result.link("back to parent link", target=new_query, pane='parent')

            try:
                print query
                result.para("Something is %s" % query['something'])
            except:
                pass

            result.popup(popup_link_cb, "Popup Links test", tooltip="Try links in the popup")

        result.notebook(
            names=['Pane 1','Pane 2','Pane 3'],
            callbacks = [ pane1, pane2, pane3]
            )
        
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

        try:
            result.para("opened from %s"% query['from'])
        except:
            pass

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

        target = query.clone()
        del target['from']
        target['from'] = "main page"
        result.link("Open main page in a popup", target=target, pane='popup')

        del target['from']
        target['from'] = "Popup"
        result.link("Open my parent", target=target, pane='parent')
        result.popup(popup_cb, "Open a popup")

        try:
            result.para(query['value'])
        except:
            pass

class DateSelectorTest(PopUpTest):
    """ Test the Date Selector widget """
    name = "DateSelectorTest"
    parameters = {'start_date': 'any', 'end_date': 'any', 'foo':'any'}
    
    def form(self,query,result):
        result.date_selector("Start Date", 'start_date')
        result.date_selector("End Date", 'end_date')
        result.textfield("Some field","foo")

    def display(self,query,result):
        result.heading("Date Selector test")
        result.para("will show data between %s and %s" % (query['start_date'],query['end_date']))

class FormTest(PopUpTest):
    """ Test the various form widgets """
    name = "FormTest"
    parameters = { "var1": "any", "var2":"any", "__submit__":"any"}

    def form(self,query,result):
        result.textarea("Enter value 1","var1")
        result.textarea("Enter value 2","var2")

    def display(self,query,result):
        result.heading("Form test")
        result.text("I have some with html data %s" % result.sanitise_data(query['var1']))
        result.para("And sanitised data %s" % query['var2'])
        result.link("Try this again",target=query)

class WizardTest(PopUpTest):
    """ Tests the Wizard """
    name ="Wizard Test"
    parameters = {"var1":"any", "var2":"any", "var3":"any", "finished":"any"}

    def form(self,query,result):
        def page1_cb(query,result):
            result.heading("Please enter your name")
            result.textfield("Name","var1")

        def page2_cb(query,result):
            result.date_selector("Birthday",'var2')

        def page3_cb(query,result):
            result.textfield("Age",'var3')
            result.checkbox("Finished?",'finished','yes')

        result.wizard(
            names = ["Enter Your Name", "Birthday", "Your Age"],
            callbacks = [page1_cb, page2_cb, page3_cb]
            )

from pyflag.ColumnTypes import StringType,IPType, TimestampType

class TableTest(PopUpTest):
    """ Tests the Table widget """
    name = "Table Test"

    def display(self, query,result):
        result.heading("Table Tests")
        
        ## Tables need to act on the DB so we create a temporary table
        ## just for this test:
        dbh=DB.DBO()
        dbh.cursor.warnings=False
        dbh.execute("drop table if exists TestTable")
        dbh.execute("""create TABLE `TestTable` (
        `id` int(11) NOT NULL auto_increment,
        `time` TIMESTAMP,
        `data` tinyblob NOT NULL,
        `foobar` varchar(10),
        `ip_addr` int(11) unsigned default 0,
        PRIMARY KEY  (`id`)
        )""")
        
        dbh.mass_insert_start("TestTable")
        dbh.insert("TestTable", _time="from_unixtime(1147329821)", data="Some Data",
                        foobar="X", _ip_addr="inet_aton('192.168.1.1')")
        dbh.insert("TestTable", _time="from_unixtime(1147329831)", data="More Data",
                        foobar="Y", _ip_addr="inet_aton('192.168.1.22')")
        dbh.insert("TestTable", _time="from_unixtime(1147329841)", data="Some More Data",
                        foobar="Z", _ip_addr="inet_aton('192.168.1.23')")
        dbh.insert("TestTable", _time="from_unixtime(1147329851)", data="Another Lot of Data",
                        foobar="Q",  _ip_addr="inet_aton('192.168.1.55')")

        for i in range(0,100):
            dbh.mass_insert(_time="from_unixtime(%s)" % (1147329851+i), data="Data %s" % i, foobar=i)

        dbh.mass_insert_commit()

        def foobar_cb(value):
            return "foo %s" % value
        
        result.table(
                         ## Can use keyword args
            elements = [ TimestampType(name = 'Timestamp',
                                       sql = 'time',
                                       ),
                         
                         ## Or positional args
                         StringType('Data', 'data',
                                    link = query_type(
            family=query['family'], report='FormTest',__target__='var1')),
                         
                         StringType('Foobar', 'foobar', callback=foobar_cb),

                         ## Note that here we just need to specify the
                         ## field name in the table, the IPType will
                         ## automatically create the translated SQL.
                         IPType('IP Address', 'ip_addr'),
                         ],
            table = "TestTable",
            )

class FileSelectorTest(PopUpTest):
    """ Test the file selector widget """
    name = "File Selector"
    parameters = {'file':'filename', 'text':'any', '__submit__':'any' }

    def form(self, query, result):
        result.fileselector("Select file:",'file')
        result.textfield("Enter text",'text')

    def display(self,query,result):
        result.heading("You have selected the following files:")
        for f in query.getarray('file'):
            result.row(f)

from pyflag.FlagFramework import HexDump

class HexDumpTest(Refresher):
    """ Test the hexdumper widget """
    name = "HexDump Test"
    def display(self,query,result):
        data = "this is a long test string. the quick brown fox jumped over the lazy cat. " * 3
        h = HexDump(data, result)
        result.heading("HexDump test")
        ## highlight and match are styles defined in the css file.
        h.dump(highlight=[[30,80,'highlight'], [40,50,'match']])

class AudioTest(Refresher):
    """ Test the Audio control """
    name = "Audio Test"
    def display(self, query, result):
        fd = open("/var/www/music.mp3")

        def audio_cb():
            while 1:
                data = fd.read(64*1024)
                if len(data)==0: break
                
                yield data
                
        result.sound_control("Play music sequence", audio_cb())
