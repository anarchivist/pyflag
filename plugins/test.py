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

""" An example of a test plugin """

import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.DB as DB

import os,os.path

description = "Test Class"
#Remove this line to ensure this appears in the menu
hidden = True

class TemplateReport(Reports.report):
    """ A sample report.

    Note that all reports must inherit from Reports.report and should override the methods and attributes listed below.
    """
    parameters = {'a':'numeric','b':'alphanum'}
    hidden = True
    name = "Test report"
    family = "Test"
    
    def display(self,query,result):
        result.heading("I am calling the display method")
        branch = ['/']

        #We are testing the graphing widget:
#        import pyflag.Graph as Graph

        ## First make one graph
#        graph = Graph.Graph()
#        graph.pie((1,2,3,'a','test point','hello'),(2,4,3,6,4,2),explode="0.1", legend='no')

##        ## Testing the image object:
##        fd=open("%s/images/defence.png" % config.FLAG_BIN,'r')
##        image = Graph.Image(fd.read())
##        fd.close()
        
#        tmp = self.ui(result)      
#        tmp.image(graph)
##        tmp.heading("Image test")
##        tmp.image(image)
        
        new_query = query.clone()
        del new_query['lookat']
        del new_query['open_tree']
        target = new_query
        
        #We are testing the tree widget. Note this could have been written as a generator for faster performance...
        def tree_cb(branch):
            path ='/'.join(branch)  + '/'
            print path,branch
            
            try:
                files = []
                dirs = []
                for d in os.listdir(path):
                    link = self.ui(result)
                    link.link(d,target,open_tree="%s%s" %(path,d),__mark__="%s%s" %(path,d))
                    if os.path.isdir(os.path.join(path,d)):
                        dirs.append((d,link,'branch'))
                    else:
                        files.append((d,link,'leaf'))

                files.sort()
                dirs.sort()
                return dirs + files 
            except OSError: return [(None,None,None)]

        tmp2 = self.ui(result)

        def pane_cb(branch,result):
            """ A callback for rendering the right pane.

            @arg branch: A list indicating the currently selected item in the tree
            @arg result: A UI object to draw on
            """
            result.text("You clicked on %s" % str(branch))
            print "Called back for %s" % (branch,)

        tmp2.tree(tree_cb = tree_cb,pane_cb = pane_cb ,branch = branch )
        ## Now place them side by side
        result.row(tmp2,width=500,height=300)
        result.end_table()

        result.para("I have two variables here, a=%s and b=%s" % (query['a'],query['b']))
        return result

    def analyse(self,query):
        #Note that analyse does not need to return anything, if it does it is ignored.
        result =self.ui()
        result.heading("I am calling the analyse method. Analysing:")
        import time
        
        time.sleep(10)
        result.para( "Done")
        return result
    
    def form(self,query,result):
        result.defaults = query
        result.case_selector()
        result.heading("I am calling the form method")
        result.const_selector("This is a selector","select",('1st','2nd','3rd'),('1st','2nd','3rd'))
        result.textfield('a parameter','a',size='5')
        result.textfield('b parameter','b',size='10')
#        tmp=self.ui(result)
#        tmp.table()
#        result.row(tmp)
#        result.table()
        return result

    def progress(self,query,result):
        result.heading("Im progressing along nicely")
        return result

class SomeClass:
    """ A private class that lives within the plugin.

    This class will not be added as a report because it does not inherit from the Reports.report class """
    pass
    
def mod_fun(a,b):
    """ A module private function. """
    return b
