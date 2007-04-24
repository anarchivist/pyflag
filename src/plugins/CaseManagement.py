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
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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

""" Creates a new case database for flag """
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import os
import pyflag.IO as IO
import pyflag.conf
config=pyflag.conf.ConfObject()
from pyflag.TableObj import StringType,TimestampType,EditableStringType,InodeType,FilenameType, TimelineObj, IntegerType
import pyflag.Registry as Registry
import time
import pyflag.pyflagsh as pyflagsh

description = "Case management"
order = 10

class NewCase(Reports.report):
    """ Creates a new flag case database."""
    parameters = {"create_case":"alphanum"}
    name = "Create new case"
    family = "Case Management"
    description = "Create database for new case to load data into"
    order = 10

    def form(self,query,result):
        result.defaults = query
        result.textfield("Please enter a new case name:","create_case")
        return result

    def display(self,query,result):
        ## Use the shell to do the heavy lifting.
        pyflagsh.shell_execv(command='create_case',
                             argv=[ query['create_case'],])

        #Get handle to flag db
        result.heading("Case Created")
        result.para("\n\nThe database for case %s has been created" %query['create_case'])
        result.link("Load a Disk Image", FlagFramework.query_type((), case=query['create_case'], family="Load Data", report="Load IO Data Source"))
	result.para('')
        result.link("Load a preset Log File", FlagFramework.query_type((), case=query['create_case'], family="Load Data", report="Load Preset Log File"))
        return result

class DelCase(Reports.report):
    """ Removes a flag case database """
    parameters = {"remove_case":"flag_db"}
    name = "Remove case"
    family = "Case Management"
    description="Remove database for specified case"
    order = 20

    def do_reset(self,query):
        pass

    def form(self,query,result):
        result.defaults = query
        result.para("Please select the case to delete. Note that all data in this case will be lost.")
        result.case_selector(case="remove_case")
        return result

    def display(self,query,result):
        try:
            FlagFramework.delete_case(query['remove_case'])
        except DB.DBError:
            pass
        result.heading("Deleted case")
        result.para("Case %s has been deleted" % query['remove_case'])
        return result

class ResetCase(Reports.report):
    """ Resets a flag case database """
    parameters = {"reset_case":"flag_db"}
    name = "Reset Case"
    family = "Case Management"
    description = "Reset a case database (delete data)"
    order = 30

    def form(self,query,result):
        result.defaults = query
        result.para("Please select the case to reset. Note that all data in this case will be lost.")
        result.case_selector(case="reset_case")
        return result

    def display(self,query,result):
        result.heading("Reset case")

        query['remove_case'] = query['reset_case']
        query['create_case'] = query['reset_case']
        tmp = result.__class__(result)
        
        report = DelCase(self.flag, self.ui)
        report.display(query,tmp)
        
        report = NewCase(self.flag, self.ui)
        report.display(query,tmp)

        result.para("Case %s has been reset" % query['reset_case'])

class ViewAnnotation(Reports.report):
    """ View the annotated Inodes """
    name = "View Annotations"
    family = "Case Management"
    order = 40

    def display(self, query,result):
        result.heading("Annotated Inodes for case %s" % query['case'])
        result.table(
            elements = [ InodeType('Inode', 'annotate.inode', case=query['case']),
                         FilenameType(case=query['case']),
                         StringType('Category','category'),
                         StringType('Note','note'),
                         ],
            table = 'annotate join file on file.inode=annotate.inode',
            case = query['case'],
            )

class ViewCaseTimeline(Reports.report):
    """ View the case time line """
    name = "View Case Timeline"
    family = "Case Management"
    order = 50

    def display(self, query, result):
        original_query = query
 
        def add_new_event(query, result):
            timeline = TimelineObj(case=query['case'])

            ## We got submitted - actually try to do the deed:
            if 'Add To Timeline' in query.getarray('__submit__'):
                result.start_table()
                newEvent = timeline.add(query, result)
                result.para("The following is the new timeline entry:")
                timeline.show(newEvent,result)
                result.end_table()
                result.link("Close this window", target=original_query, pane='parent')
                return result

            result.start_form(query, pane='self')
            result.heading("Add an arbitrary event")
            timeline.add_form(query,result)
            result.end_form(value="Add To Timeline")
            return result
      
        result.heading("Case Time Line for case %s" % query['case'])
        result.text("Add arbitrary event:")
        result.popup(add_new_event, "Add abritrary event", 
                                            case=query['case'], 
                                            icon="clock.png")
        result.text("\n")
 
        result.table(
            elements = [ IntegerType(name='id', column='id'),
                         TimestampType(name='Time', column='time'),
                         EditableStringType('Notes', 'notes'),
                         StringType('Category', 'category')
                        ],
            table = 'timeline',
            case = query['case'],
        )



class ViewIPsOfInterest(Reports.report):
    """ View all IPs of interest """
    name = "View IPs of interest """
    family = "Case Management"
    order = 60

    def display(self,query,result):
        result.heading("IPs of interest for case %s" % query['case'])
        result.text("\n\nNYI\n\n")

class ViewCaseReport(Reports.report):
    """ View a pretty print case report """
    name = "View Case Report """
    family = "Case Management"
    order = 70

    def display(self,query,result):
        result.heading("Case report for %s" % query['case'])
        result.text("\n\nNYI\n\n")
