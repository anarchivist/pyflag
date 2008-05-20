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
#  Version: FLAG $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
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
import pyflag.Registry as Registry
import time
import pyflag.pyflagsh as pyflagsh

description = "Case management"
order = 10

class NewCase(Reports.report):
    """ Creates a new flag case database."""
    parameters = {"create_case":"sqlsafe"}
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
        try:
           pyflagsh.shell_execv(command='create_case',
                             argv=[ query['create_case'],])
        except RuntimeError, e:

            result.heading("Problem Creating Case!")
            result.para("There was a problem creating the case. Are you sure "\
                        "that this wasn't because a database with the same "\
                        "name already existed in the DB?")
            result.para("Perhaps try again with a different name.")
            result.link("Try again", family="Case Management", 
                        report="Create new case")
            return result

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
        query['reset_case']=query['case']
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

        query['case'] = query['reset_case']

        result.para("Case %s has been reset" % query['reset_case'])
