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
#  Version: FLAG $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
import os
import pyflag.conf
config=pyflag.conf.ConfObject()

from os.path import join

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
                #Get handle to flag db
        dbh = self.DBO(None)
        dbh.execute("Create database if not exists %s",(query['create_case']))
        dbh.execute("select * from meta where property='flag_db' and value=%r",query['create_case'])
        if not dbh.fetch():
            dbh.execute("Insert into meta set property='flag_db',value=%r",query['create_case'])

        #Get handle to the case db
        case_dbh = self.DBO(query['create_case'])
        case_dbh.execute("Create table if not exists meta(`time` timestamp(14) NOT NULL,property varchar(50), value text, KEY property(property), KEY value(value(10)))",())

        case_dbh.execute("create table if not exists bookmarks (id int(11) auto_increment, canon text, url text,  description text,  bookmark text ,  PRIMARY KEY  (id),  KEY id (id))",())

        ## Create a directory inside RESULTDIR for this case to store its temporary files:
        try:
            os.mkdir("%s/case_%s" % (config.RESULTDIR,query['create_case']))
        except OSError:
            pass

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
        #Delete the case from the database
        dbh = self.DBO(None)
        dbh.execute("drop database if exists %s" ,query['remove_case'])
        dbh.execute("delete from meta where property='flag_db' and value=%r",query['remove_case'])

        ## Delete the temporary directory corresponding to this case and all its content
        try:
            temporary_dir = "%s/case_%s" % (config.RESULTDIR,query['remove_case'])
            for root, dirs, files in os.walk(temporary_dir,topdown=False):
                for name in files:
                    os.remove(join(root, name))
                for name in dirs:
                    os.rmdir(join(root, name))

            os.rmdir(temporary_dir)
        except:
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
        
        dbh = self.DBO(None)
        dbh.execute("drop database if exists %s" ,query['reset_case'])
        dbh.execute("Create database %s",(query['reset_case']))

        #Get handle to the case db
        case_dbh = self.DBO(query['reset_case'])
        case_dbh.execute("Create table meta(`time` timestamp(14) NOT NULL,property varchar(50), value text, KEY property(property),KEY value(value(10)))",())
        case_dbh.execute("create table bookmarks (id int(11) auto_increment, canon text, url text,  description text,  bookmark text ,  PRIMARY KEY  (id),  KEY id (id))",())

        ## Delete all files from the cases temporary directory:
        temporary_dir = "%s/case_%s" % (config.RESULTDIR,query['reset_case'])

        ## Make sure its actually created:
        try:
            os.mkdir("%s/case_%s" % (config.RESULTDIR,query['reset_case']))
        except OSError:
            pass

        for root, dirs, files in os.walk(temporary_dir,topdown=False):
            for name in files:
                os.remove(join(root, name))
            for name in dirs:
                os.rmdir(join(root, name))

        result.para("Case %s has been reset" % query['reset_case'])
        return result
