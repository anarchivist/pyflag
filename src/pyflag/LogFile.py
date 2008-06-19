#!/usr/bin/env python
# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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

""" Module for handling Log Files """
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
from pyflag.FlagFramework import query_type
import pyflag.DB as DB
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.pyflaglog as pyflaglog
import pickle,gzip
import plugins.LogAnalysis.Whois as Whois
from pyflag.ColumnTypes import IPType
import re
import pyflag.Registry as Registry
import pyflag.IO as IO
import cStringIO
import pyflag.code_parser as code_parser

def get_file(query,result):
    result.row("Select a sample log file for the previewer",stretch=False)
    result.fileselector("Please input a log file name", 'datafile')

def save_preset(query,result, log=None):
    result.textfield("name for preset:",'log_preset')
    if query.has_key('log_preset'):
        log.parse(query)
        log.store(query['log_preset'])
        query['finished']='yes'
        return True
    else:
        result.text("Please type a name for the preset.\n",color='red')
        return False

class Log:
    """ This base class abstracts Loading of log files.

    Log files are loaded through the use of log file drivers. These
    drivers extend this class, possibly providing new methods for form
    and field, and potentially even read_record.
    """
    name = "BaseClass"
    datafile = None
    query = query_type()
    
    def parse(self, query, datafile="datafile"):
        """ Parse all options from query and update ourselves.

        This may be done several times during the life of an
        object. We need to ensure that we completely refresh all data
        which is unique to our instance.

        Note that you may or may not be provided with a datafile
        here. Its ok to parse the datafile to get some important
        information (e.g. number of columns etc) if its provided but
        you must save those details in the query so you can retrieve
        them from the query in the case you dont have a datafile.

        The important requirement here is that you must be able to
        completely parse an instance of the driver from a query string
        and nothing else (because thats how it gets stored in the db).
        """
        self.query = query
        
    def __init__(self, case=None):
        self.case = case

    def drop(self, name):
        """ Drops the table named in name.
        
        By default we name the table in the db with name+'_log', but
        that is theoretically transparent to users.
        """
        tablename = name + "_log"
        dbh = DB.DBO(self.case)
        dbh.drop(tablename)
        
    def form(self,query,result):
        """ This method will be called when the user wants to configure a new instance of us. IE a new preset """

    def reset(self, query):
        """ This is called to reset the log tables this log driver has created """

    def display_test_log(self,result, filter=None):
        # try to load and display as a final test
        dbh = DB.DBO(self.case)
        temp_table = dbh.get_temp()

        ## Is there a filter implemented?
        fields = [ x for x in self.fields if x]
        if filter:
            filter_parser = code_parser.parse_eval(filter, fields, None)
        else:
            filter_parser = None

        ## Temporarily store a preset:
        self.store(temp_table)

        try:
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "About to attempt to load three rows into a temp table for the preview")

            ## Since this should be a temporary table, we explicitly tell the load
            ## method to drop it if it exists
            for a in self.load(temp_table,rows= 3, filter=filter):
                pass

            pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Created a test table containing three rows. About to try and display it...")

            del result.defaults['filter']
            ## Display the new table
            self.display(temp_table, result)
            
        finally:
            ## Drop the temporary preset and the table
            drop_preset(temp_table)
            try:
                drop_table(self.case, temp_table)
            except RuntimeError:
                pass
            
    def read_record(self, ignore_comment = True):
        """ Generates records.

        This can handle multiple files as provided in the constructor.
        """
        
        blank = re.compile("^\s*$")

        if self.datafile==None:
            raise IOError("Datafile is not set!!!")
        
        for file in self.datafile:
            ## open the file as a url:
            fd = IO.open_URL(file)
            buffer = ''
            while 1:
                if len(buffer) < 1024:
                    data = fd.read(1024)
                    buffer = buffer + data

                tmp = buffer.split("\n",1)
                if len(tmp) == 0: break

                line = tmp[0]
               
                try:
                    buffer = tmp[1]
                except:
                    data = fd.read(1024)
                    if len(data) == 0:
                        break
                    buffer = line + data
                    continue
                
                if blank.match(line) or not line:
                    continue
                if line.startswith('#') and ignore_comment:
                    continue
                else:
                    yield line

    def get_fields(self):
        """ A generator that returns all the columns in a log file.

        This can either return an array, in which case the columns
        return correspond with the order specificied by self.fields,
        or a dict in which case the keys are column names.

        You probably want to over ride this....
        """
        ## By default we dont split the row
        return [self.read_record(),]
    
    def load(self,name, rows = None, deleteExisting=None, filter=None):
        """ Loads the specified number of rows into the database.

        __NOTE__ We assume this generator will run to
        completion... This is a generator just in order to provide a
        running progress indication - maybe this should change?

        @arg table_name: A table name to use
        @arg rows: number of rows to upload - if None , we upload them all
        @arg deleteExisting: If this is anything but none, tablename will first be dropped
        @return: A generator that represents the current progress indication.
        """
        ## We append _log to tablename to prevent name clashes in the
        ## db:
        tablename = name+"_log"
        ## Set the table for our columns:
        for f in self.fields: f.table = tablename
        
        ## First we create the table. We do this by asking all the
        ## column types for their create clause:
        dbh = DB.DBO(self.case)

        dbh.cursor.ignore_warnings = True
        dbh.mass_insert_start(tablename, _fast=True)
        dbh.invalidate(tablename)

        fields = [ x for x in self.fields if x]
        if len(fields)==0:
            raise RuntimeError("No Columns were selected.")
        
        ## Add our table to the table list. This is done first to trap
        ## attempts to reuse the same table name early. FIXME - create
        ## a combined index on driver + table_name
        try:
            dbh.insert("log_tables",
                       preset = self.name,
                       table_name = name)
        except DB.DBError,e:
            pyflaglog.log(pyflaglog.WARNING, "Table %s already exists (%s)" % (name, e))

        ## Create the table:
        creation_strings = [ x.create() for x in fields]
        dbh.execute("create table if not exists `%s` (%s)", (
            tablename,
            ',\n'.join([ x for x in creation_strings if x])
            ))

        ## Is there a filter implemented?
        if filter:
            print fields
            filter_parser = code_parser.parse_eval(filter, fields, None)
        else:
            filter_parser = None

        ## Now insert into the table:
        count = 0
        for fields in self.get_fields():
            count += 1
            args = None
            columns = {}
            if isinstance(fields, list):
                args = dict()
                ## Iterate on the shortest of fields (The fields array
                ## returned from parsing this line) and self.fields
                ## (The total number of fields we expect)
                for i in range(min(len(self.fields),len(fields))):
                    try:
                        c = self.fields[i]
                        v = fields[i]
                        columns[c.column] = v

                        ## Ask the columns to format their own insert statements
                        key, value = c.insert(v)
                        args[str(key)] = value
                    except (IndexError,AttributeError),e:
                        pyflaglog.log(pyflaglog.WARNING, "Attribute or Index Error when inserting value into field: %r" % e)
            elif isinstance(fields, dict):
                args = fields
                columns = fields
                
            ## If the filter does not match, we ignore this row:
            if filter_parser:
                if not filter_parser(columns): continue

            if args:
                dbh.mass_insert(args)
            
            if rows and count > rows:
                break

            if not count % 1000:
                yield "Loaded %s rows" % count

        dbh.mass_insert_commit()
        ## Now create indexes on the required fields
        for i in self.fields:
            try:
                ## Allow the column type to create an index on the
                ## column
                if i.index:
                    i.make_index(dbh, tablename)
            except AttributeError:
                pass

        return

    def restore(self, name):
        """ Restores the table from the log tables (This is the
        opposite of self.store(name))
        """
        dbh = DB.DBO()
        dbh.execute("select * from log_presets where name=%r limit 1" , name)
        row = dbh.fetch()
        self.query = query_type(string=row['query'])
        self.name = name

    def store(self, name):
        """ Stores the configured driver in the db.

        Realistically since drivers can only be configured by the GUI
        the query string that caused them to be configured is the best
        method to reconfigure them in future. This is what is
        implemented here.
        """
        dbh = DB.DBO()
        ## Clean up the query a little:
        self.query.clear('datafile')
        self.query.clear('callback_stored')

        dbh.insert("log_presets",
                   name = name,
                   driver = self.name,
                   query = self.query)

    def display(self,table_name, result):
        """ This method is called to display the contents of the log
        file after it has been loaded
        """
        ## Display the table if possible:
        result.table(
            ## We can calculate the elements directly from our field
            ## list:
            elements = [ f for f in self.fields if f and not f.ignore ],
            table = "%s_log" % table_name,
            case = self.case
            )

        return result

## The following methods unify manipulation and access of log presets.
## The presets are stored in FLAGDB.log_presets and the table names
## are stored in casedb.log_tables. The names specified in the
## log_tables table sepecify the naked names of the log tables. By
## convension all log tables need to exist on the disk using naked
## name postfixed by _log.

def load_preset(case, name, datafiles=[]):
    """ Loads the preset named with the given datafiles and return an
    initialised object
    """
    dbh = DB.DBO()
    dbh.execute("select * from log_presets where name=%r limit 1" , name)
    row = dbh.fetch()
    if not row: raise RuntimeError("Unable to find preset %s" % name)
    
    log = Registry.LOG_DRIVERS.dispatch(row['driver'])(case)
    log.restore(name)

    del log.query['datafile']
    
    for f in datafiles:
        log.query['datafile'] = f

    log.parse(log.query)

    return log

def drop_table(case, name):
    """ Drops the log table tablename """
    if not name: return
    
    dbh = DB.DBO(case)
    pyflaglog.log(pyflaglog.DEBUG, "Dropping log table %s in case %s" % (name, case))

    dbh.execute("select * from log_tables where table_name = %r limit 1" , name)
    row = dbh.fetch()

    ## Table not found
    if not row:
        return
    
    preset = row['preset']

    ## Get the driver for this table:
    log = load_preset(case, preset)
    log.drop(name)
    
    ## Ask the driver to remove its table:
    dbh.delete("log_tables",
               where="table_name = %r " % name);

    ## Make sure that the reports get all reset
    FlagFramework.reset_all(family='Load Data', report="Load Preset Log File",
                                       table = name, case=case)

def find_tables(preset):
    """ Yields the tables which were created by a given preset.

    @return: (database,table)
    """
    dbh=DB.DBO()
    
    ## Find all the cases we know about:
    dbh.execute("select value as `case` from meta where property = 'flag_db'")
    for row in dbh:
        case = row['case']
        ## Find all log tables with the current preset
        try:
            dbh2=DB.DBO(case)
            dbh2.execute("select table_name from log_tables where preset=%r", preset)
            for row2 in dbh2:
                yield (case, row2['table_name'])
                
        except DB.DBError,e:
            pass

def drop_preset(preset):
    """ Drops the specified preset name """
    pyflaglog.log(pyflaglog.DEBUG, "Droppping preset %s" % preset)
    for case, table in find_tables(preset):
        drop_table(case, table)

    dbh = DB.DBO()
    if preset:
        dbh.delete("log_presets", where="name = %r" % preset)
    
## Some common callbacks which log drivers might need:
def end(query,result):
    """ This is typically the last wizard callback - we just refresh
    into the load preset log file report"""
    query['log_preset'] = 'test'
    result.refresh(0, query_type(preset=query['log_preset'],
                                 report="Load Preset Log File",
                                 family="Load Data"),
                   pane='parent')

import unittest
import pyflag.pyflagsh as pyflagsh

class LogDriverTester(unittest.TestCase):
    test_case = None
    test_table = None
    test_table_two = None
    log_preset = None
    log_preset_two = None
    datafile = None
    
    def test00Cleanup(self):
        """ Remove test log tables """
        ## Create the case if it does not already exist:
        pyflagsh.shell_execv(command = "delete_case",
                             argv=[self.test_case])

        ## Create the case if it does not already exist:
        pyflagsh.shell_execv(command = "create_case",
                             argv=[self.test_case])
        
        ## clear any existing presets of the same name:
        drop_preset(self.log_preset)
        drop_preset(self.log_preset_two)

        ## Clear any existing tables of the same name
        drop_table(self.test_case, self.test_table)
        drop_table(self.test_case, self.test_table_two)

    ## FIXME:
    ## This is disabled so as to leave the test table behind - this is
    ## required for development so we can examine the table afterwards
    def XXXtest99Cleanup(self):
        """ Remove test log tables """
        ## clear the preset we created
        drop_preset(self.log_preset)
