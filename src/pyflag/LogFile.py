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

def get_file(query,result):
    result.row("Select a sample log file for the previewer",stretch=False)
    tmp = result.__class__(result)
    tmp.filebox(target='datafile')
    result.row("Enter name of log file:",tmp)
    if query.has_key('datafile'):
        return True
    else:
        result.text("Please input a log file name\n",color='red')
        return False

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
    def parse(self, query, datafile="datafile"):
        """ Parse all options from query and update ourselves.

        This may be done several times during the life of an
        object. We need to ensure that we completely refresh all data
        which is unique to our instance.
        """
        
    def __init__(self, case=None):
        self.case = case
        
    def form(self,query,result):
        """ This method will be called when the user wants to configure a new instance of us. IE a new preset """

    def reset(self, query):
        """ This is called to reset the log tables this log driver has created """

    def display_test_log(self,result):
        # try to load and display as a final test
        dbh = DB.DBO(self.case)
        temp_table = dbh.get_temp()

        for a in self.load(temp_table,rows= 3):
            pass

        ## Display the new table
        self.display(temp_table, result)
    
    def read_record(self, ignore_comment = True):
        """ Generates records.

        This can handle multiple files as provided in the constructor.
        """
        if not self.datafile:
            raise IOError("Datafile is not set!!!")
        
        for file in self.datafile:
            try:
                ## Allow log files to be compressed.
                fd=gzip.open(file,'r')
            except:
                fd=open(file,'r')
                
            for line in fd:
                if line.startswith('#') and ignore_comment:
                    continue
                else:
                    yield line

    def load(self,tablename, rows = None):
        """ Loads the specified number of rows into the database.

        @arg table_name: A table name to use
        @arg rows: number of rows to upload - if None , we upload them all
        @return: A generator that represents the current progress indication.
        """        
        ## First we create the table. We do this by asking all the
        ## column types for their create clause:
        dbh = DB.DBO(self.case)
        dbh.cursor.ignore_warnings = True
        dbh.mass_insert_start(tablename, _fast=True)

        fields = [ x for x in self.fields if x]
        if len(fields)==0:
            raise RuntimeError("No Columns were selected.")
        
        dbh.execute("create table if not exists %s (%s)", (
            tablename,
            ',\n'.join([ x.create() for x in fields])
            ))

        ##  Now insert into the table:
        count = 0
        for fields in self.get_fields():
            count += 1

            args = dict()
            for i in range(len(self.fields)):
                try:
                    key, value = self.fields[i].insert(fields[i])
                    args[key] = value
                except (IndexError,AttributeError):
                    pass
                
            if args:
                dbh.mass_insert( **args)
            
            if rows and count > rows:
                break

            if not count % 1000:
                yield "Loaded %s rows" % count

        dbh.mass_insert_commit()
        ## Now create indexes on the required fields
        for i in self.fields:
            try:
                if i.index:
                    dbh.check_index(tablename, i.sql)
            except AttributeError:
                pass

        return

    def store(self, name):
        """ Stores the configured driver in the db.

        Note that Log objects are asked to pickle themselves. However
        the base class uses a generic pickler. If you need to do
        something really special for pickling or unpickling, you may
        override this method.
        """
        ## Clear stuff that is not relevant
        self.datafile = None
        self.case=None
        data=pickle.dumps(self)
        dbh = DB.DBO(self.case)
        dbh.set_meta("log_preset", name,force_create=True)
        dbh.set_meta("log_preset_%s" % name, data)

    def display(self,table_name, result):
        """ This method is called to display the contents of the log
        file after it has been loaded
        """
        ## Display the table if possible:
        result.table(
            ## We can calculate the elements directly from our field
            ## list:
            elements = [ f for f in self.fields if f ],
            table = table_name,
            case = self.case
            )

        return result

def get_loader(case ,name,datafile="datafile"):
    """ lookup and unpickle log object from the database, return loader object

    We also initialise the object to the datafile list of filenames to use.
    """
    pydbh = DB.DBO(None)
    log=pickle.loads(pydbh.get_meta('log_preset_%s' % name))
    log.datafile = datafile
    log.case = case
    return log

## Some common callbacks which log drivers might need:
def end(query,result):
    """ This is typically the last wizard callback - we just refresh
    into the load preset log file report"""
    query['log_preset'] = 'test'
    result.refresh(0, query_type(log_preset=query['log_preset'], report="Load Preset Log File", family="Load Data"), pane='parent')
