""" This module implements a Log driver for IIS logs

FIXME: This can be rewritten much simpler to use the SimpleLog parser
but just set the right tables etc in the form() method.
"""
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
import pyflag.LogFile as LogFile
import plugins.LogAnalysis.Simple as Simple
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
from pyflag.ColumnTypes import TimestampType, IntegerType, StringType, IPType
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import re

class IISLog(Simple.SimpleLog):
    """ Log parser for IIS (W3C Extended) log files """
    name = "IIS Log"
    
    def __init__(self, case=None):
        Simple.SimpleLog.__init__(self, case)
        self.separators = []
        self.types = []
        self.trans = []
        self.fields = []
        self.format = ''
        self.split_req = ''
        self.num_fields = 1

    def find_fields_line(self):
        # Find the fields line:
        count=0
        fields = None
        for row in self.read_record(ignore_comment = False):
            count+=1
            if row.startswith('#Fields: '):
                dbh=DB.DBO()
                fields = [ dbh.MakeSQLSafe(i) for i in row.split()[1:] ]
                # Coallesc the date and time field together:
                try:
                    i = fields.index('date')
                    del fields[i]
                except ValueError:
                    pass

                break

            ## couldnt we find the field header?
            if count>15:
                break
            
        if not fields:
            raise RuntimeError("Error parsing IIS log file (I can't find a #Fields header line.)\nMaybe you may be able to use the Simple or Advanced log driver for this log?")
        
        return fields

    def parse(self, query, datafile='datafile'):
        LogFile.Log.parse(self,query, datafile)

        self.datafile = query.getarray(datafile)
        # set these params, then we can just use SimpleLog's get_fields
        self.delimiter = re.compile(' ')
        self.prefilters = ['PFDateFormatChange2']

        if self.datafile:
            query.clear('fields')
            for f in self.find_fields_line():
                query['fields'] = f

        # now for the IIS magic, the code below sets up the
        # fields, types, and indexes arrays req'd by load
        # replaces the need for the form in SimpleLog

        # try to guess types based on known field-names, not perfect...
        # automatically index the non-varchar fields, leave the rest
        self.fields = []
        
        ## Note the original log file has -ip, -status etc, but after
        ## MakeSQLSafe dashes turn to underscores.
        for field in query.getarray('fields'):
            if field == 'time':
                tmp = TimestampType('Timestamp', 'timestamp')
                tmp.index = True
                self.fields.append(tmp)
            elif '_ip' in field:
                tmp = IPType('IP Address','IP Address')
                tmp.index = True
                self.fields.append(tmp)
            elif '_status' in field or '_bytes' in field:
                tmp = IntegerType(field,field)
                tmp.index = True
                self.fields.append(tmp)
            else:
                tmp = StringType(field,field)
                tmp.index = True
                self.fields.append(tmp)

    def form(self, query, result):
        result.para('NOTICE: This loader attempts to load IIS log files completely automatically by determining field names and types from the header comments, if this loader fails, please use the "Simple" loader')

        def test(query,result):
            self.parse(query)
            result.text("The following is the result of importing the first few lines from the log file into the database.\nPlease check that the importation was successfull before continuing.")
            self.display_test_log(result)
            return True

        result.wizard(
            names = (
            "Step 1: Select Log File",
            "Step 2: View test result",
            "Step 3: Save Preset",
            "Step 4: End",
            ),
            callbacks = (
            LogFile.get_file,
            test,
            FlagFramework.Curry(LogFile.save_preset, log=self),
            LogFile.end,
            ))

### Some unit tests for IIS loader:
import time
from pyflag.FlagFramework import query_type
import pyflag.pyflagsh as pyflagsh

class IISLogTest(LogFile.LogDriverTester):
    """ IIS Log file processing """
    test_case = "PyFlag Test Case"
    test_table = "Test Table"
    test_file = "pyflag_iis_standard_log.gz"
    log_preset = "IISTest"

    def test01CreatePreset(self):
        """ Test that IIS Presets can be created """
        dbh = DB.DBO(self.test_case)
        log = IISLog(case=self.test_case)
        query = query_type(datafile = self.test_file, log_preset=self.log_preset)
        log.parse(query)
        log.store(self.log_preset)
        
    def test02LoadFile(self):
        """ Test that IIS Log files can be loaded """
        dbh = DB.DBO(self.test_case)
        log = LogFile.load_preset(self.test_case, self.log_preset, [self.test_file])
        t = time.time()
        ## Load the data:
        for a in log.load(self.test_table):
            pass

        print "Took %s seconds to load log" % (time.time()-t)
            
        ## Check that all rows were uploaded:
        dbh.execute("select count(*) as c from `%s_log`", self.test_table)
        row = dbh.fetch()
        self.assertEqual(row['c'], 8334)

        ## More specific tests
        dbh.execute("select count(*) as c from `%s_log` where `IP Address` = 2921232307", self.test_table)
        row = dbh.fetch()
        self.assertEqual(row['c'], 129)


        dbh.execute("select count(*) as c from `%s_log` where cs_username = 'administrator'", self.test_table)
        row = dbh.fetch()
        self.assertEqual(row['c'], 7898)
