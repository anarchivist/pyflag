""" This module is used for loading generic syslog messages

We really have little logic here- we just split the message line to a
time stamp, a syslog source and a message text. This means we probably
cant use any indexes for searching the message text so its going to be
slow.

Note that the exact format of a syslog message is specified in:
http://www.faqs.org/rfcs/rfc3164.html

And in particular:

The TIMESTAMP field is the local time and is in the format of "Mmm dd
hh:mm:ss" (without the quote marks) where:

Mmm is the English language abbreviation for the month of the
year with the first character in uppercase and the other two
characters in lowercase.

"""
# Michael Cohen <scudette@users.sourceforge.net>
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
import time, re
import pyflag.LogFile as LogFile
import pyflag.DB as DB
import FlagFramework
from pyflag.TableObj import TimestampType, IntegerType, StringType, IPType
import pyflag.conf
config = pyflag.conf.ConfObject()
import pyflag.pyflaglog as pyflaglog

class Syslog(LogFile.Log):
    """ Log parser designed to handle simple syslog files
    """
    name = "Syslog"
    yearOfSyslog= 1970
    
    def form(self, query, result):
    
        def test(query, result):
            self.parse(query)
    
            result.text("The following is the result of importing the first few lines from the log file into the database.\nPlease check that the importation was successfull before continuing.\n\n")
            result.text("You can adjust the year of the syslog below. Please note it does currently assume that all entries are from the one year.\n")
            result.textfield("Year of syslog:",'year_of_syslog')
            self.display_test_log(result)
            return True

        result.wizard(
            names = [ "Step 1: Select Log File",
                      "Step 2: View Preview",
                      "Step 3: Save Preset",
                      "Step 4: End"],
            callbacks = [LogFile.get_file,
                         test,
                         FlagFramework.Curry(LogFile.save_preset, log=self),
                         LogFile.end
                         ],
            )

    def parse(self, query, datafile='datafile'):
        LogFile.Log.parse(self, query,datafile)

        self.fields = []
        self.delimiter = re.compile("\s+")

        self.fields.append(TimestampType('TimeStamp', 'TimeStamp'))
        self.fields.append(StringType('Hostname', 'Hostname'))
        self.fields.append(StringType('ServiceName', 'ServiceName'))
        self.fields.append(StringType('Message', 'Message'))

        self.datafile = query.getarray(datafile)

        try:
            self.yearOfSyslog=int(query['year_of_syslog'])
        except: pass

    def get_fields(self):
        for row in self.read_record():
            fields = re.split("\s+", row, 5)

            if len(fields)<5:
                pyflaglog.log(pyflaglog.DEBUG, "row does not have enough elements?")
                continue

            ## Try to parse the time:
            try:
                timestamp_str = " ".join(fields[:2])
                t = list(time.strptime(timestamp_str, "%b %d %H:%M:%S"))
            except ValueError:
                pyflaglog.log(pyflaglog.DEBUG, "Unable to parse %s as a time" % timestamp_str)
                continue

            ## Set the year of this timestamp
            t[0] = self.yearOfSyslog

            yield [t, fields[3], fields[4], fields[5]]

import time
import pyflag.pyflagsh as pyflagsh
from pyflag.FlagFramework import query_type

class SyslogTest(LogFile.LogDriverTester):
    """ Syslog Log file processing """
    test_case = "PyFlagTestCase"
    test_table = "TestTable"
    test_file = "%s/messages.gz" % config.UPLOADDIR
    log_preset = "IPTablesTest"

    def test01CreatePreset(self):
        """ Test that Syslog Presets can be created """
        dbh = DB.DBO(self.test_case)
        log = Syslog(case=self.test_case)
        query = query_type(datafile = self.test_file, log_preset=self.log_preset)

        log.parse(query)
        log.store(self.log_preset)
        
    def test02LoadFile(self):
        """ Test that Syslog Log files can be loaded """
        dbh = DB.DBO(self.test_case)
        log = LogFile.load_preset(self.test_case, self.log_preset, [self.test_file])
        t = time.time()
        ## Load the data:
        for a in log.load(self.test_table):
            pass

        print "Took %s seconds to load log" % (time.time()-t)
            
        ## Check that all rows were uploaded:
        dbh.execute("select count(*) as c from %s_log", self.test_table)
        row = dbh.fetch()
        self.assertEqual(row['c'], 2433)
