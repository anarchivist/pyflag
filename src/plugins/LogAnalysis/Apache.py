""" This module implements a Log driver for Apache logs """
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
import pyflag.LogFile as LogFile
import plugins.LogAnalysis.Simple as Simple
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import re
from pyflag.TableObj import IPType, TimestampType, StringType, IntegerType
import pyflag.conf
config=pyflag.conf.ConfObject()

def trans_date(time):
    """ convert time from apache ([01/Oct/2001:04:09:20 -0400]) to mysql (2001/10/01:04:09:20) """
    m = date_regex.match(time)
    if not m:
        return '0'
    else:
        f = m.groups()
        return "%s/%s/%s/:%s:%s:%s" % (f[2],months[f[1]],f[0],f[3],f[4],f[5])

# here are some standard apache formats taken from a debian httpd.conf
# add new ones here...
formats = { 'debian_full':"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{forensic-id}n\" %T %v",
            'debian_debug':"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{forensic-id}n\" %P %T",
            'debian_combined':"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{forensic-id}n\"",
            'debian_forensic':"%h %l %u %t \"%r\" %>s %b \"%{forensic-id}n\"",
            'debian_common':"%h %l %u %t \"%r\" %>s %b",
            'debian_referer':"%{Referer}i -> %U",
            'debian_agent':"%{User-agent}i"}

# The apache field codes, taken from apache2 documentation
## Format of each list: [column name, ColumnType class, translation function, index (true/false)]
field_codes={ 'a':['remote_ip', IPType, None, True],
              'A':['local_ip', IPType],
              'B':['rsize', IntegerType],
              'b':['rsize_inc_headers', IntegerType],
              'C':['cookie', StringType], # proceeded by {Foobar}
              'D':['srv_time', IntegerType],
              'e':['env', StringType], # proceeded by {Foobar}
              'f':['filename', StringType, None, True],
              'h':['rhost', IPType, None, True],
              'H':['rprotocol', StringType],
              'i':['header', StringType],
              'l':['rlogname', StringType],
              'm':['rmethod', StringType, None, True],
              'n':['modnote', StringType], # proceeded by {Foobar}
              'o':['reheader', StringType], # proceeded by {Foobar}
              'p':['sport', IntegerType],
              'P':['child_pid', IntegerType], # {pid|tid}
              'q':['query_string', StringType, None, True],
              'r':['request', StringType],
              's':['status', IntegerType, None, True],
              't':['time', TimestampType, trans_date , True], # {strftime format} (optional)
              'T':['serve_time', IntegerType],
              'u':['ruser', StringType],
              'U':['url', StringType, None, True],
              'v':['server_name', StringType],
              'V':['server_name_config', StringType],
              'X':['conn_aborted', StringType],
              '+':['conn_keptalive', StringType],
              '-':['conn_closedection', StringType],
              'I':['rbytes', IntegerType],
              'O':['sbytes', IntegerType]}

# most fields can also have modifiers, these are either:
# 1. optional "!" (meaning NOT) followed by a comma separated list of status codes for which the field will be logged (else log entry will just be '-')
# 2. characters '>' and '<' which determine actions where a redirect has occured
# in addition, some field codes such as 'o' and 'e' are proceeded by a name surrounded by {}. These are for arbitrarily named fields, such as request headers and environment variables

# this is a regex to eat modifiers
mod_regex = re.compile("!?[\d<>,]*")

# lookup table to translate month names
months = { 'Jan':1, 'Feb':2, 'Mar':3, 'Apr':4,
           'May':5, 'Jun':6, 'Jul':7, 'Aug':8,
           'Sep':9, 'Oct':10, 'Nov':11, 'Dec':12 }

# a regex to match standard apache time format
date_regex = re.compile('\[(\d\d)/(\w+)/(\d\d\d\d):(\d\d):(\d\d):(\d\d)\s([+-]\w+)\]')

def legend(query, result):
    """ Draw apache log file legend onto the given UI """
    result.heading("Apache log file format characters")
    result.start_table()
    for key in field_codes.keys():
        result.row(key, field_codes[key][0])
    result.end_table()

class ApacheLog(Simple.SimpleLog):
    """ Log parser for apache log files """
    name = "Apache Log"
    
    def __init__(self, case=None):
        Simple.SimpleLog.__init__(self,case)
        self.separators = []
        self.fields = []
        self.format = ''
        self.split_req = ''
        self.num_fields = 1

    def parse(self, query, datafile='datafile'):
        """ Do this:
        find '%', consume modifier, check/consume field code,
        find/consume delimiter(extra stuff), repeat
        """
        self.datafile = query.getarray(datafile)
        self.query = query

        if not query.has_key('format'):
            query['format'] = formats[formats.keys()[0]]
        try:
            self.format = query['format']
            self.split_req = query['split_req']
        except KeyError:
            pass

        # fixup string to split request into method/request/version
        if self.split_req == 'true':
            newformat = re.sub("%r", "%m %r %H", self.format)
            if newformat and len(newformat) > len(self.format):
                self.format = newformat
        
        self.num_fields = 1
        self.fields = [ ] 

        done = 0
        while 1:
            idx = self.format.find('%', done)
            if idx == -1:
                # at end now
                break
            idx += 1

            # consume modifier, dont really care about it
            m = mod_regex.match(self.format[idx:])
            if m:
                idx += m.end()

            # figure out the field
            # it could be proceeded with a {} used to refer to arbitrary env vars, http headers etc
            if self.format[idx] == '{':
                idx2 = self.format.find('}', idx)
                varname = self.format[idx+1:idx2]
                idx = idx2 + 1

            for f in field_codes:
                if self.format[idx] == f:
                    try:
                        name = "%s_%s" % (varname.lower(), field_codes[f][0])
                    except UnboundLocalError:
                        name = field_codes[f][0]

                    field = field_codes[f][1](name=name, column=name)

                    ## Install translation function:
                    try:
                        field.trans = field_codes[f][2]
                    except IndexError:
                        field.trans = None

                    ## Install indexes if needed:
                    try:
                        field.index = field_codes[f][3]
                    except IndexError:
                        field.index = False

                    self.fields.append(field)
                    break

            # skip up to the next '%'
            done = self.format.find('%', idx+1)
            if done == -1:
                self.separators.append(self.format[idx+1:])
            else:
                self.separators.append(self.format[idx+1:done])

        ## Now check that the right number of fields are provided:
        row_size=0
        count = 0
        for row in self.get_fields():
            if row_size < len(row):
                row_size = len(row)
            count +=1
            if count>10:
                break

        ## And truncate the fields list to match the input file
        self.fields = self.fields[:row_size]

        self.set_ignore_fields(query)

    def set_ignore_fields(self,query):
        # should any fields be ignored?
        for n in range(len(self.fields)):
            try:
                if query['ignore%s' % n] == 'true':
                    self.fields[n] = None
            except KeyError:
                pass
        
    def get_fields(self):
        """ A generator that returns all the columns in a log file.

        @returns: A generator that generates arrays of cells
        """
        for row in self.read_record():
            idx = 0
            arr = []
            for sep in self.separators:
                idx2 = row.find(sep, idx)
                # the last sep will be ''
                if idx2<0:
                    arr.append(row[idx:])
                    break
                
                arr.append(row[idx:idx2])
                idx = idx2 + len(sep)

            ## Do we require translation?
            for i in range(len(arr)):
                try:
                    arr[i] = self.fields[i].trans(arr[i])
                except:
                    pass
                    
            yield arr

    def form(self,query,result):
        """ This draws the form required to fulfill all the parameters for this report
        """
        def configure(query, result):
            result.start_table(hstretch=False)
            result.const_selector("Choose Format String", 'format', formats.values(), formats.keys())
            result.ruler()
            result.checkbox("Split Request into Method/URL/Version", "split_req", "true")
            result.end_table()
            

        def extra_options(query, result):
            self.parse(query)
            result.start_table()
            result.row("Raw text from file")
            sample = []
            count =0
            for line in self.read_record():
                sample.append(line)
                count +=1
                if count>3:
                    break

            [result.row(s,bgcolor='lightgray') for s in sample]
            result.end_table()
            
            result.start_table()
            result.heading("Select Options:")
            result.row("Select Fields to ignore:")
            for i in range(len(self.fields)):
                try:
                    result.checkbox(self.fields[i].name, 'ignore%s' % i, 'true')
                except: pass
            result.end_table()

            #self.draw_type_selector(result)

        def test(query,result):
            self.parse(query)
            result.text("The following is the result of importing the first few lines from the log file into the database.\nPlease check that the importation was successfull before continuing.")
            self.display_test_log(result)
            return True

        result.wizard(
            names = (
            "Step 1: Select Log File",
            "Step 2: Select Format String",
            "Step 3: Select Options",
            "Step 4: View test result",
            "Step 5: Save Preset",
            "Step 6: End",
            ),
            callbacks = (
            LogFile.get_file,
            configure,
            extra_options,
            test,
            FlagFramework.Curry(LogFile.save_preset, log=self),
            LogFile.end,
            ))

### Some unit tests for IIS loader:
import time
from pyflag.FlagFramework import query_type

class ApacheLogTest(LogFile.LogDriverTester):
    """ Apache Log file processing """
    test_case = "PyFlagTestCase"
    log_preset = "ApacheDebianCommon_test"
    test_table = "Apache_test"
    datafile = "%s/pyflag_apache_standard_log.gz" % config.UPLOADDIR

    def test01CreatePreset(self):
        """ Create a preset """
        ## First create a preset
        log = ApacheLog(case=self.test_case)
        log.parse(query_type(formats['debian_common'],
                             datafile = self.datafile))
        log.store(self.log_preset)

    def test02LoadFile(self):
        """ Test that Apache Log files can be loaded """
        ## See if we can load the preset again:
        log = LogFile.load_preset(self.test_case, self.log_preset, [self.datafile])

        t = time.time()
        ## Load the data:
        for a in log.load(self.test_table):
            print a

        print "Took %s seconds to load log" % (time.time()-t)

        ## Check that all rows were uploaded:
        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as c from %s_log", self.test_table)
        row = dbh.fetch()
        self.assertEqual(row['c'], 10000)
