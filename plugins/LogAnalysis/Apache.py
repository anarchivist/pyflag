""" This module implements a Log driver for Apache logs """
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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
import pyflag.DB as DB
import re

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
field_codes={ 'a':['remote_ip', 'IP Address'],
              'A':['local_ip', 'IP Address'],
              'B':['rsize', 'int'],
              'b':['rsize_inc_headers', 'int'],
              'C':['cookie', 'varchar(250)'], # proceeded by {Foobar}
              'D':['srv_time', 'int'],
              'e':['env', 'varchar(250)'], # proceeded by {Foobar}
              'f':['filename', 'varchar(250)'],
              'h':['rhost', 'IP Address'],
              'H':['rprotocol', 'varchar(250)'],
              'i':['header', 'varchar(250)'],
              'l':['rlogname', 'varchar(250)'],
              'm':['rmethod', 'varchar(250)'],
              'n':['modnote', 'varchar(250)'], # proceeded by {Foobar}
              'o':['reheader', 'varchar(250)'], # proceeded by {Foobar}
              'p':['sport', 'int'],
              'P':['child_pid', 'int'], # {pid|tid}
              'q':['query_string', 'varchar(250)'],
              'r':['request', 'varchar(250)'],
              's':['status', 'int'],
              't':['time', 'datetime', trans_date ], # {strftime format} (optional)
              'T':['serve_time', 'int'],
              'u':['ruser', 'varchar(250)'],
              'U':['url', 'varchar(250)'],
              'v':['server_name', 'varchar(250)'],
              'V':['server_name_config', 'varchar(250)'],
              'X':['conn_aborted', 'varchar(250)'],
              '+':['conn_keptalive', 'varchar(250)'],
              '-':['conn_closedection', 'varchar(250)'],
              'I':['rbytes', 'int'],
              'O':['sbytes', 'int']}

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

class ApacheLog(LogFile.Log):
    """ Log parser for apache log files """
    name = "Apache Log"
    
    def __init__(self, variable, query):
        LogFile.Log.__init__(self,variable,query)
        self.separators = []
        self.types = []
        self.trans = []
        self.indexes = []
        self.fields = []
        if not query.has_key('format'):
            query['format'] = formats[formats.keys()[0]]
        self.format = query['format']
        self.parse_format()

    def parse_format(self):
        """ Do this:
        find '%', consume modifier, check/consume field code,
        find/consume delimiter(extra stuff), repeat
        """
        done = 0
        while 1:
            idx = self.format.find('%', done)
            if idx == -1:
                # at end now
                #self.separators.append(
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
                        self.fields.append("%s_%s" % (varname.lower(), field_codes[f][0]))
                        del varname
                    except UnboundLocalError:
                        self.fields.append(field_codes[f][0])

                    self.types.append(field_codes[f][1])
                    self.indexes.append(True)
                    try:
                        self.trans.append(field_codes[f][2])
                    except IndexError:
                        self.trans.append('')
                    break
                
            # skip up to the next '%'
            done = self.format.find('%', idx+1)
            if done == -1:
                self.separators.append(self.format[idx+1:])
            else:
                self.separators.append(self.format[idx+1:done])
                
    def get_fields(self):
        """ A generator that returns all the columns in a log file.

        @returns: A generator that generates arrays of cells
        """
        for row in self.read_record():
            idx = 0
            arr = []
            for sep in self.separators:
                idx2 = row.find(sep, idx)
                f = row[idx:idx2]
                idx = idx2 + len(sep)
                arr.append(f)
            for i in range(len(arr)):
                if self.trans[i] != '':
                    arr[i] = self.trans[i](arr[i])
            yield arr

    def form(self,query,result):
        """ This draws the form required to fulfill all the parameters for this report
        """

        # show a preview, may help user choose format
        result.start_table()
        result.row("Unprocessed text from file")
        sample = []
        count =0
        for line in self.read_record():
            sample.append(line)
            count +=1
            if count>3:
                break
            
        [result.row(s,bgcolor='lightgray') for s in sample]
        result.end_table()

        result.ruler()

        # select an existing format string
        result.const_selector("Choose Format String", 'format', formats.values(), formats.keys())

        result.row("Current Selection:",self.format)
