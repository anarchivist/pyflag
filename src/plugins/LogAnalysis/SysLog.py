""" This module implements a Comma Seperated Log driver for PyFlag """
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
import plugins.LogAnalysis.Simple as Simple
import pyflag.DB as DB
import LogFile
import FlagFramework
from pyflag.TableObj import TimestampType, IntegerType, StringType, IPType

class Syslog(Simple.SimpleLog):
    """ Log parser designed to handle simple syslog files
    """
    name = "Syslog"
   
    def __init__(self, case=None):
        Simple.SimpleLog.__init__(self, case)
        self.separators = []
        self.types = []
        self.trans = []
        self.fields = []
        self.prefilters = []
        self.delimiter = " "
        self.format = ''
        self.split_req = ''
        self.num_fields = 1
 
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

        self.fields = []
        self.num_fields = 3
        self.delimiter = " "  

        self.fields.append(TimestampType('TimeStamp', 'TimeStamp'))
        self.fields.append(StringType('Hostname', 'Hostname'))
        self.fields.append(StringType('ServiceName', 'ServiceName'))
        self.fields.append(StringType('Message', 'Message'))

        self.datafile = query.getarray(datafile)
        # set these params, then we can just use SimpleLog's get_fields
    
        if query.has_key("year_of_syslog"): self.yearOfSyslog=query['year_of_syslog']
        else: self.yearOfSyslog="1970"

    def get_fields(self):
        checkTime = re.compile("\d{0,2} \d{0,2} \d{0,2}:\d{0,2}:\d{0,2}$")
        for row in self.read_record():
            row = self.prefilter_record(row)
            
            ## Sanity check time with a regex so we can handle dodgy files
            firstfourCols=row.split(" ",4)
            timeString = ' '.join(firstfourCols[:3])

            if not checkTime.search(timeString): continue

            ## Time is either 1970 or user specified
            timeString = self.yearOfSyslog + timeString
            timeStamp = time.strftime("%Y%m%d%H%M%S", 
                        time.strptime(timeString, "%Y %b %d %H:%M:%S"))           
            
            if len(row.split(" ", 5)) > 4: host=row.split(" ",5)[3]
            else: continue

            ## A few special cases    
            if row.split(" ")[4:7] == ["--", "MARK", "--\n"]:
                service = "N/A"
                message = " -- MARK -- "
            else:
                service=row.split(" ",5)[4]
            
                # Tidy up kernel messages
                if service.endswith(":"): service=service[:-1]

                message=" ".join(row.split(" ")[5:])                

            yield [timeStamp, host, service, message]
