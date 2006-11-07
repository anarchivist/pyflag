""" This module implements a Log driver for IIS logs """
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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

class IISLog(Simple.SimpleLog):
    """ Log parser for IIS (W3C Extended) log files """
    name = "IIS Log"
    
    def __init__(self, case=None):
        Simple.SimpleLog.__init__(self)
        self.separators = []
        self.types = []
        self.trans = []
        self.indexes = []
        self.fields = []
        self.format = ''
        self.split_req = ''
        self.num_fields = 1


    def parse(self, query, datafile='datafile'):

        self.datafile = query.getarray(datafile)
        # set these params, then we can just use SimpleLog's get_fields
        self.delimiter = ' '
        self.prefilters = ['PFDateFormatChange2']

        # now for the IIS magic, the code below sets up the
        # fields, types, and indexes arrays req'd by load
        # replaces the need for the form in SimpleLog

        # Find the fields line:
        count=0
        for row in self.read_record(ignore_comment = False):
            count+=1
            if row.startswith('#Fields: '):
                dbh=DB.DBO(None)
                self.fields = [ dbh.MakeSQLSafe(i) for i in row.split()[1:] ]
                # Coallesc the date and time field together:
                try:
                    i = self.fields.index('date')
                    del self.fields[i]
                except ValueError:
                    pass

                break

            ## couldnt we find the field header?
            if count>15:
                raise Reports.ReportError("Error parsing IIS log file (I can't find a #Fields header line.) Maybe you may be able to use the simple log driver for this log?")
        
        # try to guess types based on known field-names, not perfect...
        # automatically index the non-varchar fields, leave the rest
        self.types=[]
        self.indexes=[]

        ## Note the original log file has -ip, -status etc, but afterm
        ## MakeSQLSafe dashes turn to underscores.
        for field in self.fields:
            if field == 'time':
                self.types.append('timestamp')
                self.indexes.append(True)
            elif '_ip' in field:
                self.types.append('IP Address')
                self.indexes.append(True)
            elif '_status' in field:
                self.types.append('int')
                self.indexes.append(True)
            elif '_bytes' in field:
                self.types.append('int')
                self.indexes.append(True)
            else:
                self.types.append('varchar(250)')
                self.indexes.append(False)
            
    def form(self, query, result):
        result.para('NOTICE: This loader attempts to load IIS log files completely automatically by determining field names and types from the header comments, if this loader fails, please use the "Simple" loader')

        def test(query,result):
            self.parse(query)
            print "self.fields: %s" % self.fields
            result.text("The following is the result of importing the first few lines from the log file into the database.\nPlease check that the importation was successfull before continuing.",wrap='full')
            self.display_test_log(result,query)
            return True

        result.wizard(
            names = (
            "Step 1: Select Log File",
            "Step 4: View test result",
            "Step 5: Save Preset"),
            callbacks = (LogFile.get_file, test, FlagFramework.Curry(LogFile.save_preset, log=self))
            )
