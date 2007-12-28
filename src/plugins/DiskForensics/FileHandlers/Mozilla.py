# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
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
""" A parser for handling Mozilla history files. These files are
stored in the Mork format.
"""
from pyflag.TableObj import StringType, TimestampType, FilenameType, InodeIDType
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import FileFormats.MozHist as MozHist
import pyflag.pyflaglog as pyflaglog

class MozHistEventHandler(FlagFramework.EventHandler):
    def create(self, dbh, case):
        dbh.execute("""CREATE TABLE IF NOT EXISTS mozilla_history (
        `inode_id` int not null,
        `id` int not null,
        `name` VARCHAR(250) NOT NULL,
        `url`  VARCHAR(500) NOT NULL,
        host VARCHAR(250),
        `Typed` int,
        `LastVisitDate` TIMESTAMP,
        `VisitCount` INT,
        `FirstVisitDate` TIMESTAMP,
        `Referrer` VARCHAR(500)
        )""")

        dbh.execute("""CREATE TABLE IF NOT EXISTS mozilla_form_history (
        `inode_id` int not null,
        `id` int not null,
        `name` VARCHAR(250) NOT NULL,
        `value` VARCHAR(250) NOT NULL)""")

class BrowserHistoryReport(Reports.report):
    """ View Browser History """
    name = "Browser History"
    family = "Disk Forensics"

    def display(self, query,result):
        def hist_cb(query,result):
            elements = [ InodeIDType('Inode','inode_id', case=query['case']),
                         TimestampType('LastVisitDate','LastVisitDate'),
                         StringType('Name', 'name'),
                         StringType('URL', 'url'),
                         StringType('Host', 'host'),
                         StringType('Referrer', 'Referrer'),
                         ]
            
            result.table(
                elements = elements,
                table = 'mozilla_history',
                case = query['case'],
                filter='hist_filter',
                )

        def form_cb(query, result):
            result.table(
                elements = [ InodeIDType('Inode', 'inode_id', case=query['case']),
                             StringType('Name','name'),
                             StringType('Value', 'value'),
                             ],
                table = 'mozilla_form_history',
                filter='form_filter',
                case = query['case'],
                )

        def ie_history_cb(query,result):
            dbh=self.DBO(query['case'])
            dbh.check_index("ie_history" ,"url",10)
            
            result.table(
                elements = [ InodeIDType('Inode','inode_id', case=query['case']),
                             StringType('Type','type'),
                             StringType('URL','url'),
                             TimestampType('Modified','modified'),
                             TimestampType('Accessed','accessed'),
                             StringType('Filename', 'filename'),
                             StringType('Headers','headers') ],
                table='ie_history',
                case=query['case']
                )


        result.notebook(names = ['Mozilla History', 'Mozilla Forms', 'IE Cache'],
                        callbacks = [ hist_cb, form_cb, ie_history_cb])

## We make the scanner store it in memory - typically history files
## are not that large.
class MozHistScan(Scanner.GenScanFactory):
    class Scan(Scanner.StringIOType):
        mork = None
        def boring(self, metadata, data=''):
            if self.mork == None: 
                if 'mdb:mork:z v="1.4"' in data:
                    self.mork = False
                else: self.mork = True

            return self.mork

        def external_process(self, fd):
            ## Read all the events from the file:
            pyflaglog.log(pyflaglog.DEBUG, "Processing %s as mork" % self.fd.inode)
            
            dbh = DB.DBO(self.case)
            inode_id = self.fd.lookup_id()
            
            h = MozHist.MozHist(fd=fd)
            context = None
            while 1:
                token = h.next_token()
                if not token: break

                if token=='EVENT_END':
                    e = h.event
                    if not context:
                        if "formhistory" in h.types['80']:
                            context = 'form'
                        else:
                            context = 'history'

                    if context == 'form':
                        dbh.insert('mozilla_form_history',
                                   inode_id = inode_id,
                                   id = e['id'],
                                   name = e['Name'],
                                   value = e['Value'])

                    else:
                        result = dict(
                            inode_id = inode_id,
                            url  = e['URL'],
                            _LastVisitDate = "from_unixtime('%s')" % e['LastVisitDate'][:10],
                            _FirstVisitDate = "from_unixtime('%s')" % e['FirstVisitDate'][:10],
                            id = e['id'])

                        try: result['Typed'] = e['Typed']
                        except: pass

                        try: result['Referrer'] = e['Referrer']
                        except: pass

                        try: result['VisitCount'] = e['VisitCount']
                        except: pass

                        try: result['name'] = e['Name']
                        except: pass

                        try: result['host'] = e['Hostname']
                        except: pass

                        dbh.insert('mozilla_history', **result)
            
import pyflag.tests
import pyflag.pyflagsh as pyflagsh

class MozHistScanTest(pyflag.tests.ScannerTest):
    """ Test Mozilla History scanner """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.4.e01"
    subsystem = 'EWF'
    offset = "16128s"

    def test01RunScanner(self):
        """ Test EventLog scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'MozHistScan'])

