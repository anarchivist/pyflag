# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
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
""" A parser for handling Mozilla history files. These files are
stored in the Mork format.

    Also contains a parser for handing Mozilla/Firefox Cache directories.
"""
from pyflag.ColumnTypes import StringType, TimestampType, FilenameType, InodeIDType
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import FileFormats.MozHist as MozHist
import FileFormats.MozCache as MozCache
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
        `LastVisitDate` TIMESTAMP NULL default '0000-00-00 00:00:00',
        `VisitCount` INT,
        `FirstVisitDate` TIMESTAMP NULL default '0000-00-00 00:00:00',
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
            result.table(
                elements = [ InodeIDType(case=query['case']),
                             TimestampType('LastVisitDate','LastVisitDate'),
                             StringType('Name', 'name'),
                             StringType('URL', 'url'),
                             StringType('Host', 'host'),
                             StringType('Referrer', 'Referrer'),
                             ],
                table = 'mozilla_history',
                case = query['case'],
                filter='hist_filter',
                )

        def form_cb(query, result):
            result.table(
                elements = [ InodeIDType(case=query['case']),
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
                elements = [ InodeIDType(case=query['case']),
                             StringType('Type','type'),
                             StringType('URL','url'),
                             TimestampType('Modified','modified'),
                             TimestampType('Accessed','accessed'),
                             StringType('Filename', 'filename'),
                             StringType('Headers','headers') ],
                table='ie_history',
                case=query['case'],
                )

        result.notebook(names = ['Mozilla History', 'Mozilla Forms', 'IE Cache'],
                        callbacks = [ hist_cb, form_cb, ie_history_cb])

## We make the scanner store it in memory - typically history files
## are not that large.
class MozHistScan(Scanner.GenScanFactory):
    """ Scan for Mozilla history files """
    default = True
    depends = ['TypeScan']
    
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

import pyflag.Magic as Magic

class Mork(Magic.Magic):
    """ Detect Mork files """
    type = "Mozilla History (Mork)"
    mime = 'application/x-mozilla-history'

    regex_rules = [
        ( '<mdb:mork:z', (0,10) ),
        ]

    samples = [
        ( 100, '// <!-- <mdb:mork:z v="1.4"/> -->' ),
        ]

## Mozilla Cache handling, populates the http table as used by the http
## scanner.

import httplib
import StringIO
import pyflag.Time as Time

def parse_response(meta):
    """ Parse Cache Metadata, returns (method, status, header) """
    try:
        method = meta['request-method']
    except KeyError:
        method = "UNKNOWN"

    try:
        header = meta['response-head'].splitlines(True)
        status = header[0].split(None, 2)[1]
        header = httplib.HTTPMessage(StringIO.StringIO("".join(header[1:])))
    except KeyError:
        status = "UNKNOWN"
        header = httplib.HTTPMessage(StringIO.StringIO())

    return (method, status, header)

class MozCacheScan(Scanner.GenScanFactory):
    """ Scan for Mozilla Cache files """
    default = True
    depends = []
    
    class Scan(Scanner.StoreAndScan):
        def boring(self, metadata, data=''):
            s = self.fd.stat()
            if s['name'] == "_CACHE_MAP_":
            	return False
            return True

        def external_process(self, fd):
            #find the other files we need in order to process cache
            s = self.fd.stat()
            filename = "%s%s" % (s['path'], s['name'])
            data_fds = [ 
                self.ddfs.open("%s_CACHE_001_" % s['path']),
                self.ddfs.open("%s_CACHE_002_" % s['path']),
                self.ddfs.open("%s_CACHE_003_" % s['path'])
            ]

            mozcache = MozCache.MozCache(fd, data_fds)
            #print mozcache

            dbh = DB.DBO(self.case)

            # process each cache record
            for record in mozcache.records():
            	meta = record.get_entry()
            	(method, status, header) = parse_response(meta['MetaData'])    

            	# deal with content-encoding (gzip/deflate)
                encoding_driver = ""
                encoding = header.getheader("content-encoding")
                if encoding:
                    if "gzip" in encoding.lower():
                    	encoding_driver = "|G1"
                    elif "deflate" in encoding.lower():
                    	encoding_driver = "|d1"

            	# locate embedded entries 
                if record.record['DataLocation']['DataFile'] != 0:
                    fileidx, offset, length = record.get_data_location()
                    inode = '%s|o%s:%s' % (data_fds[fileidx].inode, offset, length)
                else:
                    inode = self.ddfs.lookup(path="%s%08Xd01" % (s['path'], record.record['HashNumber'].get_value()))[1]

                # add new entry to the VFS
                if encoding: length=0
                inode_id = self.ddfs.VFSCreate(None,
                                    "%s%s" % (inode, encoding_driver),
                                    "%s/%08Xd01" % (filename, record.record['HashNumber'].get_value()),
                                    _mtime=meta['LastModified'],
                                    _atime=meta['LastFetched'],
                                    size=length)
                # add to http table
                # we parse the date, it is automatically returned in case
                # timezone. We do not need to supply an evidence timezone as
                # http date strings contain a timezone specification.
                try:
                    date = Time.parse(header.getheader("date"), case=self.case, evidence_tz=None) 
                except TypeError:
                    date = 0
                # chomp NULL from end
                url = str(meta['KeyData'])[:-1]
                if url.startswith("HTTP:"): url = url[len("HTTP:"):]
                dbh.insert("http", 
                        inode_id=inode_id, 
                        url=url,
                        method=method,
                        status=status,
                        content_type=header.getheader("content-type"),
                        date=date,
                        )

                ## Scan the new file using the scanner train:
                fd=self.ddfs.open(inode_id=inode_id)
                Scanner.scanfile(self.ddfs,fd,self.factories)

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

