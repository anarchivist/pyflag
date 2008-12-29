# Michael Cohen <scudette@users.sourceforge.net>
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
""" This Module will automatically load in IE History files (index.dat) files.

We use the files's magic to trigger the scanner off - so its imperative that the TypeScan scanner also be run or this will not work. We also provide a report to view the history files.
"""
import os.path, cStringIO, re, cgi
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import FileFormats.IECache as IECache
import pyflag.DB as DB
from pyflag.ColumnTypes import StringType, TimestampType, FilenameType, InodeIDType, LongStringType, IntegerType
import pyflag.FlagFramework as FlagFramework
from FileFormats.HTML import url_unquote

content_type_re = re.compile(r"Content-Type:\s+([^\s]+)")
content_encoding_re = re.compile(r"Content-Encoding:\s+([^\s]+)")

class IECaseTable(FlagFramework.CaseTable):
    """ IE History Table - Stores all Internet Explorer History """
    name = 'ie_history'
    columns = [
        [ InodeIDType, {} ],
        [ IntegerType, dict(name='Offset', column='offset')],
        [ IntegerType, dict(name="Length", column='length')],
        [ StringType, dict(name='Type', column='type', width=20) ],
        [ StringType, dict(name='URL', column='url', width=1000) ],
        [ TimestampType, dict(name='Modified', column='modified') ],
        [ TimestampType, dict(name='Accessed', column='accessed') ],
        [ StringType, dict(name='Filename', column='filename', width=500) ],
        [ LongStringType, dict(name='Headers', column='headers') ],
        ]

    index = ['url','inode_id']
    
class IEIndex(Scanner.GenScanFactory):
    """ Load in IE History files """
    default = True
    depends = ['TypeScan']
    group = "FileScanners"

    ## FIXME: Implement multiple_inode_reset
    def reset(self, inode):
        Scanner.GenScanFactory.reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from ie_history")

    class Scan(Scanner.StoreAndScanType):
        types = ['application/x-ie-index']

        def external_process(self,fd):
            dbh=DB.DBO(self.case)
            dbh._warnings = False
            dbh.mass_insert_start('ie_history')
            inode_id = self.fd.lookup_id()
            
            ## Find our path
            dbh.execute("select path from file where inode_id = %r", inode_id)
            row = dbh.fetch()
            path = row['path']
            
            history = IECache.IEHistoryFile(fd)
            for event in history:
                if event:
                    url = event['url'].get_value()
                    url.inclusive = False
                    url = url.get_value()

                    ## How big is the entry
                    size = event['size'].get_value() * IECache.blocksize
                    
                    args = dict(inode_id = inode_id,
                                type = event['type'],
                                offset = event['offset'],
                                length = size,
                                url = url,
                                filename = event['filename'],
                                headers = event['data'].get_value(),)

                    modified = event['modified_time'].get_value()
                    if modified>1000:
                        args['_modified'] = 'from_unixtime(%d)' % modified
                    else: modified = None
                    
                    accessed = event['accessed_time'].get_value()
                    if accessed>1000:
                        args['_accessed'] = 'from_unixtime(%d)' % accessed
                    else: accessed = None
                    
                    dbh.mass_insert(**args)

                    ## Try to locate the actual inode
                    try:
                        index = event['directory_index'].get_value()
                        tmp_path = FlagFramework.normpath((FlagFramework.joinpath([
                            path, history.directories[index]])))
                    except:
                        continue
                    
                    dbh.execute("select inode, inode_id from file where path='%s/' and name=%r",
                                tmp_path,
                                args['filename'])
                    row = dbh.fetch()
                    if row:
                        inode_id = row['inode_id']
                        headers = args['headers']
                        ## We always create a new inode for cache
                        ## entries to guarantee they get scanned by
                        ## other scanners _after_ http info is
                        ## populated. This essentially means we get
                        ## duplicated inodes for the same actual files
                        ## which is a bit of extra overhead (cache
                        ## files are processed twice).
                        encoding_driver = "|o0"
                        
                        m = content_encoding_re.search(headers)
                        if m:
                            ## Is it gzip encoding?
                            if m.group(1) == 'gzip':
                                encoding_driver = "|G1"
                            elif m.group(1) == 'deflate':
                                encoding_driver = '|d1'
                            else:
                                print "I have no idea what %s encoding is" % m.group(1)

                        inode_id = self.ddfs.VFSCreate(None,
                                                       "%s%s" % (row['inode'],
                                                                 encoding_driver),
                                                       "%s/%s" % (tmp_path,
                                                                  args['filename']),
                                                       size = size,
                                                       _mtime = modified,
                                                       _atime = accessed
                                                       )

                        http_args = dict(
                            inode_id = inode_id,
                            url = url_unquote(url),
                            )

                        ## Put in a dodgy pcap entry for the timestamp:
                        if '_accessed' in args:
                            dbh.insert('pcap', _fast=True,
                                       _ts_sec = args['_accessed'],
                                       ts_usec = 0,
                                       offset=0, length=0)
                            packet_id = dbh.autoincrement()
                            http_args['response_packet'] = packet_id
                            http_args['request_packet'] = packet_id

                        ## Populate http table if possible
                        m = content_type_re.search(headers)
                        if m:
                            http_args['content_type'] = m.group(1)

                        host = FlagFramework.find_hostname(url)
                        if host:
                            http_args['host'] = host
                            http_args['tld'] = FlagFramework.make_tld(host)

                        dbh.insert('http', _fast=True, **http_args )

                        ## Now populate the http parameters from the
                        ## URL GET parameters:
                        try:
                            base, query = url.split("?",1)
                            qs = cgi.parse_qs(query)
                            for k,values in qs.items():
                                for v in values:
                                    dbh.insert('http_parameters', _fast=True,
                                               inode_id = inode_id,
                                               key = k,
                                               value = v)
                        except ValueError:
                            pass

                        ## Scan new files using the scanner train:
                        fd=self.ddfs.open(inode_id=inode_id)
                        Scanner.scanfile(self.ddfs,fd,self.factories)

import pyflag.tests
import pyflag.pyflagsh as pyflagsh

class IECacheScanTest(pyflag.tests.ScannerTest):
    """ Test IE History scanner """
    test_case = "PyFlagTestCase"
    test_file = "ie_cache_test.zip"
    subsystem = 'Standard'
    fstype = 'Raw'

    def test01RunScanner(self):
        """ Test IE History scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'ZipScan'])

        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'IEIndex','GoogleImageScanner'])

        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as c from http_parameters where `key`='q' and value='anna netrebko'")
        row=dbh.fetch()
        self.assertEqual(row['c'], 3, 'Unable to find all search URLs')
