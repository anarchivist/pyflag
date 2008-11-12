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
import os.path, cStringIO, re
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import FileFormats.IECache as IECache
import pyflag.DB as DB
from pyflag.ColumnTypes import StringType, TimestampType, FilenameType, InodeIDType, LongStringType, IntegerType
import pyflag.FlagFramework as FlagFramework

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
                    
                    args = dict(inode_id = inode_id,
                                type = event['type'],
                                offset = event['offset'],
                                length = event['size'].get_value() * IECache.blocksize,
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
                        encoding_driver = None
                        
                        m = content_encoding_re.search(headers)
                        if m:
                            ## Is it gzip encoding?
                            if m.group(1) == 'gzip':
                                encoding_driver = "|G1"
                            elif m.group(1) == 'deflate':
                                encoding_driver = '|d1'
                            else:
                                print "I have no idea what %s encoding is" % m.group(1)
                                
                        if encoding_driver:
                            inode_id = self.ddfs.VFSCreate(None,
                                                           "%s%s" % (row['inode'],
                                                                     encoding_driver),
                                                           "%s/%s" % (tmp_path,
                                                                      args['filename']),
                                                           _mtime = modified,
                                                           _atime = accessed
                                                           )

                        http_args = dict(
                            inode_id = inode_id,
                            url = url,
                            )

                        ## Populate http table if possible
                        m = content_type_re.search(headers)
                        if m:
                            http_args['content_type'] = m.group(1)
                            
                        dbh.insert('http', **http_args )

import pyflag.tests
import pyflag.pyflagsh as pyflagsh

class IECacheScanTest(pyflag.tests.ScannerTest):
    """ Test IE History scanner """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.4.dd"
    subsystem = 'Standard'
    offset = "16128s"

    def test01RunScanner(self):
        """ Test IE History scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'IEIndex'])

