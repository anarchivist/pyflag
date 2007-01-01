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
""" This scanner scans a file for its mime type and magic """
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import os.path
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.Graph as Graph
import pyflag.IO as IO
import pyflag.Registry as Registry
from pyflag.TableObj import ColumnType, TimestampType, InodeType, FilenameType

class TypeScan(Scanner.GenScanFactory):
    """ Detect File Type (magic).

    In addition to recording the file type, this class can also perform
    an action based on the mime type of the file"""
    order=5
    default=True
    def __init__(self,fsfd):
        Scanner.GenScanFactory.__init__(self, fsfd)
        dbh=DB.DBO(self.case)
        dbh.execute(""" CREATE TABLE IF NOT EXISTS `type` (
        `inode` varchar( 250 ) NOT NULL,
        `mime` tinytext NOT NULL,
        `type` tinytext NOT NULL )""")

        ## Create indexes on this table immediately because we need to select
        dbh.check_index('type','inode')

    def reset(self,inode):
        Scanner.GenScanFactory.reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from `type`")

    def destroy(self):
        pass

    class Scan(Scanner.BaseScanner):
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            Scanner.BaseScanner.__init__(self, inode,ddfs,outer,factories, fd=fd)
            self.filename=self.ddfs.lookup(inode=inode)
            self.type_mime = None
            self.type_str = None
        
        def process(self, data,metadata=None):
            if self.type_str==None:
                magic = FlagFramework.Magic(mode='mime')
                magic2 = FlagFramework.Magic()
                self.type_mime = magic.buffer(data)
                self.type_str = magic2.buffer(data)
                metadata['mime']=self.type_mime
                metadata['magic']=self.type_str

        def finish(self):
            # insert type into DB
            dbh=DB.DBO(self.case)
            dbh.insert('type',
                       inode = self.inode,
                       mime = self.type_mime,
                       type = self.type_str)

## A report to examine the Types of different files:
class ViewFileTypes(Reports.report):
    """ Browse the file types discovered.

    This shows all the files in the filesystem with their file types as detected by magic. By searching and grouping for certain file types it is possible narrow down only files of interest.

    A thumbnail of the file is also shown for rapid previewing of images etc.
    """
    name = "Browse Types"
    family = "Disk Forensics"
    
    def form(self,query,result):
        result.case_selector()
        
    def display(self,query,result):
        fsfd = Registry.FILESYSTEMS.fs['DBFS']( query["case"])
        
        def thumbnail_cb(inode):
            tmp = result.__class__(result)
            try:
                fd = fsfd.open(inode=inode)
                image = Graph.Thumbnailer(fd,200)
            except IOError:
                tmp.icon("broken.png")
                return
                
            if image.height>0:
                tmp.image(image,width=image.width,height=image.height)
            else:
                tmp.image(image,width=image.width)

            tmp2 = result.__class__(result)
            tmp2.decoration="raw"
            tmp2.link( tmp, target = 
                       FlagFramework.query_type((), case=query['case'],
                       inode=inode,
                       family = "Disk Forensics", report = "ViewFile"),
                       mode = "Summary",
                       tooltip=inode, border=0
                       )

            try:
                tmp2.text("\n%sx%s" % (image.owidth,image.oheight))
            except AttributeError:
                pass

            tmp2.text(" %s" % inode)
            return tmp2

        try:
            result.table(
                elements = [ InodeType('Thumbnail','a.inode', callback = thumbnail_cb,
                                       case=query['case']),
                             FilenameType(case=query['case']),
                             ColumnType('Type','type'),
                             ColumnType('Size','c.size'),
                             TimestampType('Timestamp','c.mtime') ],
                table = 'file as a, type as b, inode as c',
                where = 'b.inode=c.inode and a.inode=b.inode and a.mode like "r%%" ',
                case = query['case']
                )
        except DB.DBError,e:
            result.para("Error reading the type table. Did you remember to run the TypeScan scanner?")
            result.para("Error reported was:")
            result.text(e,color="red")

## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh

class TypeTest(unittest.TestCase):
    test_case = "PyFlagTestCase"
    def test_type_scan(self):
        """ Check the type scanner works """
        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as count from inode")
        count = dbh.fetch()['count']
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'TypeScan'])

        dbh.execute("select count(*) as count from type")
        
        ## Make sure the extra magic is being used properly.
        dbh.execute('select count(*) as count from type where type like "%Outlook%"')
        count = dbh.fetch()['count']
        self.failIf(count==0, "Unable to locate an Outlook PST file - maybe we are not using our custom magic file?")
        
