# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
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
from pyflag.TableObj import StringType, TimestampType, InodeIDType, FilenameType, IntegerType

class TypeTables(FlagFramework.EventHandler):
    def create(self, dbh, case):
        dbh.execute(""" CREATE TABLE IF NOT EXISTS `type` (
        `inode_id` int NOT NULL,
        `mime` tinytext NOT NULL,
        `type` tinytext NOT NULL )""")
        
        ## Create indexes on this table immediately because we need to select
        dbh.check_index('type','inode_id')
        
class TypeScan(Scanner.GenScanFactory):
    """ Detect File Type (magic).

    In addition to recording the file type, this class can also perform
    an action based on the mime type of the file"""
    order=5
    default=True

    def multiple_inode_reset(self,inode):
        Scanner.GenScanFactory.multiple_inode_reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from `type`")

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
            inode_id = self.fd.lookup_id()
            dbh.insert('type',
                       inode_id = inode_id,
                       mime = self.type_mime,
                       type = self.type_str)

class ThumbnailType(InodeIDType):
    def __init__(self, name='Inode', column='inode', fsfd=None):
        InodeIDType.__init__(self,name=name,column=column, case=fsfd.case)
        self.fsfd = fsfd

    ## We dont want any operations on the thumbnail
    def operators(self):
        return {}
        
    def display(self, inode_id, row, result):
        tmp = result.__class__(result)
        try:
            fd = self.fsfd.open(inode_id=inode_id)
            inode = self.fsfd.lookup(inode_id=inode_id)
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
                   FlagFramework.query_type((), case=self.case,
                   inode=inode,
                   family = "Disk Forensics", report = "ViewFile"),
                   mode = "Summary",
                   tooltip=inode, border=0
                   )

        try:
            tmp2.text("\n%sx%s\n" % (image.owidth,image.oheight))
        except AttributeError:
            pass

        tmp2.raw(InodeIDType.display(self,inode_id,row, tmp2))
        return tmp2

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
        fsfd = FileSystem.DBFS(query["case"])
        try:
            result.table(
                elements = [ ThumbnailType('Thumbnail','type.inode_id', fsfd = fsfd),
                             FilenameType(case=query['case'], table='type'),
                             StringType('Type','type'),
                             IntegerType('Size','inode.size'),
                             TimestampType('Timestamp','inode.mtime')
                             ],
                table = 'type join inode on inode.inode_id = type.inode_id',
                case = query['case']
                )
        except DB.DBError,e:
            result.para("Error reading the type table. Did you remember to run the TypeScan scanner?")
            result.para("Error reported was:")
            result.text(e,style="red")

## Show some stats:
import pyflag.Stats as Stats
class MimeTypeStats(Stats.Handler):
    name = "Mime Types"

    def render_tree(self, branch, query):
        dbh = DB.DBO(self.case)
        ## Top level view - we only show the File Types stats branch
        ## if we have any types there.
        if not branch[0]:
            dbh.execute("select count(*) as a from type")
            row = dbh.fetch()
            if row['a']>0:
                yield (self.name, self.name, 'branch')
        elif branch[0] != self.name:
            return
        elif len(branch)==1:
            dbh.execute("select `type`.`mime`  from `type` group by `mime`")
            for row in dbh:
                t = row['mime'][:20]
                yield (row['mime'].replace("/","__"), t, 'leaf')

    def render_pane(self, branch, query, result):
        ## We may only draw on the pane that belongs to us:
        if branch[0] != self.name:
            return

        if len(branch)==1:
            result.heading("Show file types")
            result.text("This statistic allows different file types to be examined")
        else:
            t = branch[1].replace("__",'/')
            result.table(
                elements = [ InodeType(column='file.inode', case = self.case),
                             FilenameType(case = self.case, link_pane='main'),
                             IntegerType('Size','inode.size'),
                             TimestampType('Timestamp','inode.mtime')],
                table = 'file, type, inode',
                where = 'type.inode=inode.inode and file.inode_id=inode.inode_id and file.mode like "r%%%%" and type.mime=%r ' % t,
                case = self.case,
                )

class TypeStats(Stats.Handler):
    name = "File Types"

    def render_tree(self, branch, query):
        dbh = DB.DBO(self.case)

        print branch
        ## Top level view - we only show the File Types stats branch
        ## if we have any types there.
        if not branch[0]:
            dbh.execute("select count(*) as a from type")
            row = dbh.fetch()
            if row['a']>0:
                yield (self.name, self.name, 'branch')
        elif branch[0] != self.name:
            return
        elif len(branch)==1:
            dbh.execute("select `type`.`type`  from `type` group by `type`")
            for row in dbh:
                t = row['type'][:20]
                yield (row['type'].replace("/","__"), t, 'leaf')

    def render_pane(self, branch, query, result):
        ## We may only draw on the pane that belongs to us:
        if branch[0] != self.name:
            return

        if len(branch)==1:
            result.heading("Show file types")
            result.text("This statistic allows different file types to be examined")
        else:
            t = branch[1].replace("__",'/')
            result.table(
                elements = [ InodeType(column='file.inode', case = self.case),
                             FilenameType(case = self.case, link_pane='main'),
                             IntegerType('Size','inode.size'),
                             TimestampType('Timestamp','inode.mtime')],
                table = 'file, type, inode',
                where = 'type.inode=inode.inode and file.inode_id=inode.inode_id and file.mode like "r%%%%" and type.type=%r ' % t,
                case = self.case,
                )
                
## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class TypeTest(pyflag.tests.ScannerTest):
    """ Magic related Scanner """
    test_case = "PyFlag Test Case"
    test_file = "pyflag_stdimage_0.4.dd"
    subsystem = 'Advanced'
    offset = "16128s"

    def test01TypeScan(self):
        """ Check the type scanner works """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'TypeScan'])

        ## Make sure the extra magic is being used properly.
        dbh = DB.DBO(self.test_case)
        dbh.execute('select count(*) as count from type where type like "%Outlook%"')
        count = dbh.fetch()['count']
        self.failIf(count==0, "Unable to locate an Outlook PST file - maybe we are not using our custom magic file?")
