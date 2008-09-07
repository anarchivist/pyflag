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
""" This scanner scans a file for its mime type and magic """
import pyflag.FlagFramework as FlagFramework
import pyflag.CacheManager as CacheManager
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import PIL, cStringIO
import os.path
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.Graph as Graph
import pyflag.IO as IO
import pyflag.Registry as Registry
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, FilenameType, IntegerType, InodeType
import fnmatch
import pyflag.Magic as Magic

class TypeScan(Scanner.GenScanFactory):
    """ Detect File Type (magic). """
    order=5
    default=True
    group = "FileScanners"

    def multiple_inode_reset(self,inode):
        Scanner.GenScanFactory.multiple_inode_reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from `type` where inode_id in (select inode_id from inode where inode.inode = %r )", inode)

    def reset(self,inode):
        Scanner.GenScanFactory.reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute("delete from `type` where inode_id = (select inode_id from inode where inode.inode = %r limit 1)" , inode)

    def reset_entire_path(self, path_glob):
        path = path_glob
        if not path.endswith("*"): path = path + "*"  
        db = DB.DBO(self.case)
        db.execute("delete from type where inode_id in (select inode_id from file where file.path rlike %r)", fnmatch.translate(path))
        Scanner.GenScanFactory.reset_entire_path(self, path_glob)
        
    def destroy(self):
        pass

    class Scan(Scanner.BaseScanner):
        type_str = None
        
        def process(self, data, metadata=None):
            if self.type_str==None:
                m = Magic.MagicResolver()
                self.type_str, self.type_mime = m.cache_type(self.case, self.fd.inode_id, data[:1024])
                metadata['mime'] = self.type_mime
                metadata['type'] = self.type_str
                
class ThumbnailType(InodeIDType):
    """ A Column showing thumbnails of inodes """
    def __init__(self, name='Thumbnail', **args ):
        InodeIDType.__init__(self, **args)
        self.fsfd = FileSystem.DBFS(self.case)
        self.name = name
        
    def select(self):
        return "%s.inode_id" % self.table

    ## When exporting to html we need to export the thumbnail too:
    def render_html(self, inode_id, table_renderer):
        try:
            fd = self.fsfd.open(inode_id = inode_id)
            image = Graph.Thumbnailer(fd, 200)

            filename, ct, fd = table_renderer.make_archive_filename(inode_id, directory = "thumbnails/")
            inode_filename, ct, fd = table_renderer.make_archive_filename(inode_id)
        
            table_renderer.add_file_from_string(filename,
                                                image.display())
        except IOError:
            return "<a href=%r ><img src='images/broken.png' /></a>" % inode_filename

        return "<a href=%r ><img src=%r /></a>" % (inode_filename, filename)

    def render_thumbnail_hook(self, inode_id, row, result):
        try:
            fd = self.fsfd.open(inode_id=inode_id)
            image = PIL.Image.open(fd)
        except IOError:
            result.icon("broken.png")
            return

        width, height = image.size

        ## Calculate the new width and height:
        new_width = 200
        new_height = int(float(new_width) / width * height)

        if new_width > width and new_height > height:
            new_height = height
            new_width = width

        def show_image(query, result):
            ## Try to fetch the cached copy:
            filename = "thumb_%s" % inode_id

            try:
                fd = CacheManager.MANAGER.open(self.case, filename)
                thumbnail = fd.read()
            except IOError:
                fd = self.fsfd.open(inode_id=inode_id)
                fd = cStringIO.StringIO(fd.read(2000000) + "\xff\xd9")
                image = PIL.Image.open(fd)
                image = image.convert('RGB')
                thumbnail = cStringIO.StringIO()

                try:
                    image.thumbnail((new_width, new_height), PIL.Image.NEAREST)
                    image.save(thumbnail, 'jpeg')
                    thumbnail = thumbnail.getvalue()
                except IOError,e:
                    print "PIL Error: %s" % e
                    thumbnail = open("%s/no.png" % (config.IMAGEDIR,),'rb').read()

                CacheManager.MANAGER.create_cache_from_data(self.case, filename, thumbnail)
                fd = CacheManager.MANAGER.open(self.case, filename)
                
            result.result = thumbnail
            result.content_type = 'image/jpeg'
            result.decoration = 'raw'

        
        result.result += "<img width=%s height=%s src='f?callback_stored=%s' />" % (new_width, new_height,
                                                                result.store_callback(show_image))

    display_hooks = InodeIDType.display_hooks[:] + [render_thumbnail_hook,]

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
        try:
            result.table(
                elements = [ ThumbnailType(name='Thumbnail',case=query['case']),
                             FilenameType(case=query['case']),
                             StringType('Type','type'),
                             IntegerType('Size','size', table='inode'),
                             TimestampType(name='Timestamp',column='mtime', table='inode')
                             ],
                table = 'type',
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
                elements = [ InodeIDType(case = self.case),
                             FilenameType(case = self.case, link_pane='main'),
                             IntegerType('Size','size', table='inode'),
                             TimestampType('Timestamp','mtime', table='inode'),
                             StringType('Type', 'type', table='type'),
                             ],
                table = 'type',
                where = DB.expand('type.mime=%r ', t),
                case = self.case,
                )

class TypeStats(Stats.Handler):
    name = "File Types"

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
                elements = [ InodeIDType(case = self.case),
                             FilenameType(case = self.case, link_pane='main'),
                             IntegerType('Size','size', table='inode'),
                             TimestampType('Timestamp','mtime', table='inode'),
                             StringType('Mime', 'mime', table='type')],
                table = 'type',
                where = DB.expand('type.type=%r ', t),
                case = self.case,
                )
                
## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class TypeTest(pyflag.tests.ScannerTest):
    """ Magic related Scanner """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.5.e01"
    subsystem = 'EWF'
    offset = "16128s"

    def test01TypeScan(self):
        """ Check the type scanner works """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'TypeScan'])

        ## Make sure the extra magic is being used properly.
        dbh = DB.DBO(self.test_case)
        dbh.execute('select count(*) as count from type where type like "%%Outlook%%"')
        count = dbh.fetch()['count']
        self.failIf(count==0, "Unable to locate an Outlook PST file - maybe we are not using our custom magic file?")

## Add some operators to the InodeType:
def operator_has_magic(self, column, operator, magic):
    """ Matches those inodes which match certain magic strings. Note that the TypeScanner must have been run on these inodes first """
    return "( %s in (select inode_id from type where type like '%%%s%%'))" % \
           (self.escape_column_name(self.column), magic)

InodeIDType.operator_has_magic = operator_has_magic

class TypeCaseTable(FlagFramework.CaseTable):
    """ Type Table """
    name = 'type'
    columns = [ [ InodeIDType, dict() ],
                [ StringType, dict(name = 'Mime', column = 'mime')],
                [ StringType, dict(name = 'Type', column = 'type')],
                ]
    index = [ 'type', ]
    primary = 'inode_id'
    extras = [ [ ThumbnailType, dict() ]]
