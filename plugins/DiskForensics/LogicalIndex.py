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
""" This module uses the indexing tools to scan the logical files within an image. This allows us to do keyword matching against compressed files, PST files etc.

This module contains a Scanner to be called by the scanning framework, and a set of reports allowing the management of the dictionary as well as the querying of the index.

Implementation Note:
The indextools engine stores a 64bit offset for the occurance of the indexed word. This number is split along a bit mask into two components: The block number and the offset within the block.

For example assume that the blocksize is 2^20 (=1,048,576). When the scanner is scanning a new file it allocates blocks of this size, and stores these into the database as inode vs blocknumber pairs. The indextools then stores blocknumber << 20 | offset_within_block.

When we need to retrieve this we get a list of offsets from the indextools. The problem them becomes how to map these indexes back into an inode and relative offset. We do this by selecting those rows which have the given blocknumber, finding out their inode and seeking the relative offset into the inode's file.

Example:
Suppose we find the word 'Linux' at the 27th byte of inode 5 (Assuming the first 4 inodes are smaller than the blocksize 2^20), indextools will store this offset as 5 << 20 | 27. We therefore insert into the database a row saying that block 5 belongs to inode 5.

When we retrieve this offset (o), we search through the db for the inode containing block o>>20 (5) and receive inode 5. We then seek o & (2^20-1) = 27 bytes into it.

Note that if a single file is larger than the blocksize, we have multiple entries in the database assigning a number of blocks to the same inode. This is not a problem if it is taken into account when reassembling the information.

"""
import pyflag.logging as logging
import pyflag.FlagFramework as FlagFramework
import pyflag.FileSystem as FileSystem
import pyflag.Reports as Reports
import pyflag.Registry as Registry
import pyflag.IO as IO
from pyflag.Scanner import *
import index,os
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB

## This blocksize is in bits (2^20)
BLOCKSIZE=20

def escape(string):
    return ("%r" % string)[1:-1]

class Index(GenScanFactory):
    """ Keyword Index files """
    ## Indexing must occur after all scanners have run.
    order=200
    default = True
    def __init__(self,dbh,table,fsfd):
        """ This creates the LogicalIndex table and initialised the index file """
        self.dbh=dbh
        ## These keep the current offset in the logical image. FIXME:
        ## When running in a distributed environment this is not
        ## accessible - maybe we need to pass this in the metadata?
        self.rel_offset = 0
        self.dbh.execute("create table if not exists `LogicalIndex_%s` (`inode` VARCHAR( 20 ) NOT NULL ,`block` BIGINT NOT NULL, primary key(block))",(table))
        ## The block number must be the largest that is available in the database.
        self.dbh.execute("select max(block) as `max` from `LogicalIndex_%s`",(table))
        row=self.dbh.fetch()
        try:
            self.block=int(row['max'])+1
        except: self.block=0
        
        self.table=table
        self.filename = "%s/case_%s/LogicalIndex_%s.idx" % (config.RESULTDIR,self.dbh.case,table)

    def prepare(self):
        try:
            ## Is the file already there?
            self.index = index.Load(self.filename)
            print "Loading old index filename %s" % self.filename
        except IOError:
            ## If not we create it
            self.index = index.index(self.filename)
            pydbh = DB.DBO(None)
            pydbh.execute("select word from dictionary")
            for row in pydbh:
                self.index.add(row['word'])
                
    def reset(self):
        """ This deletes the index file and drops the LogicalIndex table """
        GenScanFactory.reset(self)
        ## First destroy the object and then try to remove the index file
        try:
            del self.index
        except AttributeError:
            pass

        self.dbh.execute("drop table if exists `LogicalIndex_%s`",self.table)
        try:
            os.remove(self.filename)
        except OSError:
            pass
        
        self.dbh.execute("drop table if exists `LogicalIndex_%s`",(self.table))
        ## Here we reset all reports that searched this disk
        FlagFramework.reset_all(case=self.dbh.case,report='SearchIndex', family='Disk Forensics')
        self.dbh.execute("drop table if exists `LogicalKeyword_%s`",(self.table))

    def destroy(self):
        ## Destroy our index handle which will close the file and free memory
        del self.index
        
    class Scan(BaseScanner):
        def __init__(self, inode,ddfs,outer,factories=None):
            BaseScanner.__init__(self, inode,ddfs,outer,factories)
            self.index = outer.index
            self.inode=inode
            self.dbh=outer.dbh
            self.outer=outer
            self.outer.rel_offset=0
            self.outer.block+=1
            self.dbh.execute("select max(block) as `max` from `LogicalIndex_%s`",(outer.table))
            row=self.dbh.fetch()
            try:
                self.outer.block=int(row['max'])+1
            except: self.outer.block=0

            self.dbh.execute("insert into `LogicalIndex_%s` set inode=%r,block=%r",(outer.table,inode,self.outer.block))

        def process(self,data,metadata=None):
            self.index.index_buffer(self.outer.block * pow(2, BLOCKSIZE) + self.outer.rel_offset ,data)
            self.outer.rel_offset+=len(data)
            ## If the file is longer than a block, we create a new block, and adjust the relative offset
            if self.outer.rel_offset > pow(2,BLOCKSIZE):
                self.outer.block+=1
                self.outer.rel_offset -= pow(2,BLOCKSIZE)
                self.dbh.execute("insert into `LogicalIndex_%s` set inode=%r,block=%r",(self.outer.table,self.inode,self.outer.block))
                
        def finish(self):
            pass

## These reports allow the management of the Index Dictionary:
class BuildDictionary(Reports.report):
    """ Manipulate dictionary of search terms to index on """
    parameters = {}
    name="Build Dictionary"
    family="Index Tools"
    description = "Builds a dictionary for indexing "

    def form(self,query,result):
        pass

    def analyse(self,query):
        pass

    def display(self,query,result):
        ## The dictionary is site wide and lives in the FlagDB
        dbh=self.DBO(None)

        ## class_override the class variable:
        try:
            if len(query['class_override'])>3:
                del query['class']
                query['class']=query['class_override']
                del query['class_override']
                
        except KeyError:
            pass

        ## Do we need to add a new entry:
        try:
            if len(query['word'])<3:
                raise DB.DBError("Word is too short to index, minimum of 3 letter words")

            if query['action']=='insert':
                if len(query['class'])<3:
                    raise DB.DBError("Class name is too short, minimum of 3 letter words are used as class names")
                dbh.execute("insert into dictionary set word=%r,class=%r",(query['word'],query['class']))
                
            elif query['action']=='delete':
                dbh.execute("delete from dictionary where word=%r",query['word'])
                
        except KeyError:
            pass
        except DB.DBError,e:
            result.text("Error: %s" % e,color='red')
            result.text("",color='black')
            
        result.heading("Building Dictionary")

        ## Draw a form allowing users to add or delete words from the dictionary
        form=self.ui(result)
        form.start_form(query)
        form.start_table()
        form.const_selector("Action:",'action',('delete','insert'),('Delete','Add'))
        form.textfield('Word:','word')        
        form.selector('Classification:','class','select class,class from dictionary group by class order by class',())
        form.textfield('(Or create a new class:)','class_override')
        form.end_table()
        form.end_form('Go')

        table=self.ui(result)
        try:
            table.table(
                columns=['word','class'],
                names=['Word','Class'],
                table='dictionary',
                case=None,
                )
            ## If the table is not there, we may be upgrading from an old version of flag, We just recreate it:
        except DB.DBError:
            dbh.execute("""CREATE TABLE `dictionary` (
            `word` VARCHAR( 50 ) NOT NULL ,
            `class` VARCHAR( 50 ) NOT NULL ,
            `encoding` SET( 'all', 'ascii', 'ucs16' ) DEFAULT 'all' NOT NULL ,
            PRIMARY KEY ( `word` )
            ) """)

            result.para("Just created a new empty dictionary")
            result.refresh(3,query)
            
        result.row(table,form,valign='top')

class SearchIndex(Reports.report):
    """ Search for indexed keywords """
    description = "Search for words that were indexed during filesystem load. Words must be in dictionary to be indexed. "
    name = "Search Indexed Keywords"
    family = "Disk Forensics"
    parameters={'fsimage':'fsimage','keyword':'any'}

    def form(self,query,result):
        try:
            result.case_selector()
            result.meta_selector(case=query['case'],property='fsimage')
            result.textfield("Keyword to search:",'keyword')
        except KeyError:
            return

    def reset(self,query):
        dbh = self.DBO(query['case'])
        table = query['fsimage']
        keyword = query['keyword']
        try:
            dbh.execute("delete from LogicalKeyword_%s where keyword = %r" , (table,query['keyword']))
        except DB.DBError:
            pass

    def progress(self,query,result):
        result.heading("Currently searching for %r in image %r" % (query['keyword'],query['fsimage']))
        dbh = self.DBO(query['case'])
        table = query['fsimage']
        dbh.check_index("LogicalKeyword_%s" % table,"keyword")
        dbh.execute("select count(*) as Count from LogicalKeyword_%s where keyword=%r",(table,query['keyword']))
        row=dbh.fetch()
        result.text("Currently found %s occurances" % row['Count'],color='red')
        
    def analyse(self,query):
        dbh = self.DBO(query['case'])
        dbh2= self.DBO(query['case'])
        keyword = query['keyword']
        table = query['fsimage']
        dbh2.execute("CREATE TABLE if not exists `LogicalKeyword_%s` (`id` INT NOT NULL AUTO_INCREMENT ,`inode` VARCHAR( 20 ) NOT NULL ,`offset` BIGINT NOT NULL ,`text` VARCHAR( 200 ) NOT NULL ,`keyword` VARCHAR(20) NOT NULL ,PRIMARY KEY ( `id` ))",(table))
        iofd = IO.open(query['case'], query['fsimage'])
        fsfd = Registry.FILESYSTEMS.fs['DBFS']( query["case"], query["fsimage"], iofd)

        import index

        idx = index.Load("%s/case_%s/LogicalIndex_%s.idx" % (config.RESULTDIR,query['case'],table))
        for offset in idx.search(keyword):
            ## Find out which inode this offset is in:
            block = offset >> BLOCKSIZE
            dbh.execute("select inode,min(block) as minblock from LogicalIndex_%s where block = %r group by block",(query['fsimage'],block))
            row=dbh.fetch()
            if not row: continue
            ## Here we remove the block number part from the int. If
            ## there are a number of blocks in the database for this
            ## inode, we account for the extra blocks.
            off = offset - ((2*block - row['minblock'])*pow(2, BLOCKSIZE))
            dbh2.execute("insert into LogicalKeyword_%s set inode=%r, offset=%r, keyword=%r",(table,row['inode'],off,keyword))
        
    def display(self,query,result):
        dbh = self.DBO(query['case'])
        keyword = query['keyword']
        if not query.has_key('showall'):
            query['where_Keyword']="=%s" % keyword
            
        result.heading("Previously searched keywords in logical image %s" %
                       (query['fsimage']))

        q=query.clone()
        del q['where_Keyword']
        result.link("Show all previously cached keywords",q,showall='y',icon='examine.png')
        
        table = query['fsimage']
        iofd = IO.open(query['case'], query['fsimage'])
        fsfd = Registry.FILESYSTEMS.fs['DBFS']( query["case"], query["fsimage"], iofd)

        ## This stuff is done on the fly because it is time consuming - The disadvantage is that it cannot be searched on.
        def SampleData(string,result=None):
            inode,offset=string.split(',')
            offset=int(offset)
            left=offset-10
            if left<0: left=0

            dbh.check_index("LogicalKeyword_%s" % table,"inode")
            dbh.execute("select inode,text,offset,keyword from LogicalKeyword_%s where offset = %r and inode=%r ",(table,offset,inode))
            row=dbh.fetch()
            keyword=row['keyword']
            right=offset+len(keyword)+20

            if len(row['text'])<len(keyword):                
                fd = fsfd.open(inode=row['inode'])
                fd.seek(left)
                ## Read some data before and after the keyword
                data = fd.read(right-left)
                dbh.execute("update LogicalKeyword_%s set text=%r where offset=%r and inode=%r",(table,data,offset,row['inode']))
            else:
                data=row['text']

            output = result.__class__(result)
            output.text(escape(data[0:offset-left]),sanitise='full')
            output.text(escape(data[offset-left:offset-left+len(keyword)]),color='red',sanitise='full')
            output.text(escape(data[offset-left+len(keyword):]),color='black',sanitise='full')
            return output

        result.table(
            columns = ['a.inode','name','concat(a.inode,",",offset)','keyword','offset'],
            names=['Inode','Filename','Data','Keyword','Offset'],
            callbacks = { 'Data': SampleData },
            table='LogicalKeyword_%s as a, file_%s as b' % (table,table),
            where='a.inode=b.inode',
            links = [ FlagFramework.query_type((),case=query['case'],family=query['family'],report='ViewFile',fsimage=query['fsimage'],mode='HexDump',__target__='inode') ],
            case=query['case'],
            )
        
