# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
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

""" Flag module for performing structured disk forensics """
import pyflag.Reports as Reports
from pyflag.FlagFramework import Curry,query_type
import pyflag.conf
config=pyflag.conf.ConfObject()
import os,os.path,time,re, cStringIO
import pyflag.FileSystem as FileSystem
import pyflag.Graph as Graph
import pyflag.IO as IO
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.ScannerUtils as ScannerUtils
import pyflag.Registry as Registry
import pyflag.parser as parser
from pyflag.TableObj import ColumnType,TimestampType,InodeType,FilenameType

description = "Disk Forensics"
order=30

BLOCKSIZE=20

class DeletedType(ColumnType):
    """ This is a column type which shows deleted inodes graphically
    """
    ## FIXME - make the parser recognise deleted inodes
    def display(self,value, row, result):
        """ Callback for rendering deleted items """
        tmp=result.__class__(result)
        if value=='alloc':
            tmp.icon("yes.png")
        elif value=='deleted':
            tmp.icon("no.png")
        else:
            tmp.icon("question.png")

        return tmp

class BinaryType(ColumnType):
    """ This type defines fields which are either true or false """
    ## FIXME - Make parser understand binary operators.
    def display(self,value, row,result):
        if value:
            return "*"
        else:
            return " "

def make_inode_link(query,result, variable='inode'):
    """ Returns a ui based on result with links to each level of the
    inode"""
    out = result.__class__(result)
    
    tmp =  query[variable].split('|')
    for i in range(len(tmp)):
        new_query = query.clone()
        del new_query[variable]
        new_query[variable]= '|'.join(tmp[:i+1])
        tmp_result = result.__class__(result)
        tmp_result.link(tmp[i],target=new_query)
        out.text(" ")
        out.text(tmp_result)

    return out

class BrowseFS(Reports.report):
    """
    Browsing the FileSystem
    -----------------------

    The Virtual Filesystem is a central concept to PyFlag's
    operation. This report allows users to browse through the
    filesystem in a natural way.

    The report presents two views:

    - A Tree View:

       Allows for the perusal of files and directories in a tree hirarchy.

    - A Table View:

       This presents the list of files within the VFS in a tabular
       fasion. It is them possible to search through the list simply
       by introducing filter conditions.


    """
    hidden = False
    order=5
    name = "Browse Filesystem"
    family = "Disk Forensics"
    description = "Display filesystem in a browsable format"
    
    def display(self,query,result):
        result.heading("Browsing Filesystem")
        dbh = self.DBO(query['case'])
        main_result=result
        
        branch = ['']
        new_query = result.make_link(query, '')

        def tabular_view(query,result):
            result.table(
                elements = [ InodeType('Inode','f.inode',case=query['case']),
                             ColumnType('Mode','f.mode'),
                             FilenameType(case=query['case']),
                             DeletedType('Del','f.status'),
                             ColumnType('File Size','size'),
                             TimestampType('Last Modified','mtime'),
                             TimestampType('Last Accessed','atime'),
                             TimestampType('Created','ctime'),
                             ],
                table='file as f, inode as i',
                where="f.inode=i.inode",
                case=query['case'],
                )

        def tree_view(query,result):
            if (query.has_key("open_tree") and query['open_tree'] != '/'):
                br = query['open_tree']
            else:
                br = '/'
                
            if not query.has_key('open_tree'): query['open_tree']='/'
            def tree_cb(path):
                ## We expect a directory here:
                if not path.endswith('/'): path=path+'/'
                
                ## We need a local copy of the filesystem factory so
                ## as not to affect other instances!!!
                fsfd = Registry.FILESYSTEMS.fs['DBFS']( query["case"])

                for i in fsfd.dent_walk(path): 
                    if i['mode']=="d/d" and i['status']=='alloc':
                        yield(([i['name'],i['name'],'branch']))

            def pane_cb(path,tmp):
                query['order']='Filename'

                ## If we are asked to show a file, we will show the
                ## contents of the directory the file is in:
                fsfd = Registry.FILESYSTEMS.fs['DBFS']( query["case"])
                if not fsfd.isdir(path):
                    path=os.path.dirname(path)

                tmp.table(
                    elements = [ InodeType('Inode','f.inode',case=query['case']),
                                 ColumnType('Filename','name'),
                                 DeletedType('Del','f.status'),
                                 ColumnType('File Size','size'),
                                 TimestampType('Last Modified','mtime'),
                                 TimestampType('Mode','f.mode') ],
                    table='file as f, inode as i',
                    where="f.inode=i.inode and path=%r and f.mode!='d/d'" % (path+'/'),
                    case=query['case'],
                    )
        
            result.tree(tree_cb = tree_cb,pane_cb = pane_cb, branch = branch )
            main_result.toolbar(text="Scan this directory",icon="examine.png",
                    link=query_type((),
                      family="Load Data", report="ScanFS",
                      path=query['open_tree'],
                      case=query['case'],
                    ))

        
        result.notebook(
            names=["Tree View","Table View"],
            callbacks=[tree_view,tabular_view],
            )

    def form(self,query,result):
        result.case_selector()

class ViewFile(Reports.report):
    """ Report to browse the filesystem """
    parameters = {'inode':'string'}
    hidden = True
    family = "Disk Forensics"
    name = "View File Contents"
    description = "Display the contents of a file"
    
    def display(self,query,result):
        new_q = result.make_link(query, '')
        if not query.has_key('limit'): query['limit']= 0
        dbh = self.DBO(query['case'])

        fsfd = FileSystem.DBFS( query["case"])
        ## If this is a directory, only show the stats
        try:
            fd = fsfd.open(inode=query['inode'])
            image = Graph.Thumbnailer(fd,300)
        except IOError:
            fd = FileSystem.File(query['case'], None, '')
            image = None

        ## Make a series of links to each level of this inode - this
        ## way we can view parents of this inode.
        tmp = result.__class__(result)
        tmp.text("Viewing file in inode ",make_inode_link(query,result))
        result.heading(tmp)
        
        try:
            result.text("Classified as %s by magic" % image.GetMagic())
        except IOError,e:
            result.text("Unable to classify file, no blocks: %s" % e)
            image = None
        except:
            pass

        result.notebook(
            names=fd.stat_names,
            callbacks=fd.stat_cbs,
            context="mode"
            )

        result.toolbar(text="Scan this File",icon="examine.png",
                   link=query_type((),
                      family="Load Data", report="ScanFS",
                      path=fsfd.lookup(inode=query['inode']),
                      case=query['case'],
                       )
                   )
            
    def form(self,query,result):
        result.defaults = query
        result.case_selector()
        result.textfield('Inode','inode')
        return result

class Timeline(Reports.report):
    """ View file MAC times in a searchable table """
    name = "View File Timeline"
    family = "Disk Forensics"
    description = "Browse file creation, modification, and access times"

    def form(self, query, result):
        result.case_selector()

    def analyse(self, query):
        dbh = self.DBO(query['case'])
        temp_table = dbh.get_temp()
        dbh.check_index("inode","inode")
        dbh.execute("create temporary table %s select i.inode,f.status,mtime as `time`,1 as `m`,0 as `a`,0 as `c`,0 as `d`,concat(path,name) as `name` from inode as i left join file as f on i.inode=f.inode" %
                    (temp_table, ));
        dbh.execute("insert into %s select i.inode,f.status,atime,0,1,0,0,concat(path,name) from inode as i left join file as f on i.inode=f.inode" % (temp_table,))
        dbh.execute("insert into %s select i.inode,f.status,ctime,0,0,1,0,concat(path,name) from inode as i left join file as f on i.inode=f.inode" % (temp_table, ))
        dbh.execute("insert into %s select i.inode,f.status,dtime,0,0,0,1,concat(path,name) from inode as i left join file as f on i.inode=f.inode" % (temp_table, ))
        dbh.execute("""create table if not exists mac(
        `inode` varchar(250) NOT NULL default '',
        `status` varchar(8) default '',
        `time` timestamp NULL,
        `m` int default NULL,
        `a` tinyint default NULL,
        `c` tinyint default NULL,
        `d` tinyint default NULL,
        `name` text
        ) """)
        dbh.execute("insert into mac select inode,status,time,sum(m) as `m`,sum(a) as `a`,sum(c) as `c`,sum(d) as `d`,name from %s where time>0 group by time,name order by time,name" % temp_table)
        dbh.check_index("mac","inode")
        
    def progress(self, query, result):
        result.heading("Building Timeline")
    
    def display(self, query, result):
        dbh = self.DBO(query['case'])
        result.heading("File Timeline for Filesystem")
        result.table(
            elements=[ TimestampType('Timestamp','time'),
                       InodeType('Inode','inode', case=query['case']),
                       DeletedType('Del','status'),
                       BinaryType('m',"m"),
                       BinaryType('a',"a"),
                       BinaryType('c',"c"),
                       BinaryType('d',"d"),
                       ColumnType('Filename','name'),
                       ],
            table='mac',
            case=query['case'],
            )

    def reset(self, query):
        dbh = self.DBO(query['case'])
        dbh.execute("drop table mac")

## Standard file objects:
class DBFS_file(FileSystem.File):
    """ Class for reading files within a loaded dd image, supports typical file-like operations, seek, tell, read """
    
    specifier = 'D'
    def __init__(self, case, fd, inode):
        FileSystem.File.__init__(self, case, fd, inode)

        self.stat_names.extend(["Text"])
        self.stat_cbs.extend([self.textdump])

        ## This is kind of a late initialization. We get the indexes
        ## on demand later.
        self.index=None
        
    def getval(property):
        try:
            return self.data[property]
        except KeyError:
            return None

    def read(self, length=None):
        ## Call our baseclass to see if we have cached data:
        try:
            return FileSystem.File.read(self,length)
        except IOError:
            pass

        dbh=DB.DBO(self.case)
        ## We need to fetch the blocksize if we dont already know it:
        if not self.index:
            # fetch inode data
            dbh.check_index("inode" ,"inode")
            dbh.execute("select * from inode where inode=%r limit 1", (self.inode))
            self.data = dbh.fetch()
            if not self.data:
                raise IOError("Could not locate inode %s"% self.inode)

            self.size = self.data['size']
            dbh.check_index("block" ,"inode")
            dbh.execute("select block,count,`index` from block where inode=%r order by `index`", (self.inode))
            try:
                self.blocks = [ (row['block'],row['count'],row['index']) for row in dbh ]
            except KeyError:
                self.blocks = None
                
            self.index = [ d[2] for d in self.blocks ]

        if (length == None) or ((length + self.readptr) > self.size):
            length = self.size - self.readptr

        if length == 0:
            return ''

        if not self.blocks:
            # now try to find blocks in the resident table
            dbh.check_index("resident","inode")
            dbh.execute("select data from resident where inode=%r limit 1" % (self.data['inode']));
            row = dbh.fetch()
            if not row:
                raise IOError("Cant find any file data")
            data = row['data'][self.readptr:length+self.readptr]
	    self.readptr += length
	    return data

        fbuf=''
        while length>0:
        ## Where are we in the chunk?
            ddoffset,bytes_left = self.offset(self.readptr)
            
            self.fd.seek(ddoffset)
            if(bytes_left > length):
                fbuf += self.fd.read(length)
                self.readptr+=length
                return fbuf
            else:
                fbuf += self.fd.read(bytes_left)
                length-=bytes_left
                self.readptr+=bytes_left

        return fbuf

    def offset(self,offset):
        """ returns the offset into the current block group where the given offset is found"""
        ## The block in the file where the offset is found
        block = int(offset/self.fd.block_size)

        ##Obtain the index of blocks array where the chunk is. This is the index at which self.index is 
        blocks_index=0
        try:
            while 1:
                if self.index[blocks_index]<=block<self.index[blocks_index+1]: break
                blocks_index+=1

        except IndexError:
            blocks_index=len(self.index)-1

        #If the end of the chunk found occurs before the block we seek, there is something wrong!!!
        if self.blocks[blocks_index][1]+self.blocks[blocks_index][2]<=block:
            raise IOError("Block table does not span seek block %s"%block,offset)

        ## Look the chunk up in the blocks array
        ddblock,count,index=self.blocks[blocks_index]

        ## The offset into the chunk in bytes
        chunk_offset = offset-index*self.fd.block_size

        ## The dd offset in bytes
        ddoffset=ddblock*self.fd.block_size+chunk_offset

        ## The number of bytes remaining in this chunk
        bytes_left = count*self.fd.block_size-chunk_offset
        
        return ddoffset,bytes_left

    def textdump(self, query,result):
        """ Dumps the file in a text window """
        max=config.MAX_DATA_DUMP_SIZE
        def textdumper(offset,data,result):
            result.text(data,sanitise='full',font='typewriter',
                        color="red",wrap="full")

        return self.display_data(query,result,max, textdumper)

class MountedFS_file(FileSystem.File):
    """ access to real file in filesystem """
    specifier = 'M'
    def __init__(self, case, fd, inode):
        FileSystem.File.__init__(self, case, fd, inode)
        #strategy:
        #must determine path from inode
        #we can assume this vfs will never be inside another vfs...
        #just look it up in the database i spose "where inode=inode" ??
        self.case = case
        dbh = DB.DBO(case)
        dbh.check_index("file" ,"inode")
        dbh.execute("select path,name from file where inode=%r limit 1",(inode))
        row=dbh.fetch()
        path=row['path']+"/"+row['name']
        self.fd=open(fd.mount_point+'/'+path,'r')
    
    def close(self):
        self.fd.close()

    def seek(self, offset, rel=None):
        if rel!=None:
            self.fd.seek(offset,rel)
        else:
            self.fd.seek(offset)

    def read(self, length=None):
        if length!=None:
            return self.fd.read(length)
        else:
            return self.fd.read()

    def tell(self):
        return self.fd.tell()

## Unallocated space VFS Driver:
class Unallocated_File(FileSystem.File):
    """ A VFS driver for reading unallocated space off the disk.

    This driver reads the offset from the unallocated table which was previously prepared by the unallocated scanner.
    """
    specifier = 'U'
    
    def __init__(self, case, fd, inode):
        FileSystem.File.__init__(self, case, fd, inode)
        self.fd=fd
        self.case = case
        dbh = DB.DBO(case)
        dbh.execute("select * from unallocated where inode=%r limit 1",(inode))
        row=dbh.fetch()
        try:
            self.size=row['size']
            self.offset=row['offset']
        except KeyError:
            raise IOError

    def read(self,length=None):
        if self.size>0:
            if (length == None) or ((length + self.readptr) > self.size):
                length = self.size - self.readptr

            if length == 0:
                return ''
        else:
            if length==None:
                raise IOError("Unable to read entire IO source into memory")

        self.fd.seek(self.readptr+self.offset)
        result =self.fd.read(length)
        self.readptr+=len(result)
        return result
