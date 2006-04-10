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
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import os,os.path,time,re, cStringIO
import pyflag.FileSystem as FileSystem
import pyflag.logging as logging
import pyflag.Graph as Graph
import pyflag.IO as IO
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.ScannerUtils as ScannerUtils
import pyflag.Registry as Registry

description = "Disk Forensics"
order=30

BLOCKSIZE=20

def DeletedIcon(value,result):
    """ Callback for rendering deleted items """
    tmp=result.__class__(result)
    if value=='alloc':
        tmp.icon("yes.png")
    elif value=='deleted':
        tmp.icon("no.png")
    else:
        tmp.icon("question.png")

    return tmp

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
    """ Report to browse the filesystem"""
    hidden = False
    order=5
    name = "Browse Filesystem"
    family = "Disk Forensics"
    description = "Display filesystem in a browsable format"
    
    def display(self,query,result):
        result.heading("Browsing Filesystem")
        dbh = self.DBO(query['case'])
        main_result=result
        
        fsfd = FileSystem.DBFS( query["case"])
        
        branch = ['']
        new_query = result.make_link(query, '')

        def tabular_view(query,result):
            result.table(
                columns=['f.inode','f.mode','concat(path,name)','f.status','size','from_unixtime(mtime)','from_unixtime(atime)','from_unixtime(ctime)'],
                names=('Inode','Mode','Filename','Del','File Size','Last Modified','Last Accessed','Created'),
                callbacks={'Del':FlagFramework.Curry(DeletedIcon,result=result)},
                table='file as f, inode as i',
                where="f.inode=i.inode",
                case=query['case'],
                links=[ FlagFramework.query_type((), case=query['case'],family=query['family'],report='ViewFile', __target__='inode', inode="%s"),
                        None,
                        FlagFramework.query_type((),case=query['case'],family=query['family'],report='Browse Filesystem', __target__='open_tree',open_tree="%s") ]
                )

        def tree_view(query,result):
            if (query.has_key("open_tree") and query['open_tree'] != '/'):
                br = query['open_tree']
            else:
                br = '/'
                
            if not query.has_key('open_tree'): query['open_tree']='/'
            def tree_cb(branch):
                path =FlagFramework.normpath('/'.join(branch)+'/')
                ## We need a local copy of the filesystem factory so
                ## as not to affect other instances!!!
                fsfd = Registry.FILESYSTEMS.fs['DBFS']( query["case"])

                for i in fsfd.dent_walk(path): 
                    if i['mode']=="d/d" and i['status']=='alloc':
                        yield(([i['name'],i['name'],'branch']))

            def pane_cb(branch,tmp):
                query['order']='Filename'
                br=FlagFramework.normpath('/'.join(branch)+'/')
                print "br %s %s" % (br,branch)
                tmp.table(
                    columns=['f.inode','name','f.status','size', 'from_unixtime(mtime)','f.mode'],
                    names=('Inode','Filename','Del','File Size','Last Modified','Mode'),
                    table='file as f, inode as i',
                    where="f.inode=i.inode and path=%r and f.mode!='d/d'" % (br),
                    case=query['case'],
                    links=[ FlagFramework.query_type((),case=query['case'],family=query['family'],report='View File Contents', __target__='inode', inode="%s")]
                    )
        
            result.tree(tree_cb = tree_cb,pane_cb = pane_cb, branch = branch )
            main_result.toolbar(text="Scan this directory",icon="examine.png",
                    link=FlagFramework.query_type((),
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

def goto_page_cb(query,result,variable):
    try:
        limit = query[variable]
    except KeyError:
        limit='0'

    try:
        if query['refresh']:
            del query['refresh']

            ## Accept hex representation for limits
            if limit.startswith('0x'):
                del query[variable]
                query[variable]=int(limit,16)
            
            result.refresh(0,query,parent=1)            
    except KeyError:
        pass

    result.decoration = 'naked'
    result.heading("Skip directly to an offset")
    result.para("You may specify the offset in hex by preceeding it with 0x")
    result.start_form(query, refresh="parent")
    result.start_table()
    if limit.startswith('0x'):
        limit=int(limit,16)
    else:
        limit=int(limit)
        
    result.textfield('Offset in bytes (%s)' % hex(limit),variable)
    result.end_table()
    result.end_form()

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
        path = fsfd.lookup(inode=query['inode'])

        try:
            fd = fsfd.open(inode=query['inode'])
            image = Graph.Thumbnailer(fd,300)
        except IOError:
            fd = None
            image = None
            
        #How big is this file?
        i=fsfd.istat(inode=query['inode'])
        
        #Add the filename into the headers:
        if not path: path=query['inode']
        base_path,name=os.path.split(path)
        if image:
            image.headers=[("Content-Disposition","attachment; filename=%s" % name),]
            
        ## Make a series of links to each level of this inode - this
        ## way we can view parents of this inode.
        tmp = result.__class__(result)
        tmp.text("Viewing file in inode ",make_inode_link(query,result))
        result.heading(tmp)

        def download(query,result):
            """ Used for dumping the entire file into the browser """
            if fd:
                result.download(fd)
        def hexdump(query,result):
            """ Show the hexdump for the file."""
            highlight=0
            length=0
            try:
                highlight=int(query['highlight'])
                length=int(query['length'])
            except:
                pass
            
            max=config.MAX_DATA_DUMP_SIZE
                
            def hexdumper(offset,data,result):
                dump = FlagFramework.HexDump(data,result)
                dump.dump(base_offset=offset,limit=max,highlight=highlight-offset,length=length)

            return display_data(query,result,max,hexdumper)
            
        def display_data(query,result,max,cb):
            """ Displays the data.

            The callback takes care of paging the data from fd. The callback cb is used to actually render the data:

            def cb(offset,data,result)

            offset is the offset in the file where we start, data is the data.
            """
            if fd:
                #Set limits for the dump
                try:
                    limit=int(query['hexlimit'])
                except KeyError:
                    limit=0

                fd.seek(limit)
                data = fd.read(max+1)
                
                cb(limit,data,result)
                
                #Do the navbar
                new_query = query.clone()
                previous=limit-max
                if previous<0:
                    if limit>0:
                        previous = 0
                    else:
                        previous=None

                if previous != None:
                    del new_query['hexlimit']
                    new_query['hexlimit']=previous
                    result.toolbar(text="Previous page", icon="stock_left.png",
                                   link = new_query )
                else:
                    result.toolbar(text="Previous page", icon="stock_left_gray.png")

                next=limit+max
                ## If we did not read a full page, we do not display
                ## the next arrow:
                if len(data)>=max:
                    del new_query['hexlimit']
                    new_query['hexlimit']=next
                    result.toolbar(text="Next page", icon="stock_right.png",
                                   link = new_query )
                else:
                    result.toolbar(text="Next page", icon="stock_right_gray.png")
                    
                ## Allow the user to skip to a certain page directly:
                result.toolbar(
                    cb = FlagFramework.Curry(goto_page_cb, variable='hexlimit'),
                    text="Current Offset %s" % limit,
                    icon="stock_next-page.png"
                    )

            else:
                result.text("No Data Available")

            return result

        def strings(query,result):
            """ Draw the strings in a file """
            if not fd: return
            str = pyflag.Strings.StringExtracter(fd)
            try:
                offset=query['stroffset']
                if offset.startswith("!"):
                    ## We search backwards for the correct offset
                    offset=str.find_offset_prior(int(offset[1:]),config.PAGESIZE-1)
            except KeyError:
                offset=0

            q=query.clone()
            del q['mode']
            del q['hexlimit']
            
            output=result
            output.start_table()
            row_number=0
            file_offset=offset
            try:
                for i in str.extract_from_offset(int(offset)):
                    row_number+=1
                    if row_number>config.PAGESIZE: break
                    file_offset=i[0]
                    tmp_link=self.ui(result)
                    tmp_link.link("0x%x (%s)" % (file_offset,file_offset),q,mode="HexDump",hexlimit=file_offset)
          
                    tmp_string=self.ui(result)
                    tmp_string.text(i[1],color="red",sanitise="full",wrap='full')
                    output.row(tmp_link,tmp_string,valign="top")

            except IOError:
                pass
            
            result.nav_query=query.clone()
            result.nav_query['__target__']='stroffset'
            result.next=file_offset
            if row_number<config.PAGESIZE: result.next=None
            result.previous="!%s" % offset
            result.pageno=offset

            return output

        def textdump(query,result):
            """ Dumps the file in a text window """
            max=config.MAX_DATA_DUMP_SIZE
            def textdumper(offset,data,result):
                result.text(data,sanitise='full',font='typewriter',
                            color="red",wrap="full")

            return display_data(query,result,max,textdumper)
        
        def stats(query,result):
            """ Show statistics about the file """
            istat = fsfd.istat(inode=query['inode'])
            left=self.ui(result)
            link = result.__class__(result)
            link.link(path,
                      FlagFramework.query_type((),family="Disk Forensics",
                          report='BrowseFS',
                          open_tree=base_path, case=query['case'])
                      )
            left.row("Filename:",'',link)
            try:
                for k,v in istat.iteritems():
                    left.row('%s:' % k,'',v)
            except AttributeError:
                pass

            ## File specific statistics:
            if fd:
                istat = fd.stats()
                try:
                    for k,v in istat.iteritems():
                        left.row('%s:' % k,'',v)
                except AttributeError:
                    pass
            
            left.end_table()

            if image:
                right=self.ui(result)
                right.image(image,width=200)
                result.start_table(width="100%")
                result.row(left,right,valign='top',align="left")
            else:
                result.start_table(width="100%")
                result.row(left,valign='top',align="left")

        names=["Statistics","HexDump","Download","Text"]
        callbacks=[stats,hexdump,download,textdump]

        try:
            names.extend(fd.stat_names)
            callbacks.extend(fd.stat_cbs)
        except:
            pass

        
        try:
            result.text("Classified as %s by magic" % image.GetMagic())
        except IOError,e:
            result.text("Unable to classify file, no blocks: %s" % e)
            image = None
        except:
            pass

        result.notebook(
            names=names,
            callbacks=callbacks,
            context="mode"
            )

        result.toolbar(text="Scan this File",icon="examine.png",
                   link=FlagFramework.query_type((),
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
        dbh.execute("create table if not exists mac select inode,status,time,sum(m) as `m`,sum(a) as `a`,sum(c) as `c`,sum(d) as `d`,name from %s where time>0 group by time,name order by time,name" %
                    temp_table)
        dbh.check_index("mac","inode")
        
    def progress(self, query, result):
        result.heading("Building Timeline")
    
    def display(self, query, result):
        dbh = self.DBO(query['case'])
        result.heading("File Timeline for Filesystem")
        result.table(
            columns=('from_unixtime(time)','inode','status',
                     "if(m,'m',' ')","if(a,'a',' ')","if(c,'c',' ')","if(d,'d',' ')",'name'),
            names=('Timestamp', 'Inode','Del','m','a','c','d','Filename'),
            callbacks={'Del':FlagFramework.Curry(DeletedIcon,result=result)},
            table=('mac'),
            case=query['case'],
#            links=[ None, None, None, None, None, None, None, FlagFramework.query_type((),case=query['case'],family=query['family'],fsimage=query['fsimage'],report='ViewFile',__target__='filename')]
            links=[ None, FlagFramework.query_type((),case=query['case'],family=query['family'],report='ViewFile',__target__='inode')]
            )

    def reset(self, query):
        dbh = self.DBO(query['case'])
        dbh.execute("drop table mac")
                
## Standard file objects:
class DBFS_file(FileSystem.File):
    """ Class for reading files within a loaded dd image, supports typical file-like operations, seek, tell, read """
    specifier = 'D'
    def __init__(self, case, fd, inode, dbh=None):
        FileSystem.File.__init__(self, case, fd, inode, dbh)

        ## This is kind of a late initialization. We get the blocksize
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
        
        ## We need to fetch the blocksize if we dont already know it:
        if not self.index:
            # fetch inode data
            self.dbh.check_index("inode" ,"inode")
            self.dbh.execute("select * from inode where inode=%r and status='alloc'", (self.inode))
            self.data = self.dbh.fetch()
            if not self.data:
                raise IOError("Could not locate inode %s"% self.inode)

            self.size = self.data['size']
            self.dbh.check_index("block" ,"inode")
            self.dbh.execute("select block,count,`index` from block where inode=%r order by `index`", (self.inode))
            try:
                self.blocks = [ (row['block'],row['count'],row['index']) for row in self.dbh ]
            except KeyError:
                self.blocks = None
                
            self.index = [ d[2] for d in self.blocks ]

        if (length == None) or ((length + self.readptr) > self.size):
            length = self.size - self.readptr

        if length == 0:
            return ''

        if not self.blocks:
            # now try to find blocks in the resident table
            self.dbh.check_index("resident","inode")
            self.dbh.execute("select data from resident where inode=%r" % (self.data['inode']));
            row = self.dbh.fetch()
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

class MountedFS_file(FileSystem.File):
    """ access to real file in filesystem """
    specifier = 'M'
    def __init__(self, case, fd, inode, dbh=None):
        FileSystem.File.__init__(self, case, fd, inode, dbh)
        #strategy:
        #must determine path from inode
        #we can assume this vfs will never be inside another vfs...
        #just look it up in the database i spose "where inode=inode" ??

        dbh = DB.DBO(case)
        self.dbh=dbh
        self.dbh.check_index("file" ,"inode")
        dbh.execute("select path,name from file where inode=%r",(inode))
        row=self.dbh.fetch()
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
    
    def __init__(self, case, fd, inode, dbh=None):
        FileSystem.File.__init__(self, case, fd, inode, dbh)
        self.fd=fd
        self.dbh = DB.DBO(case)
        self.dbh.execute("select * from unallocated where inode=%r",(inode))
        row=self.dbh.fetch()
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
