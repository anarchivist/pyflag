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
#  Version: FLAG $Name:  $ $Date: 2004/10/26 01:07:53 $
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
import os,os.path,time,re
import pyflag.Sleuthkit as Sleuthkit
import pyflag.FileSystem as FileSystem
import pyflag.Graph as Graph
import pyflag.IO as IO
import pyflag.DB as DB
import pyflag.Scanner as Scanner

description = "Disk Forensics"
order=30

def DeletedIcon(value,result=None):
    """ Callback for rendering deleted items """
    tmp=result.__class__(result)
    if value=='alloc':
        tmp.icon("yes.png")
    elif value=='deleted':
        tmp.icon("no.png")
    else:
        tmp.icon("question.png")

    return tmp

class BrowseFS(Reports.report):
    """ Report to browse the filesystem"""
    parameters = {'fsimage':'fsimage'}
    hidden = False
    name = "Browse Filesystem"
    description = "Display filesystem in a browsable format"
    
    def display(self,query,result):
        result.heading("Browsing Filesystem in image %s" % query['fsimage'])

        # lookup the iosource for this fsimage
        iofd = IO.open(query['case'], query['fsimage'])
        fsfd = FileSystem.FS_Factory( query["case"], query["fsimage"], iofd)
        
        branch = ['']
        new_query = result.make_link(query, '')
            
        try:
            # tabular view
            if query['mode'] == 'table':
                result.table(
                    columns=['f.inode','f.mode','concat(path,name)','f.status','size','from_unixtime(mtime)','from_unixtime(atime)','from_unixtime(ctime)'],
                    names=('Inode','Mode','Filename','Del','File Size','Last Modified','Last Accessed','Created'),
                    callbacks={'Del':DeletedIcon},
                    table='file_%s as f, inode_%s as i' % (fsfd.table,fsfd.table),
                    where="f.inode=i.inode",
                    case=query['case'],
                    links=[ FlagFramework.query_type((), case=query['case'],family=query['family'],report='ViewFile', fsimage=query['fsimage'],__target__='inode', inode="%s"),None, FlagFramework.query_type((),case=query['case'],family=query['family'],report='BrowseFS', fsimage=query['fsimage'],__target__='open_tree',open_tree="%s") ]
                    )
        except KeyError:
            # default to tree view
            if (query.has_key("open_tree") and query['open_tree'] != '/'):
                br = query['open_tree']
            else:
                br = '/'
                
            result.para("Inspecting branch %s\r\n" % br)

            def tree_cb(branch):
                path ='/'.join(branch)+'/'
                ## We need a local copy of the filesystem factory so as not to affect other instances!!!
                fsfd = FileSystem.FS_Factory( query["case"], query["fsimage"], iofd)

                for i in fsfd.dent_walk(path): 
                    if i['mode']=="d/d" and i['status']=='alloc':
                        link = self.ui(result)
                        link.link(i['name'],new_query,open_tree="%s%s" %(path,i['name']), mode='table', where_Filename="%s%s" %(path,i['name']), order='Filename')# ,__mark__="%s%s" %(path,i['name']))
                        yield(([i['name'],link,'branch']))

            def pane_cb(branch,tmp):
                query['order']='Filename'
                br=os.path.normpath('/'.join(branch))+'/'
                if br=='//': br='/'
                tmp.table(
                    columns=['f.inode','name','f.status','size', 'from_unixtime(mtime)','f.mode'],
                    names=('Inode','Filename','Del','File Size','Last Modified','Mode'),
#                    callbacks={'Del':DeletedIcon},
                    table='file_%s as f, inode_%s as i' % (fsfd.table,fsfd.table),
                    where="f.inode=i.inode and path=%r and f.mode!='d/d'" % (br),
                    case=query['case'],
                    links=[ FlagFramework.query_type((),case=query['case'],family=query['family'],report='ViewFile', fsimage=query['fsimage'],__target__='inode', inode="%s")]
                    )
        
            result.tree(tree_cb = tree_cb,pane_cb = pane_cb, branch = branch )
            return result

    def form(self,query,result):
        try:
            result.case_selector()
            if query['case']!=config.FLAGDB:
               result.meta_selector(case=query['case'],property='fsimage')
        except KeyError:
            return result

class ViewFile(Reports.report):
    """ Report to browse the filesystem """
    parameters = {'fsimage':'fsimage','inode':'sqlsafe'}
    hidden = True
    name = "View File Contents"
    description = "Display the contents of a file"
    
    def display(self,query,result):
        new_q = result.make_link(query, '')
        if not query.has_key('limit'): query['limit']= 0

        # retrieve the iosource for this fsimage
        iofd = IO.open(query['case'],query['fsimage'])
        fsfd = FileSystem.FS_Factory( query["case"], query["fsimage"], iofd)
        fd = fsfd.open(inode=query['inode'])

        ## We only want this much data
        image = Graph.FileDump(fd,limit=1000000)
        #How big is this file?
        i=fsfd.istat(inode=query['inode'])
        filesize=i['size']
        
        #Add the filename into the headers:
        path=fsfd.lookup(inode=query['inode'])
        if not path: raise IOError("No path for Inode %s" % query['inode'])
        path,name=os.path.split(path)
        image.headers=[("Content-Disposition","attachment; filename=%s" % name),
                       ("Content-Length",filesize)]
        
        result.heading("Viewing file in inode %s" % (query['inode']))
        try:
            result.text("Classified as %s by magic" % image.GetMagic())
        except IOError,e:
            result.text("Unable to classify file, no blocks: %s" % e)
            image = None

        def download(query):
            """ Used for dumping the entire file into the browser """
            if image:
                result.result=image.display()
                result.type=image.GetContentType()
                result.headers=image.headers
                result.binary=True
            return None

        def hexdump(query):
            """ Show the hexdump for the file """
            out=self.ui()
            if image:
                try:
                    max=config.MAX_DATA_DUMP_SIZE
                except AttributeError:
                    max=1024

                #Set limits for the dump
                try:
                    limit=int(query['hexlimit'])
                except KeyError:
                    limit=0
                dump = FlagFramework.HexDump(image.display(),out)
                dump.dump(offset=limit,limit=max)

                #Do the navbar
                result.next=limit+max
                if result.next>fd.size:
                    result.next=None
                result.previous=limit-max
                if result.previous<0:
                    if limit>0:
                        result.previous = 0
                    else:
                        result.previous=None
                result.pageno=limit/max
                result.nav_query=query.clone()
                result.nav_query['__target__']='hexlimit'
            else:
                out.text("No Data Available")

            return out

        def strings(query):
            """ Draw the strings in a file """
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
            
            output=self.ui()
            output.start_table()
            row_number=0
            file_offset=offset
            try:
                for i in str.extract_from_offset(int(offset)):
                    row_number+=1
                    if row_number>config.PAGESIZE: break
                    file_offset=i[0]
                    tmp_link=self.ui()
                    tmp_link.link("0x%x (%s)" % (file_offset,file_offset),q,mode="HexDump",hexlimit=file_offset)
          
                    tmp_string=self.ui()
                    tmp_string.text(i[1],color="red",sanitise="full")
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

        def stats(query):
            """ Show statistics about the file """
            result=self.ui()
            istat = fsfd.istat(inode=query['inode'])
            left=self.ui()
            left.row("filename:",'',"%s/%s"%(path,name))
            for k,v in istat.iteritems():
                left.row('%s:' % k,'',v)
            left.end_table()

            if image:
                right=self.ui()
                right.image(image,width=200)
                result.start_table(width="100%")
                result.row(left,right,valign='top',align="left")
            else:
                result.join(left)
            return result

        result.notebook(
            names=["Statistics","HexDump","Download","Strings"],
            callbacks=[stats,hexdump,download,strings],
            context="mode"
            )
            
    def form(self,query,result):
        result.defaults = query
        result.case_selector()
        result.meta_selector(message='FS Image',case=query['case'],property='fsimage')
        result.textfield('Inode','inode')
        return result

class Timeline(Reports.report):
    """ View file MAC times in a searchable table """
    parameters = {'fsimage':'fsimage'}
    name = "View File Timeline"
    description = "Browse file creation, modification, and access times"

    def form(self, query, result):
        try:
            result.case_selector()
            if query['case']!=config.FLAGDB:
                result.meta_selector(message='FS Image',case=query['case'],property='fsimage')
        except KeyError:
            return result

    def analyse(self, query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        temp_table = dbh.get_temp()
        dbh.execute("create temporary table %s select i.inode,f.status,mtime as `time`,1 as `m`,0 as `a`,0 as `c`,0 as `d`,concat(path,name) as `name` from inode_%s as i left join file_%s as f on i.inode=f.inode" %
                    (temp_table, tablename, tablename));
        dbh.execute("insert into %s select i.inode,f.status,atime,0,1,0,0,concat(path,name) from inode_%s as i left join file_%s as f on i.inode=f.inode" % (temp_table, tablename, tablename))
        dbh.execute("insert into %s select i.inode,f.status,ctime,0,0,1,0,concat(path,name) from inode_%s as i left join file_%s as f on i.inode=f.inode" % (temp_table, tablename, tablename))
        dbh.execute("insert into %s select i.inode,f.status,dtime,0,0,0,1,concat(path,name) from inode_%s as i left join file_%s as f on i.inode=f.inode" % (temp_table, tablename, tablename))
        dbh.execute("create table if not exists mac_%s select inode,status,time,sum(m) as `m`,sum(a) as `a`,sum(c) as `c`,sum(d) as `d`,name from %s where time>0 group by time,name order by time,name" %
                    (tablename, temp_table))
        dbh.execute("alter table  mac_%s add key(inode)" % tablename)
        
        
    def progress(self, query, result):
        result.heading("Building Timeline")
    
    def display(self, query, result):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        
        result.table(
            columns=('from_unixtime(time)','inode','status',
                     "if(m,'m',' ')","if(a,'a',' ')","if(c,'c',' ')","if(d,'d',' ')",'name'),
            names=('Timestamp', 'Inode','Del','m','a','c','d','Filename'),
            callbacks={'Del':DeletedIcon},
            table=('mac_%s' % tablename),
            case=query['case'],
#            links=[ None, None, None, None, None, None, None, FlagFramework.query_type((),case=query['case'],family=query['family'],fsimage=query['fsimage'],report='ViewFile',__target__='filename')]
            links=[ None, FlagFramework.query_type((),case=query['case'],family=query['family'],fsimage=query['fsimage'],report='ViewFile',__target__='inode')]
            )

    def reset(self, query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        dbh = self.DBO(query['case'])
        dbh.execute("drop table mac_%s" % tablename)


import md5

class HashComparison(BrowseFS):
    """ Compares MD5 hash against the NSRL database to classify files """
    parameters = {'fsimage':'fsimage'}
    name = "MD5 Hash comparison"
    description="This report will give a table for describing what the type of file this is based on the MD5 hash matches"
    progress_dict = {}

    def progress(self,query,result):
        result.heading("Calculating Hash tables");

    def reset(self,query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        dbh.execute('drop table hash_%s',tablename);

    def analyse(self,query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        dbh.execute("create table `hash_%s` select a.inode as `Inode`,concat(path,b.name) as `Filename`,d.type as `File Type`,if(c.Code=0,'Unknown',c.Name) as `NSRL Product`,c.Code as `NSRL Code`,a.NSRL_filename,md5 as `MD5` from md5_%s as a,%s.NSRL_products as c, type_%s as d left join file_%s as b on a.inode=b.inode   where  a.NSRL_productcode=c.Code and d.inode=a.inode group by Inode,`NSRL Code`,MD5",(tablename,tablename,config.FLAGDB,tablename,tablename))

    def display(self,query,result):
        result.heading("MD5 Hash comparisons for %s" % query['fsimage'])
        dbh=self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])

        def RenderNSRL(value):
            tmp=self.ui(result)
            if value>0:
                tmp.icon("yes.png")
            else:
                tmp.icon("no.png")

            return tmp
        
        result.table(
            columns=('Inode','Filename', '`File Type`', '`NSRL Product`','NSRL_filename', '`MD5`'),
            names=('Inode','Filename','File Type','NSRL Product','NSRLFilename','MD5'),
            table='hash_%s ' % (tablename),
            case=query['case'],
            links=[ FlagFramework.query_type((),case=query['case'],family=query['family'],fsimage=query['fsimage'],report='ViewFile',__target__='inode')]
            )

class IEHistory(Reports.report):
    """ View IE browsing history with pasco"""
    parameters = {'fsimage':'fsimage'}
    name = "IE Browser History (pasco)"
    description="This report will display all IE browsing history data found in index.dat files"
    def form(self,query,result):
        try:
            result.case_selector()
            if query['case']!=config.FLAGDB:
               result.meta_selector(case=query['case'],property='fsimage')
        except KeyError:
            return result

    def display(self,query,result):
        result.heading("IE History for %s" % query['fsimage'])
        dbh=self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])

        result.table(
            columns=('path','type','url','modified','accessed','concat(filepath,filename)','headers'),
            names=('Path','Type','URL','Modified','Accessed','Filename','Headers'),
            table=('history_%s' % (tablename)),
            case=query['case']
            )
                
class VirusScan(Reports.report):
    """ Scan Filesystem for Viruses using clamav"""
    parameters = {'fsimage':'fsimage'}
    name = "Virus Scan (clamav)"
    description="This report will scan for viruses and display a table of viruses found"
    def form(self,query,result):
        try:
            result.case_selector()
            if query['case']!=config.FLAGDB:
               result.meta_selector(case=query['case'],property='fsimage')
        except KeyError:
            return result

    def display(self,query,result):
        result.heading("Virus Scan for %s" % query['fsimage'])
        dbh=self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])

        try:
            result.table(
                columns=('a.inode','concat(path,name)', 'virus'),
                names=('Inode','Filename','Virus Detected'),
                table='virus_%s as a join file_%s as b on a.inode=b.inode ' % (tablename,tablename),
                case=query['case'],
                links=[ FlagFramework.query_type((),case=query['case'],family=query['family'],fsimage=query['fsimage'],report='ViewFile',__target__='inode')]
                )
        except DB.DBError,e:
            result.para("Unable to display Virus table, maybe you did not run the virus scanner over the filesystem?")
            result.para("The error I got was %s"%e)
            
if 0:
    class VirusScan(Reports.report):
        """ Scan Filesystem for Viruses using clamav"""
        parameters = {'fsimage':'fsimage'}
        name = "Virus Scan (clamav)"
        description="This report will display a table of viruses found during the scanning on Loading the filesystem "
        progress_dict = {}

        def form(self,query,result):
            try:
                result.case_selector()
                if query['case']!=config.FLAGDB:
                   result.meta_selector(case=query['case'],property='fsimage')
            except KeyError:
                return result

        def progress(self,query,result):
            dbh=self.DBO(query['case'])
            tablename = dbh.MakeSQLSafe(query['fsimage'])

            result.heading("Scanning Image for Viruses")
            dbh.execute("select count(*) as `count` from file_%s",tablename)
            row=dbh.fetch()
            try:
                result.text("Scanned %s out of %s files" % (self.progress_dict[tablename],row['count']))
            except KeyError:
                pass

        def display(self,query,result):
            result.heading("Virus Scan for %s" % query['fsimage'])
            dbh=self.DBO(query['case'])
            tablename = dbh.MakeSQLSafe(query['fsimage'])

            result.table(
                columns=('inode','filename', 'virus'),
                names=('Inode','Filename','Virus Detected'),
                table='virus_%s ' % (tablename),
                case=query['case'],
                links=[ FlagFramework.query_type((),case=query['case'],family=query['family'],fsimage=query['fsimage'],report='ViewFile',__target__='inode')]
                )

        def analyse(self,query):
            dbh = self.DBO(query['case'])
            tablename=dbh.MakeSQLSafe(query['fsimage'])
            dbh.execute("""CREATE TABLE `virus_%s` (
            `inode` varchar( 20 ) NOT NULL default '',
            `filename` text NOT NULL default '',
            `virus` text NOT NULL default ''
            )""" , tablename)

            iofd = IO.open(query['case'],query['fsimage'])
            ddfs = FileSystem.FS_Factory(query['case'],query['fsimage'],iofd)
            dbh=self.DBO(query['case'])

            ## We use this method to communicate with our other thread:
            self.progress_dict[tablename]=0

            scanner = VScan()
            dbh.execute("select inode, concat(path,name) as filename from file_%s where mode='r/r'",tablename)
            for row in dbh:
                self.progress_dict[tablename]+=1
                print "openning file %s"  % row['filename']
                try:
                    fd = ddfs.open(inode=row['inode'])
                    ## If the file is too fragmented, we dont take the hash for it, since it might take too long. This is mostly a problem with NTFS which suffers serious fragmentation issues, where files can be heavily fragmented leading to extremely long load times.
                    if len(fd.blocks)>1000:
                        print "skipping %s, too many block runs" % row['filename']
                        # add to table as NOT SCANNED?
                        continue

                    ## We use a rolling buffer so we dont miss a hit.
                    buf=fd.read(500000)
                    virus = scanner.scan(buf)
                    if virus:
                        dbh.execute("insert into virus_%s values(%r,%r,%r)", (tablename, row['inode'],row['filename'],virus))
                    else:
                        while 1:
                            #read 500k and append to buf
                            buf += fd.read(500000)
                            if not buf: break
                            #scan the buffer
                            virus = scanner.scan(buf)
                            if virus:
                                dbh.execute("insert into virus_%s values(%r,%r,%r)", (tablename, row['inode'],row['filename'],virus))
                                break
                            #drop the first half a meg
                            buf = buf[500000:]

                        fd.close()

                except IOError,e:
                    print "IOError on %s" % e
                    continue

        def reset(self,query):
            dbh = self.DBO(query['case'])
            tablename=dbh.MakeSQLSafe(query['fsimage'])
            dbh.execute("drop table if exists `virus_%s`",tablename)


class BrowseRegistry(BrowseFS):
    """ Browse a Windows Registry file """
    description="Browse a windows registry hive file (found in c:\winnt\system32\config\) "
    name = "Browse Registry Hive"

    def display(self,query,result):
        result.heading("Registry Hive in image %r" % query['fsimage'])
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        new_q=query.clone()
            
        #Make a tree call back:
        def treecb(branch):
            """ This call back will render the branch within the registry file. """
            path ='/'.join(branch)
            dbh = self.DBO(query['case'])

            ##Show the directory entries:
            dbh.execute("select basename from regi_%s where dirname=%r and length(basename)>1 group by basename",(tablename,path))
            for row in dbh:
                tmp=self.ui()
                tmp.link(row['basename'],new_q,mode='table',where_Path="%s/%s" %(path,row['basename']))
                yield(([row['basename'],tmp,'branch']))
                
        ## End Tree Callback

        try:
            try:
                if query['mode']=='table':
                    del new_q['mode']
                    for i in new_q.keys():
                        if i.startswith('where_'):
                            del new_q[i]

                    left=self.ui(result)
                    left.link("View Tree",new_q)
                    result.row(left)
                    result.table(
                        columns=['path','type','reg_key','size','value'],
                        names=['Path','Type','Key','Size','Value'],
                        links=[ result.make_link(new_q,'open_tree',mark='target') ],
                        table='reg_%s'%tablename,
                        case=query['case'],
                        )

                elif query['mode']=='display':
                    del new_q['mode']
                    key = query['key']
                    path=query['path']
                    del new_q['key']
                    del new_q['path']
                    left=self.ui(result)
                    left.link("View Tree",new_q)
                    result.row(left)
                    result.end_table()
                    result.para("Key %s/%s:" % (path,key))

                    def hexdump(query):
                        """ Show the hexdump for the key """
                        out = self.ui()
                        dbh.execute("select value from reg_%s where path=%r and reg_key=%r",(tablename,path,key))
                        row=dbh.fetch()
                        if row:
                            FlagFramework.HexDump(row['value'],out).dump()
                        return out

                    def strings(query):
                        """ Draw the strings in the key """
                        out = self.ui()
                        out.para("not implimented yet")
                        return out

                    def stats(query):
                        """ display stats on a key """
                        out = self.ui()
                        out.para("not implimented yet")
                        return out

                    result.notebook(
                        names=["HexDump","Strings","Statistics"],
                        callbacks=[hexdump,strings,stats],
                        context="display_mode"
                        )

            except KeyError,e:
                ## Display tree output
                del new_q['mode']
                del new_q['open_tree']

                def pane_cb(branch,table):
                    try:
                        path=query['open_tree']
                    except KeyError:
                        path = '/'.join(branch);

                    # now display keys in table
                    new_q['mode'] = 'display'
                    new_q['path']=path
                    table.table(
                        columns=['reg_key','type','size',"if(length(value)<50,value,concat(left(value,50),' .... '))"],
                        names=('Key','Type','Size','Value'),
                        table='reg_%s' % tablename,
                        where="path=%r" % path,
                        case=query['case'],
                        links=[ result.make_link(new_q, 'key') ]
                        )

                left=self.ui(result)
                left.link("View Table",new_q,mode='table')
                result.row(left)

                # display paths in tree
                result.tree(tree_cb=treecb,pane_cb=pane_cb,branch=[''])

        except DB.DBError,e:
            result.heading("Error occured")
            result.text('It appears that no registry tables are available. Maybe no registry files were found during scanning.')
            result.para('The Error returned by the database is %s' % e)
            
    def reset(self,query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        
        dbh.execute('drop table if exists reg_%s',tablename)
        dbh.execute('drop table if exists regi_%s',tablename)

class SearchIndex(Reports.report):
    """ Search for indexed keywords """
    description = "Search for words that were indexed during filesystem load. Words must be in dictionary to be indexed. "
    name = "Search Indexed Keywords"
    parameters={'fsimage':'fsimage','keyword':'any'}

    def form(self,query,result):
        try:
            result.case_selector()
            result.meta_selector(case=query['case'],property='fsimage')
            result.textfield("Keyword to search:",'keyword')
        except KeyError:
            return
        
    def display(self,query,result):
        dbh = self.DBO(query['case'])
        keyword = query['keyword']
        result.heading("Occurances of %s in logical image %s" %
                       (keyword,query['fsimage']))
        table = query['fsimage']
        iofd = IO.open(query['case'], query['fsimage'])
        fsfd = FileSystem.FS_Factory( query["case"], query["fsimage"], iofd)

        import index

        idx = index.Load("%s/LogicalIndex_%s.idx" % (config.RESULTDIR,table))
        for offset in idx.search(keyword):
            ## Find out which inode this offset is in:
            dbh.execute("select inode,offset from LogicalIndex_%s where offset <= %r order by offset desc,id desc limit 2",(query['fsimage'],offset))
            for row in dbh:
                fd = fsfd.open(inode=row['inode'])
                off = offset - int(row['offset']) - 10
                if off<0: off=0
                fd.seek(off)
                data = fd.read(10 + len(keyword) + 20)
                tmp = result.__class__(result)
                tmp.link("View file",FlagFramework.query_type((),case=query['case'],family=query['family'],report='ViewFile',fsimage=query['fsimage'],inode=row['inode'],mode='HexDump'))
                if data[10:10+len(keyword)].lower() == keyword:
                    result.text(data,"        ",tmp,"\n")
                fd.close()
