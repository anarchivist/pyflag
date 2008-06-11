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
""" These are a bunch of stand alone reports useful to preview data
before lengthy processing.
"""
import pyflag.Reports as Reports
import FileFormats.RegFile as RegFile
from pyflag.format import Buffer,RAW
import pyflag.FileSystem as FileSystem
import pyflag.Registry as Registry
from pyflag.ColumnTypes import IntegerType,TimestampType,InodeType,FilenameType, StringType, StateType
from pyflag.ColumnTypes import DeletedType, BinaryType
import pyflag.DB as DB
import time
import pyflag.IO as IO

class RegistryBrowser(Reports.report):
    """
    Browse a registry file.
    -----------------------

    This reoport allows the browsing of a registry file without
    loading it into a case. This may be useful for a quick preview of
    a system.
    """
    parameters = { 'file':'filename' }
    family = "Preview"
    name = "Registry Browser"
    
    def form(self, query, result):
        result.fileselector("Select registry File","file")

    def display(self, query, result):
        def tree_cb(path):
            fd = IO.open_URL(query['file'])
            b = Buffer(fd = fd)
            header = RegFile.RegF(b)
            key = header.get_key(path)
            for k in key.keys():
                try:
                    name = k['key_name'].get_value()
                except:
                    name = None
                yield (name,name,'branch')

        def pane_cb(path, result):
            fd = IO.open_URL(query['file'])
            b = Buffer(fd = fd)
            header = RegFile.RegF(b)
            key = header.get_key(path)
            result.text("Timestamp: %s" % key['WriteTS'], style='red')
            result.start_table(**{'class':'GeneralTable'})

            ## We dont want to reference the keys because we
            ## will leak memeory while the callback remains stored.
            def details(query,result):
                fd = IO.open_URL(query['file'])
                b = Buffer(fd = fd)
                header = RegFile.RegF(b)
                key = header.get_key(path)
                result.heading("Key %s" % path)
                result.text("%s" % key, font='typewriter', wrap='full')
                
                for v in key.values():
                    try:
                        name = "%s"%  v['keyname']
                        result.heading("%s" % name)
                        result.text("%s" % v, font='typewriter', wrap='full')
                    except: pass

            result.toolbar(cb = details, text = "Examine Details", icon = "examine.png")
            
            result.row('Type','Length','Name','Value', **{'class':'hilight'})
            for v in key.values():
                try:
                    t = "%s" % v['data']['val_type']
                    length = "%s" % v['data']['len_data']
                    name = "%s"%  v['keyname']
                    data = "%s" % v['data']
                    data = RAW(data[:100])
                    result.row(t,length,name,data)
                except Exception,e:
                    print e
                    pass
                
        result.tree(tree_cb=tree_cb, pane_cb=pane_cb)

import plugins.LoadData as LoadData

class PreviewLoad(LoadData.LoadFS):
    """
    Loads a filesystem incrementally.
    ---------------------------------

    This loads a filesystem from an iosource incrementally into the
    database as the user navigates through the filesystem.
    """
    parameters = { 'iosource': 'string', 'fstype':'string', 'mount_point':'string'}
    name = "Incremental Load"
    family = "Preview"
    
    def analyse(self,query):
        pass

    def display(self,query,result):
        def tree_cb(path):
            ## We expect a directory here:
            if not path.endswith('/'): path=path+'/'

            ## We need to wait for this directory to load:
            case = query['case']
            dbh = DB.DBO(case)
            count = 0
            while 1:
                dbh.execute("select * from file where path=%r and name=''", path)
                if dbh.fetch(): break
                count +=1
                time.sleep(1)
                ## FIXME: what is a good time to decide when to give up?
                if count > 3600:
                    raise RuntimeError("Unable to load the filesystem?")
                
            ## We need a local copy of the filesystem factory so
            ## as not to affect other instances!!!
            fsfd = FileSystem.DBFS( query["case"])
            
            for i in fsfd.dent_walk(path): 
                if i['mode']=="d/d" and i['status']=='alloc':
                    yield(([i['name'],i['name'],'branch']))

        def pane_cb(path, result):
            if not path.endswith('/'): path=path+'/'
                
            result.heading("Path is %s" % path)
            case = query['case']
            dbh = DB.DBO(case)
            fsfd = Registry.FILESYSTEMS.dispatch(query['fstype'])(case)
            ## Try to see if the directory is already loaded:
            dbh.execute("select * from file where path=%r and name=''", path)
            if not dbh.fetch():
                fsfd.load(mount_point = query['mount_point'], iosource_name= query['iosource'],
                          directory = path)

            ## Now display the table
            result.table(
                elements = [ InodeType('Inode','file.inode',case=query['case']),
                             StringType('Filename','name'),
                             DeletedType('Del','file.status'),
                             IntegerType('File Size','size'),
                             TimestampType('Last Modified','mtime'),
                             TimestampType('Mode','file.mode')                             
                             ],
                table='file, inode',
                where="file.inode=inode.inode and path=%r and file.mode!='d/d'" % (path),
                case = query['case'],
                pagesize=10,
                )

        result.tree(tree_cb=tree_cb, pane_cb=pane_cb)
