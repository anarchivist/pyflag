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
""" This Module handles windows registry files.

This module contains a scanner to trigger off on registry files and scan them seperately. A report is also included to allow tree viewing and table searching of registry files.
"""
import os.path
import pyflag.logging as logging
from pyflag.Scanner import *
import plugins.DiskForensics.DiskForensics as DiskForensics
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework

class RegistryScan(GenScanFactory):
    """ Load in Windows Registry files """
    default = True
    def __init__(self,dbh, table,fsfd):
        self.dbh=dbh
        self.table=table
        dbh.MySQLHarness("regtool -t reg_%s -d create" % table)

    def reset(self):
        GenScanFactory.reset(self)
        self.dbh.MySQLHarness("regtool -t reg_%s -d drop" % self.table)
        #self.dbh.execute('drop table if exists reg_%s',self.table)
        self.dbh.execute('drop table if exists regi_%s',self.table)
        
    def destroy(self):
        ## Create the directory indexes to speed up tree navigation:
        self.dbh.execute("create table if not exists regi_%s (`dirname` TEXT NOT NULL ,`basename` TEXT NOT NULL,KEY `dirname` (`dirname`(100)))",self.table)
        dirtable = {}
        self.dbh.execute("select path from reg_%s",self.table)
        for row in self.dbh:
            array=row['path'].split("/")
            while len(array)>1:
                new_dirname="/".join(array[:-1])
                new_basename=array.pop()
                try:
                    ## See if the value is already in the dictionary
                    dirtable[new_dirname].index(new_basename)
                except ValueError:
                    dirtable[new_dirname].append(new_basename)
                except KeyError:
                    dirtable[new_dirname]=[new_basename]

        for k,v in dirtable.items():
            for name in v:
                self.dbh.execute("insert into regi_%s set dirname=%r,basename=%r",(self.table,k,name))

        ## Add indexes:
        self.dbh.check_index("reg_%s" % self.table,"path")

    class Scan(StoreAndScanType):
        types =  (
            'application/x-winnt-registry',
            'application/x-win9x-registry',
            )
        
        def external_process(self,filename):
            self.dbh.MySQLHarness("regtool -f %s -t reg_%s -p %r " % (filename,self.ddfs.table,self.ddfs.lookup(inode=self.inode)))

## Report to browse Loaded Registry Files:
class BrowseRegistry(DiskForensics.BrowseFS):
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
            path =FlagFramework.normpath('/'.join(branch))
            if path=='/': path=''
            dbh = self.DBO(query['case'])

            ##Show the directory entries:
            dbh.execute("select basename from regi_%s where dirname=%r and length(basename)>1 group by basename",(tablename,path))
            for row in dbh:
                yield(([row['basename'],row['basename'],'branch']))
                
        ## End Tree Callback
        try:
            def table_notebook_cb(query,result):
                del new_q['mode']
                del new_q['mark']
                result.table(
                    columns=['path','type','reg_key','from_unixtime(modified)','size','value'],
                    names=['Path','Type','Key','Modified','Size','Value'],
                    links=[ result.make_link(new_q,'open_tree',mark='target',mode='Tree View') ],
                    table='reg_%s'%tablename,
                    case=query['case'],
                    )

            def tree_notebook_cb(query,result):
                if (query.has_key("open_tree") and query['open_tree'] != '/'):
                    br = query['open_tree']
                else:
                    br = '/'
                    
                tmp=result.__class__(result)
                dbh.execute("select from_unixtime(modified) as time from reg_%s where path=%r",(tablename,br))
                row=dbh.fetch()
                try:
                    tmp.text("Last modified %s " % row['time'],color='red')
                    result.row(tmp)
                except TypeError:
                    pass
                    
                def pane_cb(branch,table):
                    path = FlagFramework.normpath('/'.join(branch))

                    # now display keys in table
                    new_q['mode'] = 'display'
                    new_q['path']=path
                    table.table(
                        columns=['reg_key','type','size',"if(length(value)<50,value,concat(left(value,50),' .... '))"],
                        names=('Key','Type','Size','Value'),
                        table='reg_%s' % tablename,
                        where="path=%r" % path,
                        case=query['case'],
                        links=[ FlagFramework.query_type(family=query['family'],report='BrowseRegistryKey',fsimage=query['fsimage'],path=path,__target__='key',case=query['case'])],
                        )

                # display paths in tree
                result.tree(tree_cb=treecb,pane_cb=pane_cb,branch=[''])

            result.notebook(
                names=['Tree View','Table View'],
                callbacks=[tree_notebook_cb,table_notebook_cb],
                context='mode',
                )
            
        except DB.DBError,e:
            result.heading("Error occured")
            result.text('It appears that no registry tables are available. Maybe no registry files were found during scanning.')
            result.para('The Error returned by the database is %s' % e)
            
    def reset(self,query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        
        dbh.execute('drop table if exists reg_%s',tablename)
        dbh.execute('drop table if exists regi_%s',tablename)

class BrowseRegistryKey(BrowseRegistry):
    """ Display the content of a registry key """
    parameters= {'fsimage':'fsimage','key':'string','path':'string'}
    hidden=True
    name="BrowseRegistryKey"
    family="Disk Forensics"
    description =    """ Display the content of a registry key """

    def display(self,query,result):
        path=query['path']
        key=query['key']
        result.heading("Registry Key Contents from Filesystem %s" % query['fsimage'])
        result.text("Key %s/%s:" % (path,key),color='red',font='typewriter')
        dbh=DB.DBO(query['case'])
        tablename=query['fsimage']

        def hexdump(query,out):
            """ Show the hexdump for the key """
            dbh.execute("select value from reg_%s where path=%r and reg_key=%r",(tablename,path,key))
            row=dbh.fetch()
            if row:
                FlagFramework.HexDump(row['value'],out).dump()
            return out

        def strings(query,out):
            """ Draw the strings in the key """
            out.para("not implimented yet")
            return out

        def stats(query,out):
            """ display stats on a key """
            out.para("not implimented yet")
            return out

        result.notebook(
            names=["HexDump","Strings","Statistics"],
            callbacks=[hexdump,strings,stats],
            context="display_mode"
            )


