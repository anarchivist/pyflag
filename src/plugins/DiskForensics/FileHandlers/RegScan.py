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
""" This Module handles windows registry files.

This module contains a scanner to trigger off on registry files and scan them seperately. A report is also included to allow tree viewing and table searching of registry files.
"""
import os.path
import pyflag.logging as logging
from pyflag.Scanner import *
import plugins.DiskForensics.DiskForensics as DiskForensics
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework
import pyflag.Reports as Reports
from FileFormats.RegFile import ls_r, RegF
from format import Buffer

class RegistryScan(GenScanFactory):
    """ Load in Windows Registry files """
    default = True
    depends = ['TypeScan']
    
    def prepare(self):
        ## The reg table is used for storing all the values in each
        ## key
        dbh=DB.DBO(self.case)
        dbh.execute("""CREATE TABLE if not exists `reg` (
        `path` text NOT NULL,
        `offset` INT(11),
        `type` enum('REG_NONE','REG_SZ','REG_EXPAND_SZ','REG_BINARY','REG_DWORD','REG_DWORD_BIG_ENDIAN','REG_LINK','REG_MULTI_SZ','REG_RESOURCE_LIST','REG_FULL_RESOURCE_DESCRIPTOR','REG_RESOURCE_REQUIREMENTS_LIST','Unknown') NOT NULL,
        `modified` timestamp,
        `reg_key` VARCHAR(200) NOT NULL,
        `value` text)""")

        ## The regi table is used for the key navigation
        dbh.execute("""create table if not exists regi (
        `dirname` TEXT NOT NULL ,`basename` TEXT NOT NULL)""")

    def reset(self, inode):
        GenScanFactory.reset(self, inode)
        dbh=DB.DBO(self.case)
        dbh.execute('delete from reg')
        dbh.execute('delete from regi')
        
    def destroy(self):
        ## Add indexes:
        dbh=DB.DBO(self.case)
        dbh.check_index("reg" ,"path",250)
        dbh.check_index("regi" ,"dirname",100)


    class Scan(StoreAndScanType):
        types =  (
            'application/x-winnt-registry',
## FIXME: NOT Currently supported temporarily
#            'application/x-win9x-registry',
            )
        
        def external_process(self,fd):
            b=Buffer(fd)
            header = RegF(b)
            root_key = header['root_key_offset'].get_value()
            parent_path = self.ddfs.lookup(inode=self.inode)
            
            ## One handle does the reg table, the other handle the
            ## regi table:
            regi_handle=DB.DBO(self.case)
            reg_handle=DB.DBO(self.case)

            reg_handle.mass_insert_start('reg')
            regi_handle.mass_insert_start('regi')
            
            def store_key(nk_key, path):
                regi_handle.mass_insert(dirname=path,
                                        basename=nk_key['key_name'])

                new_path="%s/%s" % (path,nk_key['key_name'])

                ## Store all the values:
                for v in nk_key.values():
                    reg_handle.mass_insert(path=new_path,
                                           offset=v['data']['offs_data'],
                                           modified=nk_key['WriteTS'],
                                           type=v['data']['val_type'],
                                           reg_key=v['keyname'],
                                           value=v['data']
                                           )
                    
                for k in nk_key.keys():
                    store_key(k,new_path)

            store_key(root_key,path=parent_path)
            reg_handle.mass_insert_commit()
            regi_handle.mass_insert_commit()
            

## Report to browse Loaded Registry Files:
class BrowseRegistry(DiskForensics.BrowseFS):
    """ Browse a Windows Registry file """
    description="Browse a windows registry hive file (found in c:\winnt\system32\config\) "
    name = "Browse Registry Hive"

    def display(self,query,result):
        result.heading("Registry Hive")
        dbh = self.DBO(query['case'])
        new_q=query.clone()
                            
        try:
            def table_notebook_cb(query,result):
                del new_q['mode']
                del new_q['mark']
                result.table(
                    columns=['path','type','reg_key','from_unixtime(modified)','value'],
                    names=['Path','Type','Key','Modified','Value'],
                    links=[ result.make_link(new_q,'open_tree',mark='target',mode='Tree View') ],
                    table='reg',
                    case=query['case'],
                    )

            def tree_notebook_cb(query,result):
                
                #Make a tree call back:
                def treecb(path):
                    """ This call back will render the branch within
                    the registry file."""
                    dbh = DB.DBO(query['case'])

                    ##Show the directory entries:
                    dbh.execute("select basename from regi where dirname=%r",(path))
                    for row in dbh:
                        yield(([row['basename'],row['basename'],'branch']))
    
                def pane_cb(path,table):
                    tmp=result.__class__(result)
                    dbh.execute("select modified as time from reg where path=%r limit 1",(path))
                    row=dbh.fetch()

                    try:
                        tmp.text("Last modified %s " % row['time'],color='red')
                        table.row(tmp)
                    except TypeError:
                        pass
                    
                    # now display keys in table
                    new_q['mode'] = 'display'
                    new_q['path']=path
                    table.table(
                        columns=['reg_key','type',"if(length(value)<50,value,concat(left(value,50),' .... '))"],
                        names=('Key','Type','Value'),
                        table='reg',
                        where="path=%r" % path,
                        case=query['case'],
                        links=[ FlagFramework.query_type(family=query['family'],report='BrowseRegistryKey',path=path,__target__='key',case=query['case'])],
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
            result.text('It appears that no registry tables are available. Did you remember to run the RegistryScan scanner?')
            result.para('The Error returned by the database is:')
            result.text(e,color='red')
            
    def reset(self,query):
        dbh = self.DBO(query['case'])

        dbh.execute('drop table if exists reg')
        dbh.execute('drop table if exists regi')

class BrowseRegistryKey(BrowseRegistry):
    """ Display the content of a registry key """
    parameters= {'key':'string','path':'string'}
    hidden=True
    name="BrowseRegistryKey"
    family="Disk Forensics"
    description =    """ Display the content of a registry key """

    def display(self,query,result):
        path=query['path']
        key=query['key']
        result.heading("Registry Key Contents")
        result.text("Key %s/%s:" % (path,key),color='red',font='typewriter')
        dbh=DB.DBO(query['case'])

        def hexdump(query,out):
            """ Show the hexdump for the key """
            dbh.execute("select value from reg where path=%r and reg_key=%r limit 1",(path,key))
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
            out.para("not implemented yet")
            return out

        result.notebook(
            names=["HexDump","Strings","Statistics"],
            callbacks=[hexdump,strings,stats],
            context="display_mode"
            )
         

class InterestingRegKey(Reports.report):
    """ Displays values of interesting registry keys, grouped into categories """
    name = "Interesting Reg Keys"
    family = "Disk Forensics"
    description="This report shows the values of interesting registry keys on the disk"
    progress_dict = {}

    def form(self,query,result):
        result.case_selector()
        
    def progress(self,query,result):
        result.heading("Looking for registry key values");

    def reset(self,query):
        dbh = self.DBO(query['case'])
        dbh.execute('drop table interestingregkeys');

    def analyse(self,query):
        dbh = self.DBO(query['case'])
        pdbh=self.DBO(None)
        try:
            dbh.execute("create table `interestingregkeys` select a.path, a.size, a.modified, a.remainder, a.type, a.reg_key, a.value, b.category, b.description from reg as a, %s.registrykeys as b where a.path LIKE concat('%%',b.path,'%%') AND a.reg_key LIKE concat('%%',b.reg_key,'%%')",(config.FLAGDB))
        except DB.DBError,e:
            raise Reports.ReportError("Unable to find the registry table for the current image. Did you run the Registry Scanner?.\n Error received was %s" % e)
    
    def display(self,query,result):
        result.heading("Interesting Registry Keys")
        dbh=self.DBO(query['case'])

        try:
            result.table(
                columns=('Path','reg_key','Value','from_unixtime(modified)','category','Description'),
                names=('Path','Key','Value','Last Modified','Category','Description'),
                table='interestingregkeys ',
                case=query['case'],
                #TODO make a link to view the rest of the reg info
                #links=[ FlagFramework.query_type((),case=query['case'],family=query['family'],fsimage=query['fsimage'],report='BrowseRegistryKey')]
                )
        except DB.DBError,e:
            result.para("Error reading the registry keys table. Did you remember to run the registry scanner?")
            result.para("Error reported was:")
            result.text(e,color="red")
