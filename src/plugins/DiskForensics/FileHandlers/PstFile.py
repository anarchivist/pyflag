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
""" This module adds support for Microsoft Outlook personal file folders (pst files).

There is a scanner which executs the scanner factory train on files within the pst file, such files include email bodies and attachments, contact details, appointments and journal entries.

This feature complements the PST virtual filesystem driver to ensure that pst files are transparently viewable by the FLAG GUI.
"""
import os.path
from pyflag.Scanner import *
import pyflag.Scanner as Scanner
import pyflag.IO as IO
import pyflag.FileSystem as FileSystem
from pyflag.FileSystem import File, StringIOFile
import pyflag.Reports as Reports
import pyflag.DB as DB
import StringIO
import re
from pyflag.FlagFramework import normpath, query_type
import pyflag.FlagFramework as FlagFramework
import Store
from pyflag.ColumnTypes import StringType, TimestampType, InodeType
import pst

def format_properties(properties):
    """ This function formats the property sets returned by the pst
    item into a hopefully more readable format

    For now - very simple.
    """
    result = []
    keys = [k for k in properties.keys() if not k.startswith("_") ]
    keys.sort()
    
    for k in keys:
        result.append("%s:\n\n%s" % (k,properties[k]))

    return ("\n%s\n" % ('-' * 50)).join(result)

class PstScan(GenScanFactory):
    """ Recurse into Pst Files """
    default = True
    order=99
    depends = ['TypeScan']
    group = "FileScanners"

    class Drawer(Scanner.Drawer):
        description = "File Type Related Scanners"
        group = "FileScanners"
        default = True

    class Scan(StoreAndScanType):
        types = (
            'application/x-msoutlook',
            )
        
        def external_process(self,fd):
            """ This is run on the extracted file """
            pst_file = pst.PstFile(fd.name)

            ## Iterate over all the elements in the file and add VFS
            ## inodes to them:
            path, inode, inode_id = self.ddfs.lookup(inode=self.fd.inode)
            
            def add_inodes(path, root_item):
                for item in pst_file.listitems(root_item):
                    properties = item.properties()

                    item_inode = "%s|P%s" % (self.fd.inode, item.get_id())
                    new_path = FlagFramework.normpath(
                        "%s/%s" % (path, item.__str__().replace('/','_'))
                        )

                    ## This is a little optimization - we save the
                    ## cache copy of the property list so the File
                    ## driver does not need to do anything:
                    property_data = format_properties(properties)

                    ## These are the inode properties:
                    args = dict(size = len(property_data))

                    try:
                        args['_ctime'] = properties.get('create_date',
                                                       properties['arrival_date'])
                    except: pass

                    try:
                        args['_mtime'] = properties.get('modify_date',
                                                       properties['sent_date'])
                    except: pass
                    
                    self.ddfs.VFSCreate(None, item_inode, new_path, **args)

                    ## Make sure we can scan it:
                    fd = self.ddfs.open(inode = item_inode)
                    Scanner.scanfile(self.ddfs, fd, self.factories)

                    ## If its an email we create VFS nodes for its
                    ## attachments:
                    try:
                        for i in range(len(properties['_attachments'])):
                            att = properties['_attachments'][i]
                            
                            attachment_path = FlagFramework.normpath(
                                "%s/%s" % (new_path, att['filename1'].replace('/','_')))

                            args['size'] = len(att['body'])
                                        
                            attach_inode = "%s:%s" % (item_inode,i)
                            self.ddfs.VFSCreate(None, attach_inode,
                                                attachment_path, **args)
                            
                            ## Make sure we scan it:
                            fd = self.ddfs.open(inode = attach_inode)
                            Scanner.scanfile(self.ddfs, fd, self.factories)
                    except KeyError:
                        pass

                    ## Recursively add the next inode:
                    add_inodes(new_path, item)

            add_inodes(path, None)

PST_STORE = Store.Store(max_size=3)

## The correspoding VFS module:
class PstFile(StringIOFile):
    """ A file like object to read items from within pst files.

    We return a formatted property list for items, and a the file
    contents for attachments

    We write the 

    """
    specifier = 'P'

    attach_number = None
    item_id = None
    pst = None

    def __init__(self, case, fd, inode):
        parts = inode.split('|')
        pstinode = parts[-1][1:]

        ## Force our parent to be cached because we need a file to
        ## work from
        fd.cache()

        ## Were we given an attachment number as well?
        try:
            item_id, attach_number = pstinode.split(':')
            self.item_id = int(item_id)
            self.attach_number = int(attach_number)
        except:
            self.item_id = int(pstinode)

        ## See if the pst file is cached - if not parse it all again
        try:
            self.pst = PST_STORE.get(fd.inode)
        except KeyError:
            self.pst = pst.PstFile(fd.cached_fd.name)
            PST_STORE.put(self.pst, key = fd.inode)
            
        StringIOFile.__init__(self, case, fd, inode)

    def read(self,length=None):
        ## Call our baseclass to see if we have cached data:
        try:
            return File.read(self,length)
        except IOError:
            pass

        item = self.pst.get_item(self.item_id)
        result =''
        properties = item.properties()
        
        if self.attach_number == None:
            result = format_properties(properties)
        else:
            attachment = properties['_attachments'][self.attach_number]
            result = attachment['body']
            
        self.size = len(result)

        return result

# a bunch of reports for browsing the outlook data
class PstExplorer(Reports.report):
    """ Browse Groupware Information"""
    parameters = {'inode':'any'}
    name = "Groupware (Email, Contacts, Appointments etc)"
    family = "Disk Forensics"
    description="This report will display all email, contact and calendaring data found in recognised email folders and files (eg. pst)"
    ## hidden for now
    hidden=True
    
    def form(self,query,result):
        try:
            result.case_selector()

            # show a list of files where email was found
            dbh = self.DBO(query['case'])
            try:
                dbh.execute('select distinct email.inode, concat(file.path,file.name) as path from email as email, file as file where file.inode = email.inode')
                result.row('Email was found in the following files, select the file to browse:',colspan=2)
                for row in dbh:
                    tmp=self.ui(result)
                    tmp.link("%s" % (row['path']),query,inode=row['inode'],where_Inode=row['inode'])
                    result.row(tmp)
            except DB.DBError,e:
                result.para("Error reading the email table. Did you remember to run the PstExplorer scanner?")
                result.para("Error reported was:")
                result.text(e,style="red")
                
            
        except KeyError:
            return result

    def display(self,query,result):
        result.heading("Email and Contacts in VFS")
        
        dbh=self.DBO(query['case'])
        
        def email(query,output):
            output.table(
                elements = [ InodeType('Inode','inode',
                                       link = query_type(case=query['case'],
                                                         family="Disk Forensics",
                                                         report='ViewFile',
                                                         __target__='inode',
                                                         inode="%s:0")),
                             TimestampType('Arrival Date','date'),
                             StringType('From','from'),
                             StringType('To', 'to'),
                             StringType('Subject', 'subject') ],
                table=('email'),
                case=query['case'],
                filter="filter0",
                )
            return output
        
        def contacts(query,output):
            output.table(
                elements = [ InodeType('Inode','inode'),
                             StringType('Name','name'),
                             StringType('Email','email'),
                             StringType('Address','address'),
                             StringType('Phone','phone') ],
                table=('contact'),
                case=query['case'],
                filter="filter1",
                )
            return output
        
        def appts(query,output):
            output.table(
                elements = [ InodeType('Inode','inode'),
                             TimestampType('Start Date','startdate'),
                             TimestampType('End Date','enddate'),
                             StringType('Location','location'),
                             StringType('Comment','comment') ],
                table=('appointment'),
                case=query['case'],
                filter="filter2",
                )
            return output
        
        def journal(query,output):
            output.table(
                elements = [ InodeType('Inode','inode'),
                             TimestampType('Start Date','startdate'),
                             TimestampType('End Date','enddate'),
                             StringType('Type','type'),
                             StringType('Comment','comment') ],
                table=('journal'),
                case=query['case'],
                filter="filter3",
                )
            return output

        try:
            result.notebook(
                names=["Email","Contacts","Appointments","Journal"],
                callbacks=[email,contacts,appts,journal],
                context="mode"
                )
        except DB.DBError:
            result.para("No groupware tables found, either there were no recognised email folders found, or the correct scanners were not run")

import pyflagsh
import pyflag.tests

class PstScannerTest(pyflag.tests.ScannerTest):
    """ Test handling of pst files """
    test_case = "PyFlag Test Case"
    test_file = "pyflag_stdimage_0.4.e01"
    subsystem = 'EWF'
    offset = "16128s"
    
    def test01RunScanner(self):
        """ Test Zip scanner handling of pst files """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'PstScan', 'TypeScan', 'RFC2822'])
