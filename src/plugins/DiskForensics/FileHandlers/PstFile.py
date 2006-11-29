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
""" This module adds support for Microsoft Outlook personal file folders (pst files).

There is a scanner which executs the scanner factory train on files within the pst file, such files include email bodies and attachments, contact details, appointments and journal entries.

This feature complements the PST virtual filesystem driver to ensure that pst files are transparently viewable by the FLAG GUI.
"""
import os.path
from pyflag.Scanner import *
import pyflag.Scanner as Scanner
import pypst2
import pyflag.IO as IO
import pyflag.FileSystem as FileSystem
from pyflag.FileSystem import File
import pyflag.Reports as Reports
import pyflag.DB as DB
import StringIO
import re
from pyflag.FlagFramework import normpath, query_type
import pyflag.FlagFramework as FlagFramework
import pexpect
import Store
from pyflag.TableObj import ColumnType, TimestampType, InodeType

class PstScan(GenScanFactory):
    """ Recurse into Pst Files """
    default = True
    order=99
    depends = ['TypeScan']

    class Drawer(Scanner.Drawer):
        description = "File Type Related Scanners"
        name = "File Scanners"
        contains = [ 'PstScan','IEIndex', 'RegistryScan', 'TypeScan', 'DLLScan',
                     'ExtractorScan' ]
        default = True

        # Let's check if this external tool exists into the PATH and then add it to the Drawer
        try: 
              s=pexpect.spawn('stegdetect -V')
              s.expect(pexpect.EOF)
              if "Stegdetect Version" in s.before :
                     contains.append('AFTJpegScan')
        except pexpect.ExceptionPexpect,e:
              pass

    def __init__(self,fsfd):
        GenScanFactory.__init__(self, fsfd)
        dbh=DB.DBO(self.case)
        self.to_re = re.compile('^to:\s+(.*?)\n(?:\w|\n)', re.IGNORECASE|re.MULTILINE|re.DOTALL)
        self.from_re = re.compile('^from:\s+(.*?)\n(?:\w|\n)', re.IGNORECASE|re.MULTILINE|re.DOTALL)
        # create the "groupware" tables
        # these are global to the image, not the file, so other scanners may wish to use them
        # in that case this code may belong elseware
        dbh.execute("CREATE TABLE IF NOT EXISTS `email` (`inode` VARCHAR(250), `date` TIMESTAMP, `to` VARCHAR(250), `from` VARCHAR(250), `subject` VARCHAR(250));")
        dbh.execute("CREATE TABLE IF NOT EXISTS `contact` (`inode` VARCHAR(250), `name` VARCHAR(250), `email` VARCHAR(250), `address` VARCHAR(250), `phone` VARCHAR(250));")
        dbh.execute("CREATE TABLE IF NOT EXISTS `appointment` (`inode` VARCHAR(250), `startdate` TIMESTAMP, `enddate` TIMESTAMP, `location` VARCHAR(250), `comment` VARCHAR(250));")
        dbh.execute("CREATE TABLE IF NOT EXISTS `journal` (`inode` VARCHAR(250), `startdate` TIMESTAMP, `enddate` TIMESTAMP, `type` VARCHAR(250), `comment` VARCHAR(250));")


    def reset(self, inode):
        GenScanFactory.reset(self, inode)
        # reset the groupware tables, this should not be done here
        # if ever another scanner wants to use them also
        dbh=DB.DBO(self.case)
        for name in ('email','contact','appointment','journal'):
            dbh.execute("delete from `%s`;", (name))
        
    def destroy(self):
        pass
    
    class Scan(StoreAndScanType):
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            StoreAndScanType.__init__(self, inode,ddfs,outer,factories,fd=fd)
            self.to_re = outer.to_re
            self.from_re = outer.from_re

        types = (
            'application/x-msoutlook',
            )
        
        def external_process(self,fd):
            """ This is run on the extracted file """
            self.fd.pst_handle=pypst2.Pstfile(fd.name)

            def scan_item(inode,item):
                """ Scans the item with the scanner train.

                inode is fully qualified inode (e.g. D12|Pxxxx.0)
                """
                fd = self.ddfs.open(inode=inode)
#                fd = PstFile(self.dbh.case, self.fd, inode, dbh=self.dbh)
#                fd = StringIO.StringIO(item.read())
#                fd.inode=inode
                Scanner.scanfile(self.ddfs,fd,self.factories)               

            def add_email(new_inode,name,item):
                """ adds the email itself into the VFS

                @arg name: The name of the email to store
                """
                # add to email table
                if item.header:
                    to = self.to_re.search(item.header)
                    fr = self.from_re.search(item.header)
                    if to:
                        to_addr = to.group(1)
                    else:
                        to_addr = "unknown"
                    if fr:
                        from_addr = fr.group(1)
                    else:
                        from_addr = "unknown"
                else:
                    from_addr = "%s" % item.outlook_sender_name
                    if item.outlook_sender:
                        from_addr += " (%s)" % item.outlook_sender
                    to_addr = "%s" % item.sentto_address

                dbh=DB.DBO(self.case)
                dbh.execute("INSERT INTO `email` SET `inode`=%r,`date`=from_unixtime(%s),`to`=%r,`from`=%r,`subject`=%r", (new_inode, item.arrival_date, to_addr, from_addr, item.subject.subj))
                
                properties = {
                    'mtime':item.arrival_date,
                    'atime':item.arrival_date,
                    'ctime':item.sent_date,
                    'size': item.size
                    }
 
                self.ddfs.VFSCreate(None,"%s:0" % new_inode, normpath("%s/body" % (name)),**properties)
                
                #scan body
                scan_item('%s:0' % (new_inode),item)

                # now add each attachment                
                count = 1
                for a in item.attach():
                    if a.filename1:
                        fname = a.filename1
                    elif a.filename2:
                        fname = a.filename2
                    else:
                        fname = "attach%i" % count

                    self.ddfs.VFSCreate(None,"%s:%s" % (new_inode,count), normpath("%s/%s" % (name,fname)),**properties)

                    #scan attachments
                    scan_item('%s:%s' % (new_inode, count),a)
                    count += 1

            def add_other(new_inode,name,item):
                """ Adds other items than emails (does not process attachments) """
                properties = {
                    'size': item.size
                    }
                                
                self.ddfs.VFSCreate(None,new_inode, normpath("%s" % (name)),**properties)
                
                #scan body
                scan_item(new_inode,item)

            def add_contact(new_inode,name,item):
                add_other(new_inode,name,item)
                name = ''
                email = ''
                address = ''
                phone = ''

                # name
                if item.first_name:
                    name = item.first_name
                if item.middle_name:
                    name += " %s" % item.middle_name
                if item.surname:
                    name += " %s" % item.surname
                if item.nickname:
                    name += " (%s)" % item.nickname

                # email
                if item.address1:
                    email = item.address1
                elif item.address2:
                    email = item.address2
                elif item.address3:
                    email = item.address3

                # address
                if item.home_address:
                    address = item.home_address
                if item.home_street:
                    address += ", %s" % item.home_street
                if item.home_city:
                    address += ", %s" % item.home_city
                if item.home_state:
                    address += ", %s" % item.home_state
                if item.home_postal_code:
                    address += ", %s" % item.home_postal_code
                if item.home_country:
                    address += ", %s" % item.home_country

                # phone
                if item.home_phone:
                    phone = item.home_phone
                elif item.home_phone2:
                    phone = item.home_phone2
                elif item.other_phone:
                    phone = item.other_phone

                if item.mobile_phone:
                    phone += ", %s(m)" % item.mobile_phone

                if item.business_phone:
                    phone += ", %s(w)" % item.business_phone
                elif item.business_phone2:
                    phone += ", %s(w)" % item.business_phone2

                dbh=DB.DBO(self.case)
                dbh.execute("INSERT INTO `contact` SET `inode`=%r,`name`=%r, `email`=%r, `address`=%r, `phone`=%r", (new_inode, name, email, address, phone))

            def add_appointment(new_inode,name,item):
                add_other(new_inode,name,item)
                location = ''
                comment = ''
                if item.location:
                    location = item.location
                if item.comment:
                    comment = item.comment

                dbh=DB.DBO(self.case)
                dbh.execute("INSERT INTO `appointment` SET `inode`=%r, `startdate`=from_unixtime(%s), `enddate`=from_unixtime(%s), `location`=%r, `comment`=%r",(new_inode, item.start, item.end, location, comment))

            def add_journal(new_inode,name,item):
                add_other(new_inode,name,item)
                jtype = ''
                comment = ''
                if item.type:
                    jtype = item.type
                if item.comment:
                    comment = item.comment

                dbh=DB.DBO(self.case)
                dbh.execute("INSERT INTO `journal` SET `inode`=%r, `startdate`=from_unixtime(%s), `enddate`=from_unixtime(%s), `type`=%r, `comment`=%r",(new_inode, item.start, item.end, jtype, comment))

            ## Just walk over all the files
            for root, dirs, files in self.fd.pst_handle.walk():
                ## We do not put empty directories (with no content) to prevent clutter
                for name in files:
                    new_inode = "%s|P%s" % (self.inode, name[0])
                    root_directory = self.ddfs.lookup(inode=self.inode)
                    
                    item = self.fd.pst_handle.getitem(name[0])
                        ## We make the filename of the VFS object root/name[1]
                    if isinstance(item, pypst2.Pstfile.Email):
                        add_email(new_inode,"%s%s/%s" % (root_directory,root[1],name[1]),item)
                    elif isinstance(item, pypst2.Pstfile.Contact):
                        add_contact(new_inode,"%s%s/%s" % (root_directory,root[1],name[1]),item)
                    elif isinstance(item, pypst2.Pstfile.Appointment):
                        add_appointment(new_inode,"%s%s/%s" % (root_directory,root[1],name[1]),item)
                    elif isinstance(item, pypst2.Pstfile.Journal):
                        add_journal(new_inode,"%s%s/%s" % (root_directory,root[1],name[1]),item)

PST_STORE = Store.Store(max_size=3)

## The correspoding VFS module:
class PstFile(File):
    """ A file like object to read items from within pst files. The pst file is specified as an inode in the DBFS """
    specifier = 'P'
    blocks=()
    size=None
    def __init__(self, case, fd, inode):
        File.__init__(self, case, fd, inode)
        parts = inode.split('|')
        pstinode = '|'.join(parts[:-1])
        thispart = parts[-1]

        ## Force our parent to be cached because we need a file to
        ## work from
        fd.cache()

        try:
            self.pst = PST_STORE.get(self.fd.inode)
        except KeyError:
            self.pst = pypst2.Pstfile(self.fd.cached_fd.name)
            PST_STORE.put(self.pst, key = self.fd.inode)
            
        item = self.pst.open(thispart[1:])
        self.data = item.read()
        self.pos = 0
        self.size=len(self.data)

        ## Force ourself to be cached
        self.cache()

    def read(self,len=None):
        ## Call our baseclass to see if we have cached data:
        try:
            return File.read(self,len)
        except IOError:
            pass
        
        if len:
            temp=self.data[self.pos:self.pos+len]
            self.pos+=len
            return temp
        else: return self.data

    def close(self):
        pass


# a bunch of reports for browsing the outlook data
class PstExplorer(Reports.report):
    """ Browse Groupware Information"""
    parameters = {'inode':'any'}
    name = "Groupware (Email, Contacts, Appointments etc)"
    family = "Disk Forensics"
    description="This report will display all email, contact and calendaring data found in recognised email folders and files (eg. pst)"
    
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
                result.text(e,color="red")
                
            
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
                             ColumnType('From','from'),
                             ColumnType('To', 'to'),
                             ColumnType('Subject', 'subject') ],
                table=('email'),
                case=query['case']
                )
            return output
        
        def contacts(query,output):
            output.table(
                elements = [ InodeType('Inode','inode'),
                             ColumnType('Name','name'),
                             ColumnType('Email','email'),
                             ColumnType('Address','address'),
                             ColumnType('Phone','phone') ],
                table=('contact'),
                case=query['case']
                )
            return output
        
        def appts(query,output):
            output.table(
                elements = [ InodeType('Inode','inode'),
                             TimestampType('Start Date','startdate'),
                             TimestampType('End Date','enddate'),
                             ColumnType('Location','location'),
                             ColumnType('Comment','comment') ],
                table=('appointment'),
                case=query['case']
                )
            return output
        
        def journal(query,output):
            output.table(
                elements = [ InodeType('Inode','inode'),
                             TimestampType('Start Date','startdate'),
                             TimestampType('End Date','enddate'),
                             ColumnType('Type','type'),
                             ColumnType('Comment','comment') ],
                table=('journal'),
                case=query['case']
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
