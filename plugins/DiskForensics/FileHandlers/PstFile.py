""" This module adds support for Microsoft Outlook personal file folders (pst files).

There is a scanner which executs the scanner factory train on files within the pst file, such files include email bodies and attachments, contact details, appointments and journal entries.

This feature complements the PST virtual filesystem driver to ensure that pst files are transparently viewable by the FLAG GUI.
"""
import os.path
import pyflag.logging as logging
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
from pyflag.FlagFramework import normpath

class PstScan(GenScanFactory):
    """ Recurse into Pst Files """
    default = True
    order=99
    def __init__(self,dbh, table,fsfd):
        self.dbh=dbh
        self.table=table
        self.to_re = re.compile('^to:\s+(.*?)\n(?:\w|\n)', re.IGNORECASE|re.MULTILINE|re.DOTALL)
        self.from_re = re.compile('^from:\s+(.*?)\n(?:\w|\n)', re.IGNORECASE|re.MULTILINE|re.DOTALL)
        # create the "groupware" tables
        # these are global to the image, not the file, so other scanners may wish to use them
        # in that case this code may belong elseware
        self.dbh.execute("CREATE TABLE IF NOT EXISTS `email_%s` (`inode` VARCHAR(250), `vfsinode` VARCHAR(250), `date` DATETIME, `to` VARCHAR(250), `from` VARCHAR(250), `subject` VARCHAR(250));", self.table)
        self.dbh.execute("CREATE TABLE IF NOT EXISTS `contact_%s` (`inode` VARCHAR(250), `vfsinode` VARCHAR(250), `name` VARCHAR(250), `email` VARCHAR(250), `address` VARCHAR(250), `phone` VARCHAR(250));", self.table)
        self.dbh.execute("CREATE TABLE IF NOT EXISTS `appointment_%s` (`inode` VARCHAR(250), `vfsinode` VARCHAR(250), `startdate` DATETIME, `enddate` DATETIME, `location` VARCHAR(250), `comment` VARCHAR(250));", self.table)
        self.dbh.execute("CREATE TABLE IF NOT EXISTS `journal_%s` (`inode` VARCHAR(250), `vfsinode` VARCHAR(250), `startdate` DATETIME, `enddate` DATETIME, `type` VARCHAR(250), `comment` VARCHAR(250));", self.table)


    def reset(self):
        GenScanFactory.reset(self)
        # reset the groupware tables, this should not be done here
        # if ever another scanner wants to use them also
        for name in ('email','contact','appointment','journal'):
            self.dbh.execute("DROP TABLE `%s_%s`;", (name, self.table))
        
    def destroy(self):
        pass
    
    class Scan(StoreAndScanType):
        def __init__(self, inode,ddfs,outer,factories=None):
            StoreAndScanType.__init__(self, inode,ddfs,outer,factories)
            self.to_re = outer.to_re
            self.from_re = outer.from_re

        types = (
            'application/x-msoutlook',
            )
        
        def external_process(self,name):
            """ This is run on the extracted file """
            pst=pypst2.Pstfile(name)

            ## filename is the filename in the filesystem for the pst file.
            filename = self.ddfs.lookup(inode=self.inode)

            def scan_item(inode,item):
                """ Scans the item with the scanner train.

                inode is fully qualified inode (e.g. D12|Pxxxx.0)
                """
                fd = StringIO.StringIO(item.read())
                fd.inode=inode
                Scanner.scanfile(self.ddfs,fd,self.factories)               

            def add_email(id,name,item):
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
                
                self.dbh.execute("INSERT INTO `email_%s` SET `inode`=%r,`vfsinode`='P%s',`date`=from_unixtime(%s),`to`=%r,`from`=%r,`subject`=%r", (self.table, self.inode, id, item.arrival_date, to_addr, from_addr, item.subject.subj))
                
                properties = {
                    'mtime':item.arrival_date,
                    'atime':item.arrival_date,
                    'ctime':item.sent_date,
                    'size': item.size
                    }
 
                self.ddfs.VFSCreate(self.inode,"P%s:0" % id, normpath("%s/body" % (name)),**properties)
                
                #scan body
                scan_item('%s|P%s:0' % (self.inode, id),item)

                # now add each attachment                
                count = 1
                for a in item.attach():
                    if a.filename1:
                        fname = a.filename1
                    elif a.filename2:
                        fname = a.filename2
                    else:
                        fname = "attach%i" % count

                    self.ddfs.VFSCreate(self.inode,"P%s:%s" % (id,count), normpath("%s/%s" % (name,fname)),**properties)

                    #scan attachments
                    scan_item('%s|P%s:%s' % (self.inode, id, count),a)
                    count += 1

            def add_other(id,name,item):
                """ Adds other items than emails (does not process attachments) """
                properties = {
                    'size': item.size
                    }
                                
                self.ddfs.VFSCreate(self.inode,"P%s" % id, normpath("%s" % (name)),**properties)
                
                #scan body
                scan_item('%s|P%s' % (self.inode, id),item)

            def add_contact(id,name,item):
                add_other(id,name,item)
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

                self.dbh.execute("INSERT INTO `contact_%s` SET `inode`=%r,`vfsinode`='P%s',`name`=%r, `email`=%r, `address`=%r, `phone`=%r", (self.table, self.inode, id, name, email, address, phone))

            def add_appointment(id,name,item):
                add_other(id,name,item)
                location = ''
                comment = ''
                if item.location:
                    location = item.location
                if item.comment:
                    comment = item.comment
                    
                self.dbh.execute("INSERT INTO `appointment_%s` SET `inode`=%r,`vfsinode`='P%s', `startdate`=from_unixtime(%s), `enddate`=from_unixtime(%s), `location`=%r, `comment`=%r",(self.table, self.inode, id, item.start, item.end, location, comment))

            def add_journal(id,name,item):
                add_other(id,name,item)
                jtype = ''
                comment = ''
                if item.type:
                    jtype = item.type
                if item.comment:
                    comment = item.comment
                
                self.dbh.execute("INSERT INTO `journal_%s` SET `inode`=%r,`vfsinode`='P%s', `startdate`=from_unixtime(%s), `enddate`=from_unixtime(%s), `type`=%r, `comment`=%r",(self.table, self.inode, id, item.start, item.end, jtype, comment))

            ## Just walk over all the files
            for root, dirs, files in pst.walk():
                ## We do not put empty directories (with no content) to prevent clutter
                for name in files:
                    item = pst.getitem(name[0])
                        ## We make the filename of the VFS object root/name[1]
                    if isinstance(item, pypst2.Pstfile.Email):
                        add_email(name[0],"%s/%s" % (root[1],name[1]),item)
                    elif isinstance(item, pypst2.Pstfile.Contact):
                        add_contact(name[0],"%s/%s" % (root[1],name[1]),item)
                    elif isinstance(item, pypst2.Pstfile.Appointment):
                        add_appointment(name[0],"%s/%s" % (root[1],name[1]),item)
                    elif isinstance(item, pypst2.Pstfile.Journal):
                        add_journal(name[0],"%s/%s" % (root[1],name[1]),item)

## The correspoding VFS module:
class Pst_file(File):
    """ A file like object to read items from within pst files. The pst file is specified as an inode in the DBFS """
    specifier = 'P'
    blocks=()
    size=None
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)
        parts = inode.split('|')
        pstinode = '|'.join(parts[:-1])
        thispart = parts[-1]

        # open the pst file from disk cache
        # or from fd if cached file does not exist
        fname = FileSystem.make_filename(case, pstinode)
        if not os.path.isfile(fname):
            outfd = open(fname, 'w')
            outfd.write(fd.read())
            outfd.close()

        pst = pypst2.Pstfile(fname)
        item = pst.open(thispart[1:])
        self.data = item.read()
        self.pos = 0
        self.size=len(self.data)

    def read(self,len=None):
        if len:
            temp=self.data[self.pos:self.pos+len]
            self.pos+=len
            return temp
        else: return self.data

    def close(self):
        pass

    def tell(self):
        return self.pos

    def seek(self,pos,rel=0):
        if rel==1:
            self.pos+=pos
        elif rel==2:
            self.pos=len(self.data)+pos
        else:
            self.pos=pos


# a bunch of reports for browsing the outlook data
class PstExplorer(Reports.report):
    """ Browse Groupware Information"""
    parameters = {'fsimage':'fsimage','inode':'any'}
    name = "Groupware (Email, Contacts, Appointments etc)"
    family = "Disk Forensics"
    description="This report will display all email, contact and calendaring data found in recognised email folders and files (eg. pst)"
    
    def form(self,query,result):
        try:
            result.case_selector()
            result.meta_selector(message='FS Image',case=query['case'],property='fsimage')
            # show a list of files where email was found
            dbh = self.DBO(query['case'])
            tablename = dbh.MakeSQLSafe(query['fsimage'])
            dbh.execute('select distinct email.inode, concat(file.path,file.name) as path from email_%s as email, file_%s as file where file.inode = email.inode', (tablename, tablename))
            result.row('Email was found in the following files, select the file to browse:',colspan=2)
            for row in dbh:
                tmp=self.ui()
                tmp.link("%s" % (row['path']),query,inode=row['inode'],where_Inode=row['inode'])
                result.row(tmp)
            
        except KeyError:
            return result

    def display(self,query,result):
        result.heading("Email and Contacts in FS Image %s" % query['fsimage'])
        
        dbh=self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['fsimage'])
        
        def email(query):
            output = self.ui(result)
            output.table(
                columns=('inode','vfsinode','date','`from`','`to`','subject'),
                names=('Inode','VFSInode','Arrival Date','From','To','Subject'),
                table=('email_%s' % (tablename)),
                case=query['case']
                )
            return output
        
        def contacts(query):
            output = self.ui(result)
            output.table(
                columns=('inode','vfsinode','name','email','address','phone'),
                names=('Inode','VFSInode','Name','Email','Address','Phone'),
                table=('contact_%s' % (tablename)),
                case=query['case']
                )
            return output
        
        def appts(query):
            output = self.ui(result)
            output.table(
                columns=('inode','vfsinode','startdate','enddate','location','comment'),
                names=('Inode','VFSInode','Start Date','End Date','Location','Comment'),
                table=('appointment_%s' % (tablename)),
                case=query['case']
                )
            return output
        
        def journal(query):
            output = self.ui(result)
            output.table(
                columns=('inode','vfsinode','startdate','enddate','type','comment'),
                names=('Inode','VFSInode','Start Date','End Date','Type','Comment'),
                table=('journal_%s' % (tablename)),
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

class ViewEmail(Reports.report):
    """ Display a pst email message """
    parameters = {'fsimage':'fsimage','inode':'sqlsafe'}
    name = "Display email message"
    family = "Disk Forensics"
    description = "This report displays an email item from a pst vfs entry as a nicely formatted email message"
    hidden = True

    def form(self, query, result):
        try:
            result.case_selector()
            result.meta_selector(message='FS Image',case=query['case'],property='fsimage')
            result.textfield('Inode','inode')
        except KeyError:
            return result

    def display(self, query, result):
        result.heading("Email Message in %i" % query['inode'])

        iofd = IO.open(query['case'],query['fsimage'])
        fsfd = FileSystem.FS_Factory( query["case"], query["fsimage"], iofd)
        #fd = fsfd.open(inode=query['inode'])

        # grab a list of subitems for this email
        # (headers, body, attachments)
        # use pypst directly or dbfs???
