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
from pyflag.FlagFramework import normpath

class PstScan(GenScanFactory):
    """ Recurse into Pst Files """
    order=99
    def __init__(self,dbh, table,fsfd):
        self.dbh=dbh
        self.table=table
        # create the "groupware" tables
        self.dbh.execute("CREATE TABLE IF NOT EXISTS `email_%s` (`inode` VARCHAR(250), `vfsinode` VARCHAR(250), `date` DATETIME, `to` VARCHAR(250), `from` VARCHAR(250), `subject` VARCHAR(250));", self.table)
        self.dbh.execute("CREATE TABLE IF NOT EXISTS `contact_%s` (`inode` VARCHAR(250), `vfsinode` VARCHAR(250), `name` VARCHAR(250), `address` VARCHAR(250));", self.table)
        self.dbh.execute("CREATE TABLE IF NOT EXISTS `appointment_%s` (`inode` VARCHAR(250), `vfsinode` VARCHAR(250), `startdate` DATETIME, `enddate` DATETIME, `location` VARCHAR(250), `comment` VARCHAR(250));", self.table)
        self.dbh.execute("CREATE TABLE IF NOT EXISTS `journal_%s` (`inode` VARCHAR(250), `vfsinode` VARCHAR(250), `startdate` DATETIME, `enddate` DATETIME, `type` VARCHAR(250), `comment` VARCHAR(250));", self.table)


    def reset(self):
        for name in ('email','contacts','appointments','journal'):
            self.dbh.execute("DROP TABLE `%s_%s`;", (name, self.table))
        
    def destroy(self):
        pass
    
    class Scan(StoreAndScan):            
        def boring(self,metadata):
            return metadata['mime'] not in (
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
                self.dbh.execute("INSERT INTO `email_%s` SET `inode`=%r,`vfsinode`='P%s',`date`=from_unixtime(%s),`to`=%r,`from`=%r,`subject`=%r;", (self.table, self.inode, id, item.arrival_date, item.sentto_address, item.sender_address, item.subject.subj))
                
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
 
            ## Just walk over all the files
            for root, dirs, files in pst.walk():
                ## We do not put empty directories (with no content) to prevent clutter
                for name in files:
                    item = pst.getitem(name[0])
                    if isinstance(item, pypst2.Pstfile.Email):
                        ## We make the filename of the email VFS object root/name[1]
                        add_email(name[0],"%s/%s" % (root[1],name[1]),item)
                    else:
                        add_other(name[0],"%s/%s" % (root[1],name[1]),item)

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
    parameters = {'fsimage':'fsimage'}
    name = "Groupware (Email, Contacts, Appointments etc)"
    family = "Disk Forensics"
    description="This report will display all email, contact and calendaring data found in recognised email folders and files (eg. pst)"
    
    def form(self,query,result):
        try:
            result.case_selector()
            result.meta_selector(message='FS Image',case=query['case'],property='fsimage')
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
                columns=('inode','vfsinode','name','address'),
                names=('Inode','VFSInode','Name','Address'),
                table=('contacts_%s' % (tablename)),
                case=query['case']
                )
            return output
        
        def appts(query):
            output = self.ui(result)
            output.table(
                columns=('inode','vfsinode','startdate','enddate','location','comment'),
                names=('Inode','VFSInode','Start Date','End Date','Location','Comment'),
                table=('appointments_%s' % (tablename)),
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
