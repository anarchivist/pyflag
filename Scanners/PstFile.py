""" This scanner recurses into Microsoft Outlook personal file folders (pst files), executing the scanner factory train on files within the pst file, such files include email bodies and attachments, contact details, appointments and journal entries.
This feature complements the PST virtual filesystem driver to ensure that pst files are transparently viewable by the FLAG GUI.
"""
import os.path
import pyflag.logging as logging
from Scanners import *
import pypst2

class PstScan(GenScanFactory):
    """ Recurse into Pst Files """
    order=99
    def __init__(self,dbh, table):
        self.dbh=dbh
        self.table=table

    def reset(self):
        pass
        
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

            def scan_item(inode):
                ## call the scanners on this new file (FIXME limit the recursion level here)
                data=item.read()
                if data:
                    objs = [c.Scan(inode, self.ddfs, c, factories=self.factories) for c in self.factories]
                
                    metadata={}
                    for o in objs:
                        try:
                            o.process(data,metadata=metadata)
                            o.finish()
                        except Exception,e:
                            logging.log(logging.ERRORS,"Scanner (%s) Error: %s" %(o,e))               

            def add_email:
                # add a directory entry for the email itself
                dbh.execute("insert into file_%s set inode='%s|P%s',mode='d/d',status='alloc',path=%r,name=%r",(self.ddfs.table, self.inode, name[0], mode, root[1], name[1]))
                dbh.execute("insert into inode_%s set inode='%s|P%s',uid=0,gid=0,mtime=%r,atime=%r,ctime=%r,mode=0,links='',link='',size=0",(table, self.inode, name[0], item.modify_date, item.modify_date, item.create_date))

                # now add body and each attachment
                dbh.execute("insert into file_%s set inode='%s|P%s:0',mode='r/r',status='alloc',path='%s/%s',name='body'",(self.ddfs.table, self.inode, name[0], root[1], name[1]))
                dbh.execute("insert into inode_%s set inode='%s|P%s:0',uid=0,gid=0, mtime=%r,atime=%r,ctime=%r,mode=0,links='',link='',size=%s",(table, self.inode, name[0], time.ctime(item.arrival_date), time.ctime(item.arrival_date), time.ctime(item.sent_date), item.size))
                
                count = 1
                for a in item.attach():
                    if a.filename1:
                        fname = a.filename1
                    elif a.filename2:
                        fname = a.filename2
                    else:
                        fname "attach%i" % count

                    dbh.execute("insert into file_%s set inode='%s|P%s:%s',mode='r/r',status='alloc',path='%s/%s',name=%r",(self.ddfs.table, self.inode, name[0], count, root[1], name[1], fname))
                    dbh.execute("insert into inode_%s set inode='%s|P%s:%s',uid=0,gid=0, mtime=%r,atime=%r,ctime=%r,mode=0,links='',link='',size=%s",(table, self.inode, name[0], count, time.ctime(item.arrival_date), time.ctime(item.arrival_date), time.ctime(item.sent_date), a.size))
                    #scan attachments
                    scan_item('%s|P%s:%s' % (self.inode, name[0], count))
                    count += 1
                #scan body
                scan_item('%s|P%s:0' % (self.inode, name[0]))

            def add_folder:
                dbh.execute("insert into file_%s set inode='%s|P%s',mode='d/d',status='alloc',path=%r,name=%r",(self.ddfs.table, self.inode, name[0], mode, root[1], name[1]))
                dbh.execute("insert into inode_%s set inode='%s|P%s',uid=0,gid=0,mtime=%r,atime=%r,ctime=%r,mode=0,links='',link='',size=0",(table, self.inode, name[0], item.modify_date, item.modify_date, item.create_date))

            def add_other:
                dbh.execute("insert into file_%s set inode='%s|P%s',mode='r/r',status='alloc',path=%r,name=%r",(self.ddfs.table, self.inode, name[0], root[1], name[1]))
                dbh.execute("insert into inode_%s set inode='%s|P%s',uid=0,gid=0, mtime=%r,atime=%r,ctime=%r,mode=0,links='',link='',size=%s",(table, self.inode, name[0], item.modify_date, item.modify_date, item.create_date, item.size))
                #scan body
                scan_item('%s|P%s' % (self.inode, name[0]))
 

            ## Just walk over all the files and stat them all building the tables.
            for root, dirs, files in pst.walk2((pst.rootid, filename)):
                for name in dirs:
                    item = pst.getitem(name[0])
                    add_folder()
                for name in files:
                    item = pst.getitem(name[0])
                    if isinstance(item, pypst2.Pstfile.Email):
                        add_email()
                    else:
                        add_other()

            ## Set the pst file to be a d/d entry so it looks like its a virtual directory:
            self.ddfs.dbh.execute("update file_%s set mode='d/d' where inode=%r",(self.ddfs.table,self.inode))
