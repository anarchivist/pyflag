""" This module adds support for Microsoft Outlook personal file folders (pst files).

There is a scanner which executs the scanner factory train on files within the pst file, such files include email bodies and attachments, contact details, appointments and journal entries.

This feature complements the PST virtual filesystem driver to ensure that pst files are transparently viewable by the FLAG GUI.
"""
import os.path
import pyflag.logging as logging
from pyflag.Scanner import *
import pypst2
import pyflag.FileSystem as FileSystem
from pyflag.FileSystem import File
import pyflag.Reports as Reports

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

            def scan_item(inode,item):
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

            def add_email():
                # add a directory entry for the email itself
                self.ddfs.dbh.execute("insert into file_%s set inode='%s|P%s',mode='d/d',status='alloc',path=%r,name=%r",(self.table, self.inode, name[0], root[1]+'/', name[1]))
                self.ddfs.dbh.execute("insert into inode_%s set inode='%s|P%s',uid=0,gid=0,mtime=%r,atime=%r,ctime=%r,mode=0,links='',link='',size=0",(self.table, self.inode, name[0], item.modify_date, item.modify_date, item.create_date))

                # now add body and each attachment
                self.ddfs.dbh.execute("insert into file_%s set inode='%s|P%s:0',mode='r/r',status='alloc',path='%s/%s',name='body'",(self.table, self.inode, name[0], root[1], name[1]+'/'))
                self.ddfs.dbh.execute("insert into inode_%s set inode='%s|P%s:0',uid=0,gid=0, mtime=%r,atime=%r,ctime=%r,mode=0,links='',link='',size=%s",(self.table, self.inode, name[0], item.arrival_date, item.arrival_date, item.sent_date, item.size))
                
                count = 1
                for a in item.attach():
                    if a.filename1:
                        fname = a.filename1
                    elif a.filename2:
                        fname = a.filename2
                    else:
                        fname = "attach%i" % count

                    self.ddfs.dbh.execute("insert into file_%s set inode='%s|P%s:%s',mode='r/r',status='alloc',path='%s/%s',name=%r",(self.ddfs.table, self.inode, name[0], count, root[1], name[1]+'/', fname))
                    self.ddfs.dbh.execute("insert into inode_%s set inode='%s|P%s:%s',uid=0,gid=0, mtime=%r,atime=%r,ctime=%r,mode=0,links='',link='',size=%s",(self.table, self.inode, name[0], count, item.arrival_date, item.arrival_date, item.sent_date, a.size))
                    #scan attachments
                    scan_item('%s|P%s:%s' % (self.inode, name[0], count),a)
                    count += 1
                    
                #scan body
                scan_item('%s|P%s:0' % (self.inode, name[0]),item)

            def add_folder():
                self.ddfs.dbh.execute("insert into file_%s set inode='%s|P%s',mode='d/d',status='alloc',path=%r,name=%r",(self.table, self.inode, name[0], root[1]+'/', name[1]))
                self.ddfs.dbh.execute("insert into inode_%s set inode='%s|P%s',uid=0,gid=0,mtime=%r,atime=%r,ctime=%r,mode=0,links='',link='',size=0",(self.table, self.inode, name[0], item.modify_date, item.modify_date, item.create_date))

            def add_other():
                self.ddfs.dbh.execute("insert into file_%s set inode='%s|P%s',mode='r/r',status='alloc',path=%r,name=%r",(self.table, self.inode, name[0], root[1]+'/', name[1]))
                self.ddfs.dbh.execute("insert into inode_%s set inode='%s|P%s',uid=0,gid=0, mtime=%r,atime=%r,ctime=%r,mode=0,links='',link='',size=%s",(self.table, self.inode, name[0], item.modify_date, item.modify_date, item.create_date, item.size))
                #scan body
                scan_item('%s|P%s' % (self.inode, name[0]),item)
 

            ## Just walk over all the files
            for root, dirs, files in pst.walk((pst.rootid, filename)):
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
            #self.ddfs.dbh.execute("update file_%s set mode='d/d' where inode=%r",(self.ddfs.table,self.inode))
            self.ddfs.dbh.execute("select * from file_%s where mode='r/r' and inode=%r order by status",(self.table,self.inode))
            row=self.ddfs.dbh.fetch()
            self.ddfs.dbh.execute("insert into file_%s set mode='d/d',inode=%r,status=%r,path=%r,name=%r",(self.table,self.inode,row['status'],row['path'],row['name']))

## The correspoding VFS module:
class Pst_file(File):
    """ A file like object to read items from within pst files. The pst file is specified as an inode in the DBFS """
    specifier = 'P'
    blocks=()
    size=None
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)
        # strategy:
        # cache whole of file in 'fd' to disk
        # load into pypst2
        # split inode into item_id and attachment number (if any)
        # retrieve item using item_id
        # if attachment, retrieve attachment from item using attachment number
        # set self.data to either attachment or item
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
