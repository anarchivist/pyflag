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

            def insert_into_table(mode,root,name):
                rel_root="/"+root[len(fd.mount_point):]+"/"
                if rel_root=="//": rel_root="/"
                it = pst.getitem(name)
                
                s=os.stat(os.path.join(root,name))
                dbh.execute("insert into file_%s set inode='M%s',mode=%r,status='alloc',path=%r,name=%r",(table, s.st_ino, mode, rel_root, name))
                try:
                    link=os.readlink("%s/%s" % (root,name))
                except OSError:
                    link=''
            
                dbh.execute("insert into inode_%s set inode='M%s',uid=%r,gid=%r, mtime=%r,atime=%r,ctime=%r,mode=%r,links=%r,link=%r,size=%r",(table,s.st_ino,s.st_uid,s.st_gid,s.st_mtime,s.st_atime,s.st_ctime,str(oct(s.st_mode))[1:],s.st_nlink,link,s.st_size))
                
            ## Just walk over all the files and stat them all building the tables.
            for root, dirs, files in pst.walk(pst.rootid):
                for name in dirs:
                    insert_into_table('d/d',root,name)
                for name in files:
                    insert_into_table('r/r',root,name)

            
            ## List all the files in the zip file:
            dircount = 0
            namelist = zip.namelist()
            for i in range(len(namelist)):                
                dirs=namelist[i].split('/')
                for d in range(0, len(dirs)):
                    path='%s/%s' % (filename,'/'.join(dirs[0:d]))
                    if not path.endswith('/'): path=path+'/'
                    self.ddfs.dbh.execute("select * from file_%s where path=%r and name=%r",(self.ddfs.table, path, dirs[d]))
                    if not self.ddfs.dbh.fetch():
                        dircount += 1
                        self.ddfs.dbh.execute("insert into file_%s set path=%r,name=%r,status='alloc',mode='d/d',inode='%s|Zdir%s'",(self.ddfs.table,path,dirs[d],self.inode,dircount))

                ## Add the file itself to the file table:
                self.ddfs.dbh.execute("update file_%s set mode='r/r',inode='%s|Z%s' where path=%r and name=%r",(self.ddfs.table, self.inode, i, path, dirs[-1]))
                
                ## Add the file to the inode table:
                self.ddfs.dbh.execute("insert into inode_%s set inode='%s|Z%s',size=%r,mtime=unix_timestamp('%s-%s-%s:%s:%s:%s')",(self.ddfs.table, self.inode, i, zip.infolist()[i].file_size)+zip.infolist()[i].date_time)

                ## Now call the scanners on this new file (FIXME limit the recursion level here)
                if self.factories:
                    try:
                        data=zip.read(namelist[i])
                    except zipfile.zlib.error:
                        continue
                    
                    objs = [c.Scan("%s|Z%s" % (self.inode, str(i)),self.ddfs,c,factories=self.factories) for c in self.factories]
                    
                    metadata={}
                    for o in objs:
                        try:
                            o.process(data,metadata=metadata)
                            o.finish()
                        except Exception,e:
                            logging.log(logging.ERRORS,"Scanner (%s) Error: %s" %(o,e))

            ## Set the zip file to be a d/d entry so it looks like its a virtual directory:
            self.ddfs.dbh.execute("update file_%s set mode='d/d' where inode=%r",(self.ddfs.table,self.inode))
