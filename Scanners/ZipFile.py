""" This scanner recurses into zip files, executing the scanner factory train on files within the ZIP file.

This feature complements the ZIP filesystem driver to ensure that zip files are transparently viewable by the FLAG GUI.
"""
import os.path
import pyflag.logging as logging
from Scanners import *
import zipfile

class ZipScan(GenScanFactory):
    """ Recurse into Zip Files """
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
                'application/x-zip',
                )

        def external_process(self,name):
            """ This is run on the extracted file """
            zip=zipfile.ZipFile(name)

            ## filename is the filename in the filesystem for the zip file.
            filename = self.ddfs.lookup(inode=self.inode)
            
            ## List all the files in the zip file:
            dircount = 0
            list = zip.namelist()
            for i in range(len(list)):                
                dirs=list[i].split('/')
                for d in range(0,len(dirs)):
                    path='%s/%s' % (filename,'/'.join(dirs[0:d]))
                    if not path.endswith('/'): path=path+'/'

                    self.ddfs.dbh.execute("select * from file_%s where path=%r and name=%r",(self.ddfs.table,path,dirs[d]))
                    if not self.ddfs.dbh.fetch():
                        dircount+=1
                        self.ddfs.dbh.execute("insert into file_%s set path=%r,name=%r,status='alloc',mode='d/d',inode='%s|Zdir%i'",(self.ddfs.table,path,dirs[d],self.inode,dircount))

                ## Add the file itself to the file table:
                self.ddfs.dbh.execute("update file_%s set mode='r/r',inode='%s|Z%i' where path=%r and name=%r",(self.ddfs.table,self.inode,i,path,dirs[-1]))
                
                ## Add the file to the inode table:
                self.ddfs.dbh.execute("insert into inode_%s set inode='%s|Z%i',size=%r,mtime=unix_timestamp('%s-%s-%s:%s:%s:%s')",(self.ddfs.table,self.inode,i,zip.infolist[i].file_size)+zip.infolist[i].date_time)

                ## Now call the scanners on this new file (FIXME limit the recursion level here)
                if self.factories:
                    try:
                        data=zip.read(zip.namelist[i])
                    except zipfile.zlib.error:
                        continue
                    
                    objs = [c.Scan("%s|Z%i" % (self.inode,i),self.ddfs,c,factories=self.factories) for c in self.factories]
                    
                    metadata={}
                    for o in objs:
                        try:
                            o.process(data,metadata=metadata)
                            o.finish()
                        except Exception,e:
                            logging.log(logging.ERRORS,"Scanner (%s) Error: %s" %(o,e))

            ## Set the zip file to be a d/d entry so it looks like its a virtual directory:
            self.ddfs.dbh.execute("update file_%s set mode='d/d' where inode=%r",(self.ddfs.table,self.inode))
