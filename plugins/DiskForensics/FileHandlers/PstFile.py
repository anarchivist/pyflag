""" This module adds support for Microsoft Outlook personal file folders (pst files).

There is a scanner which executs the scanner factory train on files within the pst file, such files include email bodies and attachments, contact details, appointments and journal entries.

This feature complements the PST virtual filesystem driver to ensure that pst files are transparently viewable by the FLAG GUI.
"""
import os.path
import pyflag.logging as logging
from pyflag.Scanner import *
import pyflag.Scanner as Scanner
import pypst2
import pyflag.FileSystem as FileSystem
from pyflag.FileSystem import File
import pyflag.Reports as Reports
import StringIO
from pyflag.FlagFramework import normpath

class PstScan(GenScanFactory):
    """ Recurse into Pst Files """
    order=99
    def __init__(self,dbh, table,fsfd):
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
                """ Adds other items than emails (does not process attachments """
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
                        print "Will do %s" % (name,)
                        add_other(name[0],"%s/%s" % (root[1],name[1]),item)

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
