""" These Flash commands allow more sophisticated operations, most of
which may not be needed by most users. Some operations are
specifically designed for testing and have little use in practice.
"""
import pyflag.pyflagsh as pyflagsh
import pyflag.Registry as Registry
import pyflag.DB as DB
import fnmatch
import pyflag.FileSystem as FileSystem
import pyflag.Scanner as Scanner
import time, types
import pyflag.pyflaglog as pyflaglog

class scan_path(pyflagsh.command):
    """ This takes a path as an argument and runs the specified scanner on the path
    this might be of more use than specifying inodes for the average user since if you load
    two disk images, then you might have /disk1 and /disk2 and want to just run scans over
    one of them, which is simpler to specify using /disk1. """

    def help(self):
        return "scan VFSPath [list of scanners]: Scans the VFS path with the scanners specified"
    
    def complete(self, text,state):
        if len(self.args)>2 or len(self.args)==2 and not text:
            scanners = [ x for x in Registry.SCANNERS.scanners if x.startswith(text) ]
            return scanners[state]
        else:
            dbh = DB.DBO(self.environment._CASE)
            dbh.execute("select substr(path,1,%r) as abbrev,path from file where path like '%s%%' group by abbrev limit %s,1",(len(text)+1,text,state))
            return dbh.fetch()['path']
        
    def wait_for_scan(self, cookie):
        """ Waits for scanners to complete """
        
        pdbh = DB.DBO()
        pdbh.check_index('jobs','cookie')
        
        ## Often this process owns a worker as well. In that case we can wake it up:
        import pyflag.Farm as Farm
        Farm.wake_workers()
        
        ## Wait until there are no more jobs left.
        while 1:
            pdbh.execute("select count(*) as total from jobs where cookie=%r and arg1=%r",
                         (cookie,
                          self.environment._CASE))
            row = pdbh.fetch()
            if row['total']==0: break
            time.sleep(1)

    def execute(self):
        scanners=[]
                
        if len(self.args)<2:
            yield self.help()
            return
        elif type(self.args[1]) == types.ListType:
            scanners = self.args[1]
        else: 
            for i in range(1,len(self.args)):
                scanners.extend(fnmatch.filter(Registry.SCANNERS.scanners, self.args[i]))

        ## Assume that people always want recursive - I think this makes sense
        path = self.args[0]
        if not path.endswith("*"):
            path = path + "*"
            
        ## FIXME For massive images this should be broken up, as in the old GUI method
        dbh=DB.DBO(self.environment._CASE)
        dbh.execute("select inode.inode from inode join file on file.inode = inode.inode where file.path rlike %r", fnmatch.translate(path))

        pdbh = DB.DBO()
        pdbh.mass_insert_start('jobs')
    
        ## This is a cookie used to identify our requests so that we
        ## can check they have been done later.
        cookie = int(time.time())
            
        for row in dbh:
            inode = row['inode']

            pdbh.mass_insert(
                command = 'Scan',
                arg1 = self.environment._CASE,
                arg2 = row['inode'],
                arg3 = ','.join(scanners),
                cookie=cookie,
                )#
    
        pdbh.mass_insert_commit()
    
        ## Wait for the scanners to finish:
        self.wait_for_scan(cookie)
        
        yield "Scanning complete"

        
class scan(pyflagsh.command):
    """ Scan a glob of inodes with a glob of scanners """
    def help(self):
        return "scan inode [list of scanners]: Scans the inodes with the scanners specified"

    def complete(self, text,state):
        if len(self.args)>2 or len(self.args)==2 and not text:
            scanners = [ x for x in Registry.SCANNERS.scanners if x.startswith(text) ]
            return scanners[state]
        else:
            dbh = DB.DBO(self.environment._CASE)
            dbh.execute("select  substr(inode,1,%r) as abbrev,inode from inode where inode like '%s%%' group by abbrev limit %s,1",(len(text)+1,text,state))
            return dbh.fetch()['inode']
    
    def execute(self):
        if len(self.args)<2:
            yield self.help()
            return

        ## Try to glob the inode list:
        dbh=DB.DBO(self.environment._CASE)
        dbh.execute("select inode from inode where inode rlike %r",fnmatch.translate(self.args[0]))
        pdbh = DB.DBO()
        pdbh.mass_insert_start('jobs')
        ## This is a cookie used to identify our requests so that we
        ## can check they have been done later.
        cookie = int(time.time())
        scanners = []
        for i in range(1,len(self.args)):
            scanners.extend(fnmatch.filter(Registry.SCANNERS.scanners, self.args[i]))

        for row in dbh:
            inode = row['inode']
            pdbh.mass_insert(
                command = 'Scan',
                arg1 = self.environment._CASE,
                arg2 = row['inode'],
                arg3 = ','.join(scanners),
                cookie=cookie,
                )

        pdbh.mass_insert_commit()

        ## Wait for the scanners to finish:
        if self.environment.interactive:
            self.wait_for_scan(cookie)
            
        yield "Scanning complete"

    def wait_for_scan(self, cookie):
        """ Waits for scanners to complete """
        pdbh = DB.DBO()
        ## Often this process owns a worker as well. In that case we can wake it up:
        import pyflag.Farm as Farm
        Farm.wake_workers()
        
        ## Wait until there are no more jobs left.
        while 1:
            pdbh.execute("select count(*) as total from jobs where cookie=%r and arg1=%r", (cookie,
                         self.environment._CASE))
            row = pdbh.fetch()
            if row['total']==0: break

            time.sleep(1)

##
## This allows people to reset based on the VFS path
##
            
class scanner_reset_path(scan):
    """ Reset all files under a specified path """
    def help(self):
        return "scanner_reset_path path [list of scanners]: Resets the inodes under the path given with the scanners specified"

    def execute(self):
        if len(self.args)<2:
            yield self.help()
            return

        scanners = []
        
        if type(self.args[1]) == types.ListType:
            scanners = self.args[1]
        else:
            for i in range(1,len(self.args)):
                scanners.extend(fnmatch.filter(Registry.SCANNERS.scanners, self.args[i]))
        print "GETTING FACTORIES"
        factories = Scanner.get_factories(self.environment._CASE, scanners)
        print "OK NOW RESETING EM"
        for f in factories:
                    f.reset_entire_path(self.args[0])
        print "HOKAY"
        yield "Reset Complete"

## There is little point in distributing this because its very quick anyway.
class scanner_reset(scan):
    """ Reset multiple inodes as specified by a glob """
    def help(self):
        return "reset inode [list of scanners]: Resets the inodes with the scanners specified"
    
    def execute(self):
        if len(self.args)<2:
            yield self.help()
            return

        scanners = []
        for i in range(1,len(self.args)):
            scanners.extend(fnmatch.filter(Registry.SCANNERS.scanners, self.args[i]))

        factories = Scanner.get_factories(self.environment._CASE, scanners)

        for f in factories:
            f.multiple_inode_reset(self.args[0])
            
        yield "Resetting complete"
    
class load_and_scan(scan):
    """ Load a filesystem and scan it at the same time """
    def help(self):
        return """load_and_scan iosource mount_point fstype [list of scanners]:

        Loads the iosource into the right mount point and scans all
        new inodes using the scanner list. This allows scanning to
        start as soon as VFS inodes are produced and before the VFS is
        fully populated.
        """
    def complete(self, text,state):
        if len(self.args)>4 or len(self.args)==4 and not text:
            scanners = [ x for x in Registry.SCANNERS.scanners if x.startswith(text) ]
            return scanners[state]
        elif len(self.args)>3 or len(self.args)==3 and not text:
            fstypes = [ x for x in Registry.FILESYSTEMS.class_names if x.startswith(text) ]
            return fstypes[state]
        elif len(self.args)>2 or len(self.args)==2 and not text:
            return 
        elif len(self.args)>1 or len(self.args)==1 and not text:
            dbh = DB.DBO(self.environment._CASE)
            dbh.execute("select substr(value,1,%r) as abbrev,value from meta where property='iosource' and value like '%s%%' group by abbrev limit %s,1",(len(text)+1,text,state))
            return dbh.fetch()['value']
    
    def execute(self):
        if len(self.args)<3:
            yield self.help()
            return

        iosource=self.args[0]
        mnt_point=self.args[1]
        filesystem=self.args[2]

        dbh = DB.DBO()
        dbh.mass_insert_start('jobs')
        ## This works out all the scanners that were specified:
        tmp = []
        for i in range(3,len(self.args)):
            tmp.extend([x for x in fnmatch.filter(
                Registry.SCANNERS.scanners, self.args[i]) ])


        scanners = [ ]
        for item in tmp:
            if item not in scanners:
                scanners.append(item)

        ## Load the filesystem:
        try:
            fs = Registry.FILESYSTEMS.dispatch(filesystem)
        except KeyError:
            yield "Unable to find a filesystem of %s" % filesystem
            return

        fs=fs(self.environment._CASE)
        fs.cookie = int(time.time())
        fs.load(mnt_point, iosource, scanners)

        ## Wait for all the scanners to finish
        self.wait_for_scan(fs.cookie)
        
        yield "Loading complete"
