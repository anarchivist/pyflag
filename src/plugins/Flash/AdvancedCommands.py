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
import time

class scan(pyflagsh.command):
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
        self.wait_for_scan(cookie)            
        yield "Scanning complete"

    def wait_for_scan(self, cookie):
        """ Waits for scanners to complete """
        pdbh = DB.DBO()
        ## Often this process owns a worker as well. In that case we can wake it up:
        import pyflag.Farm as Farm
        Farm.wake_workers()
        
        ## Wait until there are no more jobs left. FIXME: this is a
        ## short cut, we should probably only wait for our own jobs to
        ## finish. Maybe we need to add a cookie field to the jobs
        ## table so we can easily find our own jobs only.
        while 1:
            pdbh.execute("select count(*) as total from jobs where cookie=%r and arg1=%r", (cookie,
                         self.environment._CASE))
            row = pdbh.fetch()
            if row['total']==0: break

            time.sleep(1)

## There is little point in distributing this because its very quick anyway.
class scanner_reset(scan):
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

        ddfs = FileSystem.DBFS(self.environment._CASE)

        ## Try to glob the inode list:
        dbh = DB.DBO(self.environment._CASE)
        dbh.execute("select inode from inode where inode rlike %r",fnmatch.translate(self.args[0]))

        for row in dbh:
            inode = row['inode']
            Scanner.resetfile(ddfs, inode, factories)

        yield "Resetting complete"
    
class load_and_scan(scan):
    def help(self):
        return "load_and_scan iosource fstype mount_point [list of scanners]: Loads the iosource into the right mount point and scans all new inodes using the scanner list. This allows scanning to start as soon as VFS inodes are produced and before the VFS is fully populated."

    def complete(self, text,state):
        if len(self.args)>4 or len(self.args)==4 and not text:
            scanners = [ x for x in Registry.SCANNERS.scanners if x.startswith(text) ]
            return scanners[state]
        elif len(self.args)>3 or len(self.args)==3 and not text:
            fstypes = [ x for x in Registry.FILESYSTEMS.fs.keys() if x.startswith(text) ]
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
            fs = Registry.FILESYSTEMS.fs[filesystem]
        except KeyError:
            yield "Unable to find a filesystem of %s" % filesystem
            return

        fs=fs(self.environment._CASE)
        fs.cookie = int(time.time())
        fs.load(mnt_point, iosource, scanners)

        ## Wait for all the scanners to finish
        self.wait_for_scan(fs.cookie)
        
        yield "Loading complete"
