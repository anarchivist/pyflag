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

class scan(pyflagsh.command):
    def help(self):
        return "scan inode [list of scanners]: Scans the inodes with the scanners specified"

    def __init__(self, args, environment):
        pyflagsh.command.__init__(self,args,environment)
        self.dbh = DB.DBO(environment._CASE)
        self.case = environment._CASE
        self.ddfs = FileSystem.DBFS(self.case)

    def complete(self, text,state):
        if len(self.args)>2 or len(self.args)==2 and not text:
            scanners = [ x for x in Registry.SCANNERS.scanners if x.startswith(text) ]
            return scanners[state]
        else:
            self.dbh.execute("select  substr(inode,1,%r) as abbrev,inode from inode where inode like '%s%%' group by abbrev limit %s,1",(len(text)+1,text,state))
            return self.dbh.fetch()['inode']
    
    def execute(self):
        print self.args
        if len(self.args)<2:
            yield self.help()
            return

        ## Try to glob the inode list:
        self.dbh.execute("select inode from inode where inode rlike %r",fnmatch.translate(self.args[1]))
        #factories = self.get_factories(self.args[2])
        dbh = DB.DBO()
        dbh.mass_insert_start('jobs')
        scanners = [ '%s:%s' % (self.case, x) for x in fnmatch.filter(Registry.SCANNERS.scanners, self.args[2]) ]
        
        for row in self.dbh:
            inode = row['inode']
            dbh.mass_insert(
                command = 'Scan',
                arg1 = row['inode'],
                arg2 = ','.join(scanners)
                )
            #yield "Scanning %s:" % inode

            #Scanner.scanfile(self.ddfs, self.ddfs.open(inode=inode), factories)

        yield "Scanning complete"

class scanner_reset(scan):
    def help(self):
        return "reset inode [list of scanners]: Resets the inodes with the scanners specified"
    
    def execute(self):
        if len(self.args)<2:
            yield self.help()
            return

        ## Try to glob the inode list:
        self.dbh.execute("select inode from inode where inode rlike %r",fnmatch.translate(self.args[1]))
        scanners = ["%s:%s" % (self.case,x) for x in fnmatch.filter(Registry.SCANNERS.scanners,self.args[2])]
        factories = Scanner.get_factories(scanners)

        for row in self.dbh:
            inode = row['inode']
            Scanner.resetfile(self.ddfs, inode, factories)

        yield "Resetting complete"
    
