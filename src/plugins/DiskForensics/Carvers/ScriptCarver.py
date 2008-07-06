""" This carver is used to find scripts embedded in e.g. memory images.

Its quite simple, we search for the script header #!/usr/bin/python
for example, then just scan the rest for ascii chars.
"""
import JPEGCarver
import pyflag.DB as DB
import re

class ScriptCarver(JPEGCarver.JPEGCarver):
    """ Scan for interpreted scripts """
    default = True
    depends = 'IndexScan'
    group = "Carvers"
    regexs = [ '#!/usr/bin/', '#!/bin/']
    ids = []

    class Scan(JPEGCarver.CarverScan):
        def examine_hit(self, fd, offset, length):
            ## We only carve files
            if offset==0: return
            
            fd.seek(offset)
            ## Scripts are usually small so we limit ourselves to 10k
            data = fd.read(100000)
            lines = data.splitlines()
            m = re.match("#!/(usr/)?bin/([^\n]+)", lines[0])
            interpreter = m.group(2)
            possibles = {'bash':'sh',
                         'sh':'sh',
                         'perl':'pl',
                         'python':"py",}

            found = False
            for p in possibles.keys():
                if interpreter.startswith(p):
                    found = True
                    self.extension = possibles[p]
                    self.mime = "application/x-%s-script" % p
                    self.type = "%s Script" % p
                    break
                
            if not found: return

            self.len = 0

            for line in lines:
                if len(line)>0 and re.search("[\x00-\x08\x80-\xff]", line):
                    break
                self.len += len(line)+1

            ## We only carver scripts which are longer than a few
            ## lines
            if self.len > 300:
                print "Found script for %s in %s" % (p,offset)
                self.add_inode(fd, offset)

        def make_filename(self, offset):
            return "%s.%s" % (offset, self.extension)
                    
        def get_length(self, fd, offset):
            print "Length is %s" % self.len
            return self.len

        def add_type_info(self, inode_id):
            dbh = DB.DBO(self.fd.case)
            dbh.insert('type',
                       inode_id = inode_id,
                       mime = self.mime,
                       type = self.type,
                       )

JPEGCarver.ensure_carver_signatures_in_dictionary(ScriptCarver)

import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class ScriptCarverTest(pyflag.tests.ScannerTest):
    """ Script Carver tests """
    test_case = "PyFlagIndexTestCase"
    test_file = "pyflag_stdimage_0.5.dd"
    #test_file = "response_data/challenge.mem"
    subsystem = 'Standard'
    fstype = "Raw"
    order = 30
    offset = "0"
    
    def test01CarveImage(self):
        """ Carving from Image """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'ScriptCarver'])

        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as c from type where type like %r", "%script")
        row = dbh.fetch()
        self.assert_(row != None)
        self.assert_(row['c']>=3)
