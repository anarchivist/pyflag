""" This module implements features specific for POP Processing """
# Michael Cohen <scudette@users.sourceforge.net>
# Gavin Jackson <Gavz@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************
import pyflag.conf
config=pyflag.conf.ConfObject()
from pyflag.Scanner import *
import pyflag.Scanner as Scanner
import pyflag.Time as Time
import re, posixpath
from NetworkScanner import *

config.add_option("POP3_PORTS", default='[110,]',
                  help="A list of ports to be considered for POP transactions")

class POPException(Exception):
    """ Raised if line is an invalid pop command """

class POP:
    """ Class managing the pop connection information """
    def __init__(self,fd):
        self.fd=fd
        self.dispatcher={
            "+OK"   :self.NOOP,
            "-ERR"  :self.NOOP,
            "DELE"  :self.NOOP,
            "QUIT"  :self.NOOP,
            }
        self.username=''
        self.password=''
        self.files=[]

    def read_multi_response(self):
        """ Reads the next few lines off fd and returns a combined response """
        result=''
        while 1:
            line = self.fd.readline()
            if not line or line=='.\r\n':
                return result

            ## This cleans out escaped lines as mentioned in the RFC
            if line.startswith('.'): line=line[1:]
            result+=line

    def NOOP(self,args):
        """ A do nothing parser """

    def CAPA(self,args):
        ## We just ignore this
        self.read_multi_response()

    def USER(self,args):
        response=self.fd.readline()
        self.username=args[0]

    def PASS(self,args):
        response=self.fd.readline()
        if response.startswith("+OK"):
            self.password=args[0]
            pyflaglog.log(pyflaglog.DEBUG,"Login for %s successful with password %s" % (self.username,self.password))

    def STAT(self,args):
        """ We ignore STAT commands """
        response=self.fd.readline()

    def LIST(self,args):
        """ We ignore LIST commands """
        self.read_multi_response()

    def UIDL(self,args):
        self.read_multi_response()

    #GJ: We _really_ needed to handle this command 
    def TOP(self,args):
        ## Read the first line to see if it has been successful:
        response=self.fd.readline()
        if response.startswith("+OK"):
            start = self.fd.tell()
            data = self.read_multi_response()
            length = len(data)
            pyflaglog.log(pyflaglog.DEBUG,"Message %s starts at %s in stream and is %s long" % (args[0],start,length))
            self.files.append((args[0],(start,length)))

    def RETR(self,args):
        ## Read the first line to see if it has been successful:
        response=self.fd.readline()
        if response.startswith("+OK"):
            start = self.fd.tell()
            data = self.read_multi_response()
            length = len(data)
            pyflaglog.log(pyflaglog.DEBUG,"Message %s starts at %s in stream and is %s long" % (args[0],start,length))
            self.files.append((args[0],(start,length)))
                                                           
    def parse(self):
        line = self.fd.readline().strip()
        if not line: return 0
        tmp = line.split(" ")
        command=tmp[0]
        args=tmp[1:]
        ## Dispatch the command handler:
        try:
            self.__class__.__dict__[command](self,args)
        except KeyError,e:
            try:
                self.dispatcher[command](args)
            except KeyError:
                raise POPException("POP: Command %r not implemented." % (command))
        except Exception,e:
            raise POPException("POP: Unable to parse line: %s." % (line))

        return line

class EmailTables(FlagFramework.EventHandler):
    def create(self, dbh, case):
        ## This table stores common usernames/passwords:
        dbh.execute(
            """ CREATE TABLE if not exists `passwords` (
            `inode_id` INT,
            `username` VARCHAR(255) NOT NULL,
            `password` VARCHAR(255) NOT NULL,
            `type` VARCHAR(255) NOT NULL
            ) """)        

class POPScanner(StreamScannerFactory):
    """ Collect information about POP transactions.
    """
    default = True
    group = 'NetworkScanner'
    
    def process_stream(self, stream, factories):
        forward_stream, reverse_stream = self.stream_to_server(stream, "POP3")
        if not reverse_stream or not forward_stream: return

        combined_inode = "I%s|S%s/%s" % (stream.fd.name, forward_stream,reverse_stream)
        pyflaglog.log(pyflaglog.DEBUG,"Openning %s for POP3" % combined_inode)

        ## We open the file and scan it for emails:
        fd = self.fsfd.open(inode=combined_inode)
        p=POP(fd)
        while 1:
            try:
                if not p.parse():
                    break
            except POPException,e:
                pyflaglog.log(pyflaglog.DEBUG,"%s" % e)

        for f in p.files:
            ## Add a new VFS node
            offset, length = f[1]
            new_inode="%s|o%s:%s" % (combined_inode,offset, length)

            ds_timestamp = Time.convert(stream.ts_sec, case=self.case, evidence_tz="UTC")
            date_str = ds_timestamp.split(" ")[0]

            path, inode, inode_id = self.fsfd.lookup(inode=combined_inode)
            path=posixpath.normpath(path+"/../../../../../")

            inode_id = self.fsfd.VFSCreate(None,new_inode,
                                           "%s/POP/%s/Message_%s" % (path, date_str,
                                                                     f[0]),
                                           mtime=stream.ts_sec,
                                           size = length
                                           )

            ## Scan the new file using the scanner train. If
            ## the user chose the RFC2822 scanner, we will be
            ## able to understand this:
            self.scan_as_file(new_inode, factories)

        ## If there is any authentication information in here,
        ## we save it for Ron:
        dbh = DB.DBO(self.case)
        if p.username and p.password:
            dbh.execute("insert into passwords set inode_id=%r,username=%r,password=%r,type='POP3'",(
                inode_id, p.username, p.password))

    class Scan(StreamTypeScan):
        types = [ "protocol/x-pop-request" ]

import pyflag.Magic as Magic
class POPRequstStream(Magic.Magic):
    """ Detect POP Request stream """
    type = "POP Request Stream"
    mime = "protocol/x-pop-request"
    default_score = 20

    regex_rules = [
        ## These are the most common pop commands - we look for at least 5 of them:
        ( "CAPA", (0,50)),
        ( "\nUSER ", (0,50)),
        ( "\nPASS ", (0,50)),
        ( "LIST\r\n", (0,50)),
        ( "UIDL\r\n", (0,50)),
        ( "RETR [0-9]+", (0,50)),
        ( "DELE [0-9]+", (0,50))
        ]

    samples = [
        ( 100, \
"""CAPA
USER thadon
PASS password1
CAPA
LIST
UIDL
RETR 1
DELE 1
QUIT
""")]        

class POPResponseStream(Magic.Magic):
    """ Detect POP Response stream """
    type = "POP Response Stream"
    mime = "protocol/x-pop-response"

    default_score = 20
    regex_rules = [
        ( "\n.OK ", (0,500))
        ]

    samples = [
        ( 100, \
"""+OK POP3 mailhost.someisp1.com.au (Version 3.1e-3) http://surgemail.com
+OK Capability list follows
TOP
USER
UIDL
SURGEMAIL
.
+OK scudette@users.sourceforg.net nice to hear from you - password required
+OK scudette      has 1 mail messages
+OK 1 30202
+OK 1 (30202)
""")]

## UnitTests:
import pyflag.tests as tests
import pyflag.pyflagsh as pyflagsh
from pyflag.FileSystem import DBFS

class POPTests(tests.ScannerTest):
    """ Tests POP Scanner """
    test_case = "PyFlagTestCase"
    test_file = "stdcapture_0.4.pcap.e01"
    subsystem = "EWF"
    fstype = "PCAP Filesystem"
    
    order = 21
    def test01SMTPScanner(self):
        """ Test POP Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "POPScanner", "RFC2822",
                                   ])                   ## List of Scanners

        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as total from passwords where type='POP3'")
        row = dbh.fetch()
        self.failIf(row['total']==0,"Could not parse any POP3 passwords")
