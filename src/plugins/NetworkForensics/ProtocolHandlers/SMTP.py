""" This module implements features specific for SMTP Processing """
# Michael Cohen <scudette@users.sourceforge.net>
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
import dissect,sys, posixpath
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import pyflag.Reports as Reports
import pyflag.pyflaglog as pyflaglog
import pyflag.Time as Time

config.add_option("SMTP_PORTS", default="[25,]",
                  help="A list of ports to be considered for SMTP transactions")

class SMTPException(Exception):
    """ Raised if line is an invalid SMTP command """

class SMTP:
    """ Class managing the SMTP State """
    def __init__(self,fd,dbh,ddfs):
        self.fd=fd
        self.ddfs = ddfs
        self.dispatcher = {
            'EHLO': self.NOOP,
            'HELO': self.NOOP,
            'MAIL': self.MAIL,
            'RCPT': self.RCPT,
            'DATA': self.DATA,
            'QUIT': self.NOOP,
            }
        self.mail_from = ''
        self.rcpt_to = []
        self.count=0

    def read_response(self):
        """ This reads the SMTP responses. SMTP is a little nicer than
        POP because we know when a multiline response is finished (by
        the presence of a code followed by space).
        """
        result = ''
        while 1:
            line = self.fd.readline()
            result+=line
            ## Responses with a space after the error code signify end
            ## of response:
            if line[3]==' ':
                return result

            try:
                int(line[:3])
            except:
                raise SMTPException("Invalid response %r" % line)

    def NOOP(self,args):
        self.read_response()

    def MAIL(self,args):
        self.mail_from = args
        self.read_response()
        pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Set mail from to %s " % self.mail_from)

    def RCPT(self,args):
        self.rcpt_to = args
        self.read_response()
        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Set RCPT to %s" % self.rcpt_to)
        
    def DATA(self,args):
        result=self.read_response()
        if result[0]=='3':
            start = self.fd.tell()
            while 1:
                line = self.fd.readline()
                if not line or line=='.\r\n':
                    break
                
            end = self.fd.tell()
            length = end-start
            self.count += 1
            pyflaglog.log(pyflaglog.DEBUG,"Message starts at %s in stream and is %s long" % (start,length))
            return self.count, start, length

    def parse(self):
        while 1:
            line = self.fd.readline().strip()

            ## Stop iteration if we are at the end
            if line=='':
                return

            ## If the line has an error code at the start, we are looking
            ## at a response.
            try:
                int(line[:3])
                continue
            except:                pass

            tmp = line.split(":")
            command = tmp[0].split(" ")
            try:
                yield(self.dispatcher[command[0].upper()](tmp[-1]))
            except KeyError:
                pyflaglog.log(pyflaglog.DEBUG,"SMTP Command %r not implemented." % command[0])
        
class SMTPScanner(StreamScannerFactory):
    """ Collect information about SMTP transactions.

    This is an example of a scanner which uses packet dissection, as well as the result of the Stream reassembler.
    """
    default = True
    group = 'NetworkScanners'

    def process_stream(self, stream, factories):
        combined_inode = "I%s|S%s/%s" % (stream.fd.name, stream.inode_id, stream.reverse)
        pyflaglog.log(pyflaglog.DEBUG,"Openning %s for SMTP" % combined_inode)

        ## We open the file and scan it for emails:
        fd = self.fsfd.open(inode=combined_inode)
        dbh=DB.DBO(self.case)
        p=SMTP(fd,dbh,self.fsfd)
        
        ## Iterate over all the messages in this connection
        for f in p.parse():
            if not f: continue

            ## message number and its offset:
            count, offset, length = f
            
            ## Create the VFS node:
            path, combined_inode, inode_id =self.fsfd.lookup(inode=combined_inode)
            path=posixpath.normpath(path+"/../../../../../")
            new_inode="%s|o%s:%s" % (combined_inode,offset,length)
            ds_timestamp = Time.convert(stream.ts_sec, case=self.case, evidence_tz="UTC")
            date_str = ds_timestamp.split(" ")[0]

            self.fsfd.VFSCreate(None, new_inode,
                                "%s/SMTP/%s/Message_%s" % (path,
                                                           date_str,
                                                           count),
                                mtime = stream.ts_sec, size=length
                                )
            
            ## Scan the new file using the scanner train. If
            ## the user chose the RFC2822 scanner, we will be
            ## able to understand this:
            self.scan_as_file(new_inode, factories)

    class Scan(StreamTypeScan):
        types = ["protocol/x-smtp-request"]

import pyflag.Magic as Magic
class SMTPRequestMagic(Magic.Magic):
    """ Detect SMTP request stream """
    type = "SMTP Request Stream"
    mime = "protocol/x-smtp-request"
    default_score = 25
    literal_rules = [
        ( "ehlo ", (0,10)),
        ( "\nmail from:", (0,500)),
        ( "\nrcpt to:", (0,500)),
        ( "\ndata", (0,500))
        ]

    samples = [
        ( 100, \
"""EHLO [192.168.1.34]
MAIL FROM:<scudette@users.sourceforge.net> SIZE=147450
RCPT TO:<scudette@users.sourceforge.net>
DATA
Message-ID: <42BE76A2.8090608@users.sourceforge.net>
Date: Sun, 26 Jun 2005 19:34:26 +1000
From: scudette <scudette@users.sourceforge.net>
User-Agent: Debian Thunderbird 1.0.2 (X11/20050602)
X-Accept-Language: en-us, en
""")]
    
## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
from pyflag.FileSystem import DBFS
import pyflag.tests 

class SMTPTests(pyflag.tests.ScannerTest):
    """ Tests SMTP Scanner """
    test_case = "PyFlagTestCase"
    test_file = "stdcapture_0.3.pcap"
    subsystem = "Advanced"
    fstype = "PCAP Filesystem"
    order = 21
    def test01SMTPScanner(self):
        """ Test SMTP Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "SMTPScanner", "RFC2822", "TypeScan"
                                   ])                   ## List of Scanners
