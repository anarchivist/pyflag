""" This module implements features specific for SMTP Processing """
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.78 Date: Fri Aug 19 00:47:14 EST 2005$
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
import dissect,sys
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import pyflag.Reports as Reports
import pyflag.logging as logging

class SMTPException(Exception):
    """ Raised if line is an invalid SMTP command """

class SMTP:
    """ Class managing the SMTP State """
    def __init__(self,fd,dbh,ddfs):
        self.fd=fd
        self.dbh = dbh
        self.ddfs = ddfs
        self.dispatcher = {
            'EHLO': self.NOOP,
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
        logging.log(logging.VERBOSE_DEBUG,"Set mail from to %s " % self.mail_from)

    def RCPT(self,args):
        self.rcpt_to = args
        self.read_response()
        logging.log(logging.VERBOSE_DEBUG, "Set RCPT to %s" % self.rcpt_to)
        
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
            logging.log(logging.DEBUG,"Message starts at %s in stream and is %s long" % (start,length))
            return (self.count,"%s:%s" % (start,length))

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
            except:
                pass

            tmp = line.split(":")
            command = tmp[0].split(" ")
            try:
                yield(self.dispatcher[command[0].upper()](tmp[-1]))
            except KeyError:
                logging.log(logging.DEBUG,"SMTP Command %r not implemented." % command[0])
        
class SMTPScanner(NetworkScanFactory):
    """ Collect information about SMTP transactions.

    This is an example of a scanner which uses packet dissection, as well as the result of the Stream reassembler.
    """
    default = True
    depends = ['StreamReassembler']

    def prepare(self):
        ## This table simply stores the fact that a certain Inode is
        ## an SMTP String. We deduce this by checking if ethereal
        ## decodes it as such. I guess if we want to parse SMTP
        ## streams which are not on port 25, we need to tell ethereal
        ## this via its config file.
        self.smtp_connections = {}
        try:
            config.SMTP_PORTS[0]
        except:
            config.SMTP_PORTS=[config.SMTP_PORTS]

    class Scan(NetworkScanner):
        def process(self,data,metadata=None):
            NetworkScanner.process(self,data,metadata)
            
            ## Is this an SMTP request?
            if self.proto_tree.is_protocol_to_server("SMTP"):
                self.outer.smtp_connections[metadata['inode']]=1

        def finish(self):
            if not NetworkScanner.finish(self): return
            
            for key in self.outer.smtp_connections.keys():
                forward_stream = key[1:]
                reverse_stream = find_reverse_stream(
                    forward_stream,self.table,self.dbh)
                
                combined_inode = "S%s/%s" % (forward_stream,reverse_stream)

                logging.log(logging.DEBUG,"Openning %s for SMTP" % combined_inode)
                ## We open the file and scan it for emails:
                fd = self.ddfs.open(inode=combined_inode)
                p=SMTP(fd,self.dbh,self.ddfs)

                ## Iterate over all the messages in this connection
                for f in p.parse():
                    if not f: continue

                    ## Create the VFS node:
                    path=self.ddfs.lookup(inode="S%s" % forward_stream)
                    path=os.path.dirname(path)
                    new_inode="%s|o%s" % (combined_inode,f[1])
                    self.ddfs.VFSCreate(None,new_inode,"%s/SMTP/Message_%s" % (path,f[0]))
                    
                    ## Scan the new file using the scanner train. If
                    ## the user chose the RFC2822 scanner, we will be
                    ## able to understand this:
                    self.scan_as_file(new_inode)


