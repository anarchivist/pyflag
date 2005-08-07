""" This module implements features specific for POP Processing """
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.76 Date: Sun Apr 17 21:48:37 EST 2005$
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
import re
from NetworkScanner import *

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
            logging.log(logging.DEBUG,"Login for %s successful with password %s" % (self.username,self.password))

    def STAT(self,args):
        """ We ignore STAT commands """
        response=self.fd.readline()

    def LIST(self,args):
        """ We ignore LIST commands """
        self.read_multi_response()

    def UIDL(self,args):
        self.read_multi_response()

    def RETR(self,args):
        ## Read the first line to see if it has been successful:
        response=self.fd.readline()
        if response.startswith("+OK"):
            start = self.fd.tell()
            data = self.read_multi_response()
            length = len(data)
            logging.log(logging.DEBUG,"Message %s starts at %s in stream and is %s long" % (args[0],start,length))
            self.files.append((args[0],"%s:%s" % (start,length)))
                                                           
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
                raise POPException("Command %r not implemented." % (command))

        return line

class POPScanner(NetworkScanFactory):
    """ Collect information about POP transactions.

    This is an example of a scanner which uses the Ethereal packet dissection, as well as the result of the Stream reassembler.
    """
    default = True
    depends = ['StreamReassembler']

    def prepare(self):
        ## This dict simply stores the fact that a certain Inode is
        ## a POP stream. We deduce this by checking if ethereal
        ## decodes it as such. I guess if we want to parse POP
        ## streams which are not on port 110, we need to tell ethereal
        ## this via its config file.
        self.pop_connections = {}

        ## This table stores common usernames/passwords:
        self.dbh.execute(
            """ CREATE TABLE if not exists `passwords_%s` (
            `inode` VARCHAR(255) NOT NULL,
            `username` VARCHAR(255) NOT NULL,
            `password` VARCHAR(255) NOT NULL,
            `type` VARCHAR(255) NOT NULL
            ) """,(self.table,))
            
    def reset(self):
        self.dbh.execute("delete from passwords_%s where type='POP3'",(self.table,))

    class Scan(NetworkScanner):
        def process(self,data,metadata=None):
            NetworkScanner.process(self,data,metadata)

            ## Is this a POP request?
            try:
                request = self.proto_tree['pop.request'].value()

                self.outer.pop_connections[metadata['inode']]=1
            except KeyError:
                pass

        def finish(self):
            if not NetworkScanner.finish(self): return
            
            for key in self.outer.pop_connections.keys():
                forward_stream = key[1:]
                reverse_stream = find_reverse_stream(
                    forward_stream,self.table,self.dbh)
                
                combined_inode = "S%s/%s" % (forward_stream,reverse_stream)

                ## We open the file and scan it for emails:
                fd = self.ddfs.open(inode=combined_inode)
                p=POP(fd)
                while 1:
                    try:
                        if not p.parse():
                            break
                    except POPException,e:
                        logging.log(logging.DEBUG,"%s" % e)

                for f in p.files:
                    ## Add a new VFS node
                    path=self.ddfs.lookup(inode="S%s" % forward_stream)
                    path=os.path.dirname(path)
                    new_inode="%s|o%s" % (combined_inode,f[1])
                    self.ddfs.VFSCreate(None,new_inode,"%s/POP/Message_%s" % (path,f[0]))

                    ## Scan the new file using the scanner train. If
                    ## the user chose the RFC2822 scanner, we will be
                    ## able to understand this:
                    self.scan_as_file(new_inode)

                ## If there is any authentication information in here,
                ## we save it for Ron:
                if p.username and p.password:
                    self.dbh.execute("insert into passwords_%s set inode=%r,username=%r,password=%r,type='POP3'",(self.table,key,p.username,p.password))
