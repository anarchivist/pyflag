""" This module implements processing for MSN Instant messager traffic """
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
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import pyflag.Reports as Reports

class message:
    """ A class representing the message """
    def __init__(self,fp, dbh,table,fd):
        self.fp=fp
        self.dbh=dbh
        self.table=table
        self.fd=fd

    def parse(self):
        """ We parse the first message from the file like object in
        fp, thereby consuming it"""
        
        # Read the first command:
        self.cmdline=self.fp.readline()
        if len(self.cmdline)==0: raise IOError("Unable to command from stream")

        try:
            self.cmd = self.cmdline.split()[0]
        except IndexError:
            return ''

        ## Dispatch the command handler
        try:
            return getattr(self,self.cmd)()
        except AttributeError:
            return None
#            return "Oops, command %s not understood" % self.cmdline
        
    def get_data(self):
        return "\n      ".join(self.msg_array[self.header_offset:])

    def NLN(self):
        """ Notifies Client when users go offline or online state changes """
        print "NLN changed"

    def parse_mime(self):
        """ Parse the contents of the headers """
        words = self.cmdline.split()
        self.length = int(words[-1])
        self.offset = self.fp.tell()
        data = self.fp.read(self.length)
        self.headers = {}
        
        self.msg_array = data.splitlines()
        ## This is the offset after which the data starts and before which
        ## the headers start
        self.header_offset = len(self.msg_array)
        for i in range(len(self.msg_array)):
            if len(self.msg_array[i])==0:
                self.header_offset=i
                break
            
            try:
                header,value = self.msg_array[i].split(":")
                self.headers[header.lower()]=value.lower().strip()
            except ValueError:
                pass
            
    def MSG(self):
        """ Sends message to members of the current session

        There are two types of messages that may be sent:
        1) A message from the client to the message server. This does not contain the nick of the client, but does contain a transaction ID.
        2) A message from the Switchboard server to the client contains the nick of the sender.

        These two commands are totally different.
        """
        ## Read the data for this MSG:
        self.parse_mime()
        words = self.cmdline.split()
        try:
            ## If the second word is a transaction id (int) its a message from client to server
            int(words[1])
            sender = "Client"
            friendly_sender = "Implied Client Machine"
        except ValueError:
            sender = words[1]
            friendly_sender = words[2]

        try:
            content_type = self.headers['content-type']
        except:
            content_type = "unknown/unknown"

        ## Now we try to find the time stamp of this request:
        packet_id = self.fp.get_packet_id(position=self.offset)
        self.dbh.execute("select ts_sec from pcap_%s where id = %s "
                         ,(self.table,packet_id))
        row = self.dbh.fetch()
        timestamp = row['ts_sec']

        self.dbh.execute(""" insert into msn_messages_%s set sender=%r,friendly_name=%r,
        inode=%r, packet_id=%r, content_type=%r, data=%r, ts_sec=%r
        """,(
            self.table,sender,friendly_sender,self.fp.inode, packet_id,
            content_type,self.get_data(), timestamp
            ))
            
    def OUT(self):
        """ Ends a session """
        print "Ended session"

def parse_msg(data):
    """ Parses a message out of data """
    fp = cStringIO.StringIO(data)
    m = message(fp)
    while 1:
        try:
            result = m.parse()
            if result:
                print result
        except IOError:
            break

    return result

class MSNScanner(NetworkScanFactory):
    """ Collect information about MSN Instant messanger traffic """
    default = True

    def prepare(self):
        self.dbh.execute(
            """CREATE TABLE if not exists `msn_messages_%s` (
            `sender` VARCHAR( 250 ) NOT NULL ,
            `friendly_name` VARCHAR( 255 ) NOT NULL ,
            `content_type` VARCHAR( 50 ) NOT NULL ,
            `inode` VARCHAR(50) NOT NULL,
            `packet_id` INT,
            `ts_sec` int(11),
            `data` TEXT NOT NULL
            )""",(self.table,))
        self.msn_connections = {}

    class Scan(NetworkScanner):
        def process(self,data,metadata=None):
            NetworkScanner.process(self,data,metadata)
            
            ## Is this an MSN packet bound to the server?
            try:
                request = self.proto_tree['msnms']
                dest_port = self.proto_tree['tcp.dstport'].value()

                if dest_port==1863:
                    self.outer.msn_connections[metadata['inode']]=1
            except KeyError:
                pass

        def finish(self):
            for key in self.outer.msn_connections.keys():
                forward_stream = key[1:]

                reverse_stream = find_reverse_stream(
                    forward_stream,self.table,self.dbh)

                if reverse_stream:
                    combined_inode = "S%s/%s" % (forward_stream,reverse_stream)
                else:
                    combined_inode = "S%s" % (forward_stream)
                    
                logging.log(logging.DEBUG,"Openning %s for MSN Scanner" % combined_inode)
                ## We open the file and scan it for emails:
                fd = self.ddfs.open(inode=combined_inode)
                m=message(fd,self.dbh,self.table,fd)
                while 1:
                    try:
                        result=m.parse()
                    except IOError:
                        break        

class BrowseMSNChat(Reports.report):
    """ This allows MSN chat messages to be browsed. """
    parameters = { 'fsimage':'fsimage' }
    name = "Browse MSN Chat"
    family = "Network Forensics"
    def form(self,query,result):
        try:
            result.case_selector()
            result.meta_selector(case=query['case'],property='fsimage')
        except KeyError:
            pass

    def display(self,query,result):
        result.heading("MSN Chat sessions in %s " % query['fsimage'])
        result.table(
            columns = [ 'from_unixtime(ts_sec)','packet_id','sender','data'],
            names = ['Time Stamp','Packet','Sender Nick','Text'],
            table = "msn_messages_%s" % query['fsimage'],
            where = "content_type like 'text/plain%' ",
            links = [None,
                     FlagFramework.query_type((),
                                              family="Network Forensics", case=query['case'],
                                              report='View Packet', fsimage=query['fsimage'],
                                              __target__='id')],
            case = query['case']
            )

if __name__ == "__main__":
    fd = open("/tmp/case_demo/S93-94")
    data = fd.read()
    parse_msg(data)
