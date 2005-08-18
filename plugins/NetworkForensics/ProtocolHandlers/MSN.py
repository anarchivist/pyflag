""" This module implements processing for MSN Instant messager traffic

Most of the information for this protocol was taken from:
http://www.hypothetic.org/docs/msn/ietf_draft.txt
http://www.hypothetic.org/docs/msn/client/file_transfer.php
http://www.hypothetic.org/docs/msn/notification/authentication.php

"""
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
from pyflag.FileSystem import CachedFile
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import pyflag.Reports as Reports
import pyflag.logging as logging
import base64
import plugins.NetworkForensics.PCAPFS as PCAPFS

def safe_base64_decode(s):
    """ This attempts to decode the string s, even if it has incorrect padding """
    tmp = s
    for i in range(1,5):
        try:
            return base64.decodestring(tmp)
        except:
            tmp=tmp[:-i]
            continue

    return s

allowed_file_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_ "

def get_temp_path(case,inode):
    """ Returns the full path to a temporary file based on filename.
    """
    filename = inode.replace('/','-')
    result= "%s/case_%s/%s" % (config.RESULTDIR,case,filename)
    return result

class message:
    """ A class representing the message """
    def __init__(self,dbh,table,fd,ddfs):
        self.dbh=dbh
        self.table=table
        self.fd=fd
        self.ddfs = ddfs
        self.client_id=''
        self.session_id = -1

    def parse(self):
        """ We parse the first message from the file like object in
        fp, thereby consuming it"""
        
        # Read the first command:
        self.cmdline=self.fd.readline()
        if len(self.cmdline)==0: raise IOError("Unable to command from stream")

        try:
            ## We take the last 3 letters of the line as the
            ## command. If we lose sync at some point, readline will
            ## resync up to the next command automatically
            self.cmd = self.cmdline.split()[0][-3:]

            ## All commands are in upper case - if they are not we
            ## must have lost sync:
            if self.cmd != self.cmd.upper() or not self.cmd.isalpha(): return None
        except IndexError:
            return ''

        ## Dispatch the command handler
        try:
            return getattr(self,self.cmd)()
        except AttributeError,e:
            logging.log(logging.VERBOSE_DEBUG,"Unable to handle command %r from line %s (%s)" % (self.cmd,self.cmdline.split()[0],e))
            return None

    def get_data(self):
        return self.data

    def parse_mime(self):
        """ Parse the contents of the headers """
        words = self.cmdline.split()
        self.length = int(words[-1])
        self.offset = self.fd.tell()
        self.headers = {}
        ## Read the headers:
        while 1:
            line = self.fd.readline()
            if line =='\r\n': break
            try:
                header,value = line.split(":")
                self.headers[header.lower()]=value.lower().strip()
            except ValueError:
                pass

        current_position = self.fd.tell()
        self.data = self.fd.read(self.length-(current_position-self.offset))

    def ANS(self):
        """ Logs into the Switchboard session.

        We use this to store the current session ID for the entire TCP connection.
        """
        words = self.cmdline.split()
        try:
            self.session_id = int(words[-1])
            self.dbh.execute("insert into msn_session_%s set id=%r, user=%r",
                             (self.table,self.session_id, words[2]))
            ## This stores the current clients username
            self.client_id = words[2]
            logging.log(logging.DEBUG, "MSN: %s has logged into a session id %s" % (words[2],self.session_id))
        except: pass

    def IRO(self):
        words = self.cmdline.split()
        self.dbh.execute("insert into msn_session_%s set id=%r, user=%r",
                         (self.table,self.session_id, words[4]))

    def JOI(self):
        words = self.cmdline.split()
        self.dbh.execute("insert into msn_session_%s set id=%r, user=%r",
                         (self.table,self.session_id, words[1]))
                         
    def plain_handler(self,content_type,sender,friendly_sender):
        """ A handler for content type text/plain """
        ## Try to find the time stamp of this request:
        packet_id = self.fd.get_packet_id(position=self.offset)
        self.dbh.execute("select ts_sec from pcap_%s where id = %s "
                         ,(self.table,packet_id))
        row = self.dbh.fetch()
        timestamp = row['ts_sec']

        self.dbh.execute(""" insert into msn_messages_%s set sender=%r,friendly_name=%r,
        inode=%r, packet_id=%r, data=%r, ts_sec=%r, session=%r
        """,(
            self.table,sender,friendly_sender,self.fd.inode, packet_id,
            self.get_data(), timestamp, self.session_id
            ))

    def p2p_handler(self,content_type,sender,friendly_sender):
        """ Handle a p2p transfer """
        data = self.get_data()
        ## Now we break out the header:
        ( channel_sid, id, offset, total_data_size, message_size ) = struct.unpack(
            "IIQQI",data[:4+4+8+8+4])

        ## MSN header is 48 bytes long
        data = data[48:48+message_size]
        
        ## When channel session id is 0 we are negotiating a transfer
        ## channel
        if channel_sid==0:
            fd = cStringIO.StringIO(data)
            request_type=fd.readline()
            if request_type.startswith("INVITE"):
                ## We parse out the invite headers here:
                headers = {}
                while 1:
                    line = fd.readline()
                    if not line: break
                    tmp = line.find(":")
                    key,value = line[:tmp],line[tmp+1:]
                    headers[key.lower()]=value.strip()

                context = safe_base64_decode(headers['context'])

                self.dbh.execute("insert into msn_p2p_%s set session_id = %r, channel_id = %r, to_user= %r, from_user= %r, context=%r",
                                 (self.table,self.session_id,headers['sessionid'],
                                  headers['to'],headers['from'],context))

                ## Add a VFS entry for this file:
                path=self.ddfs.lookup(inode=self.fd.inode)
                path=os.path.dirname(path)
                new_inode = "CMSN%s-%s" % (headers['sessionid'],self.session_id)
                try:
                ## Parse the context line:
                    parser = ContextParser()
                    parser.feed(context)
                    filename = parser.context_meta_data['location']
                    size=parser.context_meta_data['size']
                    if len(filename)<1: raise IOError
                except:
                    ## If the context line is not a valid xml line, we
                    ## just make a filename off its printables.
                    filename = ''.join([ a for a in context if a in allowed_file_chars ])
                    size=0
                
                ## The filename and size is given in the context
                self.ddfs.VFSCreate(None,new_inode, "%s/MSN/%s" %
                                    (path,filename) ,
                                    size=size)

        ## We have a real channel id so this is an actual file:
        else:
            filename = get_temp_path(self.dbh.case,"MSN%s-%s" % (channel_sid,self.session_id))
            fd=os.open(filename,os.O_RDWR | os.O_CREAT)
            os.lseek(fd,offset,0)
            bytes = os.write(fd,data)
            if bytes <message_size:
                logging.log(logging.WARNINGS,  "Unable to write as much data as needed into MSN p2p file. Needed %s, write %d." %(message_size,bytes))
            os.close(fd)
            
    ct_dispatcher = {
        'text/plain': plain_handler,
        'application/x-msnmsgrp2p': p2p_handler,
        }
            
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
            tid = int(words[1])
            sender = "%s (Target)" % self.client_id
            friendly_sender = "Implied Client Machine"
        except ValueError:
            tid = 0
            sender = words[1]
            friendly_sender = words[2]

        try:
            content_type = self.headers['content-type']
        except:
            content_type = "unknown/unknown"

        ## Now dispatch the relevant handler according to the content
        ## type:
        try:
            ct = content_type.split(';')[0]
            self.ct_dispatcher[ct](self,content_type,sender,friendly_sender)
        except KeyError,e:
            logging.log(logging.VERBOSE_DEBUG, "Unable to handle content-type %s(%s) - ignoring message %s " % (content_type,e,tid))
            
from HTMLParser import HTMLParser

class ContextParser(HTMLParser):
    """ This is a simple parser to parse the MSN Context line """
    def handle_starttag(self, tag, attrs):
        self.context_meta_data = FlagFramework.query_type(attrs)

class MSNScanner(NetworkScanFactory):
    """ Collect information about MSN Instant messanger traffic """
    default = True
    depends = [ 'StreamReassembler']

    def prepare(self):
        self.dbh.execute(
            """CREATE TABLE if not exists `msn_messages_%s` (
            `sender` VARCHAR( 250 ) NOT NULL ,
            `friendly_name` VARCHAR( 255 ) NOT NULL ,
            `inode` VARCHAR(50) NOT NULL,
            `packet_id` INT,
            `session` INT,
            `ts_sec` int(11),
            `data` TEXT NOT NULL
            )""",(self.table,))
        self.dbh.execute(
            """ CREATE TABLE if not exists `msn_session_%s` (
            `id` INT,
            `user` VARCHAR( 250 ) NOT NULL
            )""",(self.table,))
        self.dbh.execute(
            """ CREATE TABLE if not exists `msn_p2p_%s` (
            `inode` VARCHAR(250),
            `session_id` INT,
            `channel_id` INT,
            `to_user` VARCHAR(250),
            `from_user` VARCHAR(250),
            `context` VARCHAR(250)
            )""",(self.table,))
            
        self.msn_connections = {}

    class Scan(NetworkScanner):
        def process(self,data,metadata=None):
            NetworkScanner.process(self,data,metadata)
            
            ## Is this an MSN packet bound to the server?
            try:
                request = self.proto_tree['msnms']
                dest_port = self.proto_tree['tcp.dstport'].value()

                self.outer.msn_connections[metadata['inode']]=1
            except KeyError:
                pass

        def finish(self):
            if not NetworkScanner.finish(self): return
            
            for key in self.outer.msn_connections.keys():
                ## First parse the forward stream
                fd = self.ddfs.open(inode=key)
                m=message(self.dbh,self.table,fd,self.ddfs)
                while 1:
                    try:
                        result=m.parse()
                    except IOError:
                        break
                    
                
class MSNFile(CachedFile):
    """ VFS driver for reading the cached MSN files """
    specifier = 'C'
    
    def __init__(self,case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)
        ## Figure out the filename
        cached_filename = get_temp_path(case,inode[1:])
        ## open the previously cached copy
        self.cached_fd = open(cached_filename,'r')
        
        ## Find our size:
        self.cached_fd.seek(0,2)
        self.size=self.cached_fd.tell()
        self.cached_fd.seek(0)
        self.readptr=0


class BrowseMSNChat(Reports.report):
    """ This allows MSN chat messages to be browsed.

    Note that to the left of each column there is an icon with an
    arrow pointing downwards. Clicking on this icon shows the full msn
    messages for all sessions from 60 seconds prior to this message.

    This is useful if you have isolated a specific message by
    searching for it, but want to see what messages were sent around
    the same time to get some context.
    """
    parameters = { 'fsimage':'fsimage' }
    name = "Browse MSN Chat"
    family = "Network Forensics"
    def form(self,query,result):
        try:
            result.case_selector()
            PCAPFS.draw_only_PCAPFS(query,result)
        except KeyError:
            pass

    def display(self,query,result):
        """ This callback renders an icon which when clicked shows the
        full msn messages for all sessions from 60 seconds prior to
        this message."""
        
        result.heading("MSN Chat sessions in %s " % query['fsimage'])

        def draw_prox_cb(value):
            tmp = result.__class__(result)
            tmp.link('Go To Approximate Time',
              target=FlagFramework.query_type((),
                family=query['family'], report=query['report'],
                fsimage=query['fsimage'], where_Prox = ">%s" % (int(value)-60),
                case = query['case'],
              ),
              icon = "stock_down-with-subpoints.png",
                     )

            return tmp

        result.table(
            columns = ['ts_sec', 'from_unixtime(ts_sec)','packet_id','session','sender','data'],
            names = ['Prox','Time Stamp','Packet','Session','Sender Nick','Text'],
            table = "msn_messages_%s" % query['fsimage'],
            callbacks = {'Prox':draw_prox_cb},
            links = [None, None,
                     FlagFramework.query_type((),
                                              family="Network Forensics", case=query['case'],
                                              report='View Packet', fsimage=query['fsimage'],
                                              __target__='id'),
                     FlagFramework.query_type((),
                                              family="Network Forensics", case=query['case'],
                                              report='BrowseMSNSessions', fsimage=query['fsimage'],
                                              __target__='where_Session ID'),
                     ],
            case = query['case']
            )

class BrowseMSNSessions(BrowseMSNChat):
    """ This shows MSN Session users. """
    parameters = { 'fsimage':'fsimage' }
    name = "Browse MSN Sessions"
    family = "Network Forensics"
    hidden = True
    def display(self,query,result):
        result.heading("MSN Chat sessions in %s " % query['fsimage'])
        result.table(
            columns = [ 'id','user'],
            names = ['Session ID','Users'],
            table = "msn_session_%s" % query['fsimage'],
            case = query['case']
            )

if __name__ == "__main__":
    fd = open("/tmp/case_demo/S93-94")
    data = fd.read()
    parse_msg(data)