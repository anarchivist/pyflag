""" This modules handles the IRC protocol.

"""
# Michael Cohen <scudette@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
#   Added recipient column to table
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
import pyflag.DB as DB
from pyflag.FileSystem import CachedFile
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import pyflag.Reports as Reports
import pyflag.logging as logging
import cStringIO,re
import plugins.NetworkForensics.PCAPFS as PCAPFS

class IRC:
    """ Class to manage the IRC state """
    command_lookup = {
        001: "Welcome Reply",
        002: "Host Server",
        003: "Server Creation Date",
        004: "Server Modes",
        005: "Server Info",
        251: "LUSER Client Reply",
        252: "LUSER OP Reply",
        253: "LUSER Unknown Reply",
        254: "LUSER Channel Reply",
        255: "LUSER Clients-Servers",
        256: "ADMIN Reply",
        265: "Curent Local Users",
        266: "Current Global Users",
        301: "NICK away Reply",
        303: "ISON Reply",
        311: "WHOISUSER Reply",
        312: "WHOISSERVER Reply",
        313: "WHOISOPERATOR Reply",
        317: "WHOIS IDLE Reply",
        318: "WHOIS End",
        319: "WHOIS Reply Channel OP",
        322: "LIST Reply",
        329: "Channel Creation Time",
        324: "MODE Channel",
        332: "TOPIC Reply",
        333: "TOPIC Reply WHO TIME",
        341: "INVITE Reply",
        353: "NAME Reply",
        366: "NAME End",
        372: "MOTD Reply",
        375: "MOTD Start",
        376: "MOTD End",
        377: "MOTD Reply",
        378: "MOTD Reply",
        381: "OPER Success Reply",
        382: "REHASHING Reply",
        465: "ERROR Banned",
        482: "ERROR Not OP",
        }
    
    def __init__(self,fd,dbh,ddfs):
        self.fd=fd
        self.dbh = dbh
        self.ddfs = ddfs

    def rewrite_reply(self,prefix,command,line):
        return line, self.command_lookup[command]+"(%s)" % command

    def PRIVMSG(self,prefix,command,line):
        return line,command

    def store_command(self,prefix,command,line):
        """ Handle the PRIVMSG command """
        packet_id = self.fd.get_packet_id(position=self.offset)
        self.dbh.execute("select ts_sec from pcap_%s where id = %s "
                         ,(self.table,packet_id))
        row = self.dbh.fetch()
        timestamp = row['ts_sec']

        if not prefix: prefix = self.nick

        m=re.search("^:?([^!@]+)",prefix)
        if m:
            short_name = m.group(1)
        else:
            short_name = prefix

        try:
            base_stream_inode = self.fd.inode[:self.fd.inode.index('/')]
        except IndexError:
            base_stream_inode = self.fd.inode
        if (line != None):
            recipient = line.split(':')[0]
        else:
            recipient = ""
            self.dbh.execute(""" insert into irc_messages_%s set sender=%r,full_sender=%r,
            inode=%r, packet_id=%r, data=%r, ts_sec=%r, command = %r, recipient = %r""",(
                self.table,short_name,prefix,base_stream_inode, packet_id,
                line, timestamp, command, recipient 
                ))

    password = ''
    def PASS(self,prefix,command,line):
        self.password = line
        return line,command

    nick = ''
    def NICK(self,prefix,command,line):
        """ When a user changes their nick we store it in the database """
        self.nick = line
        self.dbh.execute(
            """ insert into  `irc_userdetails_%s`  set
            inode=%r, nick=%r, username=%r, password=%r
            """,( self.table, self.fd.inode, self.nick, self.username, self.password))
        return line,command

    username = ''
    def USER(self,prefix,command,line):
        self.username = line
        return line,command

    def dispatch(self,prefix,command,line):
        """ A dispatcher to handle the command given. """
        try:
            line,command=getattr(self,command)(prefix,command,line)
        except AttributeError,e:
            ## Command is not in this class maybe its manually dispatched:
            try:
                line,command=self.dispatch_dict[command](self,prefix,command,line)
            except KeyError:
                ## If the command is an int, we try to remap it:
                try:
                    line,command=self.rewrite_reply(prefix,int(command),line)
                except (ValueError,KeyError):
                    pass

        self.store_command(prefix,command,line)



class IRCScanner(NetworkScanFactory):
    """ Collect information about IRC traffic """
    default = True
    depends = ['StreamReassembler']
    
    def prepare(self):
        self.dbh.execute(
            """CREATE TABLE if not exists `irc_messages_%s` (
            `id` int auto_increment,
            `sender` VARCHAR( 250 ) NOT NULL ,
            `full_sender` VARCHAR( 255 ) NOT NULL ,
            `recipient` VARCHAR(50),
            `command` VARCHAR(255) NOT NULL,
            `inode` VARCHAR(50) NOT NULL,
            `packet_id` INT,
            `session` VARCHAR(250),
            `ts_sec` int(11),
            `data` TEXT NOT NULL,
            key(id)
            )""",(self.table,))
        self.dbh.execute(
            """ CREATE TABLE if not exists `irc_session_%s` (
            `id` VARCHAR(250),
            `user` VARCHAR( 250 ) NOT NULL
            )""",(self.table,))
        self.dbh.execute(
            """ CREATE TABLE if not exists `irc_userdetails_%s` (
            `inode` VARCHAR(250),
            `nick` VARCHAR(250),
            `username` VARCHAR(250),
            `password` VARCHAR(250)
            )""",(self.table,))
        self.dbh.execute(
            """ CREATE TABLE if not exists `irc_p2p_%s` (
            `inode` VARCHAR(250),
            `session_id` INT,
            `channel_id` INT,
            `to_user` VARCHAR(250),
            `from_user` VARCHAR(250),
            `context` VARCHAR(250)
            )""",(self.table,))
        
        self.irc_connections = {}

    class Scan(NetworkScanner):
        def process(self,data,metadata=None):
            NetworkScanner.process(self,data,metadata)

            if self.proto_tree.is_protocol_to_server("IRC"):
                self.outer.irc_connections[metadata['inode']]=1

        def finish(self):
            if not NetworkScanner.finish(self): return
            
            for key in self.outer.irc_connections.keys():
                forward_stream = key[1:]
                reverse_stream = find_reverse_stream(
                    forward_stream,self.table,self.dbh)
                
                combined_inode = "S%s/%s" % (forward_stream,reverse_stream)
                self.fd = self.ddfs.open(inode=combined_inode)
                regex = re.compile("(?::([^ ]+) )?([^ ]+)(?: (.*))?")
                while 1:
                    self.offset=self.fd.tell()
                    line=self.fd.readline().strip()
                    if len(line)==0: break
                    try:
                        m=regex.match(line)
                        ## Dispatch a command handler:
                        self.dispatch(m.group(1),m.group(2),m.group(3))
                    except IndexError,e:
                        logging.log(logging.WARNINGS, "unable to parse line %s (%s)" % (line,e))

class BrowseIRCChat(Reports.report):
    """ This allows chat messages to be browsed. """
    parameters = { 'fsimage':'fsimage' }
    name = "Browse IRC Chat"
    family = "Network Forensics"
    def form(self,query,result):
        try:
            result.case_selector()
            PCAPFS.draw_only_PCAPFS(query,result)
        except KeyError:
            pass

    def display(self,query,result):
        result.heading("Chat sessions in %s " % query['fsimage'])
        def Stream_cb(value):
            tmp = result.__class__(result)
            try:
                base_stream_inode = value[:value.index('/')]
            except IndexError:
                base_stream_inode = value
                
            tmp.link(value,target = FlagFramework.query_type((),
                    family='Disk Forensics', case=query['case'],
                    fsimage=query['fsimage'], inode=base_stream_inode,
                    report='View File Contents', mode="Combined streams"
                                                             ))
            return tmp

        
        result.table(
            columns = ['id', 'from_unixtime(ts_sec)','inode','packet_id','command','sender','recipient', 'data'],
            names = ['ID','Time Stamp','Stream','Packet','Command','Sender Nick','Recipient','Text'],
            table = "irc_messages_%s" % query['fsimage'],
#            callbacks = { 'Stream':  Stream_cb },
            links = [None, None,
                     FlagFramework.query_type((),
                        family='Disk Forensics', case=query['case'],
                        fsimage=query['fsimage'], __target__='inode',
                        report='View File Contents', mode="Combined streams"
                        ),
                     FlagFramework.query_type((),
                        family="Network Forensics", case=query['case'],
                        report='View Packet', fsimage=query['fsimage'],
                        __target__='id'),
                     ],
            case = query['case']
            )
