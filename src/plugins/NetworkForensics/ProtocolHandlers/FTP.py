""" This module implements features specific for HTTP Processing """
# Michael Cohen <scudette@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.85 Date: Fri Dec 28 16:12:30 EST 2007$
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
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
import pyflag.Reports as Reports

from pyflag.FileSystem import File
from pyflag.FlagFramework import query_type
from NetworkScanner import *
import plugins.NetworkForensics.PCAPFS as PCAPFS
import TreeObj
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, IntegerType, PacketType, IPType

import dissect,sys,struct,sys,cStringIO, re, time, cgi

config.add_option("FTP_PORTS", default='[21,]', 
                  help = "A list of ports to be considered for FTP "\
                         "control channels")

class FTPControlStream:
    server_functions = { 220: "TwoTwenty",
                         230: "TwoThirty",
                         250: "TwoFifty",
                         200: "TwoHundred",
                         550: "FiveFifty" }

    reverse_command_regex = re.compile("(\d{3})(-|\s)*(.*)")
    forward_command_regex = re.compile("(\w{2,6})(\s)*(.*)")
    port_command_regex = re.compile("\s*?(\d{1,3}),(\d{1,3}),(\d{1,3})"\
                                    ",(\d{1,3}),(\d{1,3}),(\d{1,3})\s*")

    def __init__(self, forward_fd=None, reverse_fd=None, case=None):
        self.case = case

        self.forward_fd = forward_fd
        self.reverse_fd = reverse_fd

        self.forward_stream_parsed = False
        self.reverse_stream_parsed = False

        self.reverse_commands = {}
        self.forward_commands = {}

        self.session_events = []
        self.session_meta_data = {}
        self.session_meta_data['username'] = "<Unknown>"
        self.session_meta_data['password'] = "<Unknown>"
        self.session_meta_data['server_banner'] = "<None>"
        self.session_meta_data['welcome_banner'] = "<None>"
        self.session_meta_data['client_ip'] = 0
        self.session_meta_data['server_ip'] = 0
        self.session_meta_data['total_bytes'] = 0
        self.session_meta_data['start_time'] = 0
        self.session_meta_data['inode'] = "None"

        self.data_streams = []

        self.state = {}
        self.state['current'] = "none"
        self.state['cwd'] = "/"
        self.state['pending_directory'] = None
        self.state['data_mode'] = "ASCII"

    # Client Side commands
    def PORT(self):

        # We further break up the port command
        match = self.port_command_regex.match(self.forward_commands['data'])

        if match:
            #  PORT h1,h2,h3,h4,p1,p2
            try:
                p1 = int(match.groups()[4])
                p2 = int(match.groups()[5])
            except:
                pyflaglog.log(pyflaglog.WARNING, "Found a malformed PORT "\
                              " command! Not sure what to do. It looked like"\
                              " this: %s" % self.forward_commands['data'])
                return

            
            # Assumes a download! TODO
            MASK32 = 0xffffffffL
            def aton(str):
                """ convert dotted decimal IP to int """
                oct = [long(i) for i in str.split('.')]
                result=((oct[0] << 24) | (oct[1] << 16) | (oct[2] << 8) | (oct[3])) & MASK32
                return result

            self.data_streams.append( { "source":
                                           self.session_meta_data['server_ip'],
                                        "destination":
                                           aton(".".join(match.groups()[0:4])),
                                        "destination_port":
                                           (p2 + (256 * p1)),
                                        "source_port":
                                           20,
                                        "inode":
                                           "Unknown",
                                        "time":
                                           self.get_time_of_packet() } )

            self.state['current'] = "port_pending"

        else:
            pyflaglog.log(pyflaglog.WARNING, "Found a malformed PORT "\
                          " command! Not sure what to do. It looked like"\
                          " this: %s" % self.forward_commands['data'])
            return

    def USER(self):
        self.session_meta_data['username'] = self.forward_commands['data']
        self.state['current'] = "username_pending"

    def PASS(self):
        self.session_meta_data['password'] = self.forward_commands['data']
        self.state['current'] = "password_pending"

    def CWD(self):
        self.state['current'] = "directory_change_pending"
        self.state['pending_directory'] = self.forward_commands['data']

    def NLST(self):
        self.state['current'] = "directory_listing"
        # We should have a port command already associated with this
        lastOne = len(self.data_streams) - 1
        self.data_streams[lastOne]['purpose'] = \
                "Directory Listing of %s" % self.state['cwd']

    # Server side responses
    def TwoHundred(self):
        if self.state['current'] == "port_pending":
            self.state['current'] = "idle"
    
    def TwoFifty(self):
        if self.state['current'] == "directory_change_pending":
            self.state['current'] = "idle"

            ## TODO - Proper directory handling...
            ## (this is ovbviously very dodgy atm)
            self.state['cwd'] += self.state['pending_directory']
    
    def TwoTwenty(self):
        self.state['current'] = "ready"
        self.session_meta_data['server_banner'] = \
                                self.reverse_commands['data']
        pass

    def TwoThirty(self):
        
        if self.state['current'] == "password_pending":
            self.state['current'] = "logged_in"

        # Then we have to handle to the fact it is OK to get lots of these
        elif self.state['current'] == "logged_in":
            self.state['current'] = "idle"
        elif self.state['current'] == "idle":
            pass

        # What about other cases...
        elif self.state['current'] == "username_pending":
            pass
            ##TODO
            # No password required

        elif self.state['current'] == "ready":
            self.state['current'] = "idle"
            ## No log in required
            ## TODO

        else:
            pyflaglog.log(pyflaglog.WARNING, "We got a 230 response when "\
                          "we were not expecting it. Setting state to idle"\
                          ". Our current state was: %s" % self.state['current'])
            
            self.state['current'] = "idle"

        # Update the welcome banner
        if self.session_meta_data.has_key('welcome_banner'):
            self.session_meta_data['welcome_banner'] += \
                                        self.reverse_commands['data']
        else:
            self.session_meta_data['welcome_banner'] = \
                                        self.reverse_commands['data']

    def FiveFifty(self):
        # Bad Error change message
        if self.state['current'] == "directory_change_pending":
            self.state['current'] = "idle"
        else:
            pyflaglog.log(pyflaglog.WARNING, "We got a 550 response when "\
                          "we were not expecting it. Setting state to idle")
            self.state['current'] = "idle"


    def forward_stream_parse(self):
        """ Parse the forward stream of this FTP control session """

        self.forward_cmdline=self.forward_fd.readline()

        if len(self.forward_cmdline)==0: 
            self.forward_stream_parsed = True
            return

        # Parse
        ## TODO better exception handling
        self.forward_command_regexed = \
                self.forward_command_regex.match(self.forward_cmdline)

        if self.forward_command_regexed:
            self.forward_commands['command'] = \
                            self.forward_command_regexed.groups()[0]
            self.forward_commands['data'] = \
                            self.forward_command_regexed.groups()[2]
        
        self.session_events.append(
                               {"type":"CLIENT COMMAND", 
                                "command":self.forward_commands['command'],
                                "data":self.forward_commands['data']}
                                  )  

        # Is this a special command (i.e. do we need to actually do anything?)
        if hasattr(self, self.forward_commands['command'].upper()):
            getattr(self, self.forward_commands['command'].upper())()
 
       
    def reverse_stream_parse(self):
        """ Parse the reverse stream of this FTP control connection """

        self.reverse_cmdline=self.reverse_fd.readline()
        if len(self.reverse_cmdline)==0:
            self.reverse_stream_parsed = True
            return

        self.reverse_command_regexed = \
                self.reverse_command_regex.match(self.reverse_cmdline)

        # Parse
        ## TODO better exception handling here
        if self.reverse_command_regexed:
            self.reverse_commands['command'] = \
                            self.reverse_command_regexed.groups()[0]
            self.reverse_commands['data'] = \
                            self.reverse_command_regexed.groups()[2]

            self.session_events.append(
                                  {"type":"SERVER RESPONSE", 
                                   "command":self.reverse_commands['command'],
                                   "data":self.reverse_commands['data']}
                                  )  

            # Is this a special command (i.e. do we need to 
            # actually do anything?)
            try:
                function = int(self.reverse_commands['command'])
                if self.server_functions.has_key(function):
                    function_name = self.server_functions[function]
                    if hasattr(self,function_name):
                        getattr(self,function_name)()

            except AttributeError, ValueError:
                pass 

        # Did not match our return code regex
        else:
            pyflaglog.log(pyflaglog.WARNING, "We got a weird return message"\
                          " from the server. Setting state to idle")
            self.state['current'] = "idle"

    def get_time_of_packet(self, forward = True):
        id = self.get_forward_packet_id()
        dbh = DB.DBO(case = self.case)
        dbh.execute("""select * from `pcap` where id="%s" """ % id)
        row = dbh.fetch()
        return row['ts_sec']

    def get_next_packet_id(self,forward=True):
        try:
            if forward:
                offset = self.forward_fd.tell()
                return self.forward_fd.get_packet_id(offset+1)
            else:
                offset = self.reverse_fd.tell()
                return self.reverse_fd.get_packet_id(offset+1)
        except IOError:
            return -1

    def get_next_forward_packet_id(self):
        return self.get_next_packet_id(forward=True)
        
    def get_next_reverse_packet_id(self):
        return self.get_next_packet_id(forward=False)

    def get_packet_id(self,forward=True):
        try:
            if forward:
                offset = self.forward_fd.tell()
                return self.forward_fd.get_packet_id(offset)
            else:
                offset = self.reverse_fd.tell()
                return self.reverse_fd.get_packet_id(offset)
        except IOError:
            return -1

    def get_forward_packet_id(self):
        return self.get_packet_id(forward=True)
        
    def get_reverse_packet_id(self):
        return self.get_packet_id(forward=False)

    def parse(self):
    
        # Meta data
        self.session_meta_data['client_ip'] = self.forward_fd.src_ip
        self.session_meta_data['server_ip'] = self.forward_fd.dest_ip
        self.session_meta_data['start_time'] = self.forward_fd.ts_sec
        self.session_meta_data['total_bytes'] = self.forward_fd.size
        self.session_meta_data['inode'] = self.forward_fd.inode

        while not (self.forward_stream_parsed and self.reverse_stream_parsed):

            # Is one or the other done?
            if self.forward_stream_parsed:
                self.reverse_stream_parse()
            elif self.reverse_stream_parsed:
                self.forward_stream_parse()

            # Nope, both are still going, which one is next in the stream?
            elif (self.get_next_forward_packet_id() < \
                  self.get_next_reverse_packet_id()):

                self.forward_stream_parse()

            elif (self.get_next_forward_packet_id() > \
                  self.get_next_reverse_packet_id()):
                
                self.reverse_stream_parse()

            # Who knows, just do the forward one?
            else:
                self.forward_stream_parse()


    def save_to_db(self,dbh = None):
        # here we save everything in 
        # self.session_meta_data, self.session_events and self.data_streams
        
        ## First save the meta data...
        if not dbh:
            return

        dbh.insert('ftp_sessions',
                    client_ip = self.session_meta_data['client_ip'],
                    server_ip = self.session_meta_data['server_ip'],
                    username = self.session_meta_data['username'],
                    password = self.session_meta_data['password'],
                    server_banner = self.session_meta_data['server_banner'],
                    welcome_banner = self.session_meta_data['welcome_banner'],
                    total_bytes = self.session_meta_data['total_bytes'],
                    start_time = self.session_meta_data['start_time'],
                    inode = self.session_meta_data['inode'])
    

        session_id = dbh.autoincrement()
        
        for event in self.session_events:
            dbh.insert('ftp_commands',
                        command = event['command'],
                        command_type = event['type'],
                        data = event['data'],
                        ftp_session_id = session_id,
                        data_stream = "None")


        for stream in self.data_streams:
            dbh.insert('ftp_data_streams',
                       ftp_session_id = session_id,
                       source = stream['source'],
                       source_port = stream['source_port'],
                       destination = stream['destination'],
                       destination_port = stream['destination_port'],
                       purpose = stream['purpose'],
                       time_created = stream['time'],
                       inode = stream['inode'])
        
            

    def printStatus(self):
        print "--- Control Stream ---"
        print " Session Events:"
        print "   ", self.session_events
        print " Current State:"
        print "   ", self.state
        print " Current Meta-Data:"
        print "   ", self.session_meta_data
        print " Current Data Sessions:"
        print "   ", self.data_streams
        print "---                ---"

class FTPDataStream:
    def __init__(self):
        pass


class FTPScanner(StreamScannerFactory):
    """ Analyse data for FTP protocol """
    default = True
    
    def process_stream(self, stream, factories):

        def is_data_stream(stream):
            ## TODO
            # Search the DB to see if this is an FTP stream.
            dbh = DB.DBO(case = self.case)
            dbh.execute("""select * from ftp_data_streams where """ \
                        """`source` = %s and `source_port` = %s and """ \
                        """`destination` = %s and `destination_port` = %s """\
                        % (stream.src_ip, stream.src_port, stream.dest_ip,
                           stream.dest_port))
            row = dbh.fetch()
            if row:
                return True

            return False

        ## We first need to check whether or not it's a data stream
        if is_data_stream(stream):
            #print "DATA stream."
            dbh = DB.DBO(case = self.case)
            dbh.execute("""update ftp_data_streams set inode  """ \
                        """ = "%s" where """ \
                        """`source` = %s and `source_port` = %s and """ \
                        """`destination` = %s and `destination_port` = %s """\
                        % (stream.inode, stream.src_ip, stream.src_port, 
                           stream.dest_ip, stream.dest_port))
            return

        ## Nope, is it a control stream?
        forward_stream, reverse_stream = self.stream_to_server(stream, 
                                                               "FTP")
        if not (reverse_stream and forward_stream): 
            return

        ## TODO
        ## Should we try and make do if we only get a single stream?
        ## For the moment, no
        if reverse_stream == None or forward_stream == None:
            return
        ##

        ## Create forward and reverse inodes and then open them.
        forward_inode =  "I%s|S%s" % (stream.fd.name, forward_stream)
        reverse_inode = "I%s|S%s" % (stream.fd.name, reverse_stream)
        forward_fd = self.fsfd.open(inode = forward_inode)
        reverse_fd = self.fsfd.open(inode = reverse_inode)

        ## Create our FTPControl stream...
        controlStream = FTPControlStream(forward_fd = forward_fd,
                                         reverse_fd = reverse_fd,
                                         case = self.case)


        dbh = DB.DBO(self.case)

        ## Allow it to parse iteself
        controlStream.parse()

        ## How did we go? (debug)
        # controlStream.printStatus()

        ## Save to DB
        controlStream.save_to_db(dbh)

class FTPTables(FlagFramework.EventHandler):
    def create(self, dbh, case):
        pass
        
        # ftp_sessions will give an overview of each "session" (control 
        # connection
        dbh.execute(
            """CREATE TABLE if not exists `ftp_sessions` (
            `inode_id` INT(16) not null ,
            `client_ip` int(11) unsigned not null,
            `server_ip` int(11) unsigned not null,
            `username` varchar(128) not null,
            `password` varchar(128) not null,
            `server_banner` text,
            `welcome_banner` text,
            `total_bytes` int(32),
            `start_time` timestamp,
            `inode` varchar(255)
            )""")

        # ftp_commands will list each ftp command
        dbh.execute(
            """CREATE TABLE if not exists `ftp_commands` (
            `inode_id` INT(16) not null ,
            `ftp_session_id` INT(16) not null, 
            `command_type` varchar(128),
            `command` varchar(128),
            `data` text,
            `timestamp` timestamp,
            `data_stream` varchar(255)
            )""")
        
        # ftp_data_streams will list each ftp data stream (directory 
        # listings and also file transfers etc)
        dbh.execute(
            """CREATE TABLE if not exists `ftp_data_streams` (
            `inode_id` INT(16) not null ,
            `ftp_session_id` int(16) not null,
            `source` INT(11) unsigned not null,
            `source_port` INT(16) not null,
            `destination` INT(11) unsigned not null,
            `destination_port` int(16) not null,
            `purpose` varchar(255) not null,
            `inode` varchar(255) not null,
            `time_created` timestamp not null
            )""")

        
class BrowseFTPRequests(Reports.report):
    name = "Browse FTP Data"
    family = "Network Forensics"
    hidden = False
    
    def display(self,query,result):    
    
        def sessions(query, result):
            result.table(
                elements = [ IntegerType("FTP Session id", "id"),
                             InodeIDType(case=query['case']),
                             TimestampType("Start Time", "start_time"), 
                             IPType("Client IP", "client_ip", case=query['case']),
                             IPType("Server IP", "server_ip", case=query['case']),
                             StringType("Username", "username"),
                             StringType("Password", "password"),
                             StringType("Server Banner", "server_banner"),
                             IntegerType("Total bytes", "total_bytes")],
                table = "ftp_sessions",
                case = query['case'])

        def commands(query, result):
            result.table(
                elements = [ IntegerType("FTP Session id", "ftp_session_id",
                                link = query_type(family = "Network Forensics", 
                                                  case = query['case'], 
                                                  report = "Browse FTP Data")),
                             StringType("Command Type", "command_type"),
                             StringType("Command", "command"),
                             StringType("Data", "data")],
                table = 'ftp_commands',
                case = query['case'])

        def streams(query, result):
            result.table(
                elements = [ IntegerType("FTP Session id", "ftp_session_id",
                                link = query_type(family = "Network Forensics", 
                                                  case = query['case'], 
                                                  report = "Browse FTP Data")),
                             TimestampType("Time Created", "time_created"),
                             StringType("Purpose", "purpose"),
                             InodeType("Inode", "inode", case=query['case'])],
                table = 'ftp_data_streams',
                case = query['case'])

        result.heading("FTP Data Browser")
        result.notebook(
                        names = ['FTP Sessions',
                                 'FTP Commands',
                                 'FTP Data Streams'],
                    callbacks = [sessions,
                                 commands,
                                 streams]
                        )
                                        


import unittest, pyflag.pyflagsh as pyflagsh

class FTPTests(unittest.TestCase):
    """ Tests FTP Scanner """
    order=22

    def test01FTPScanner(self):
        """ Test basic FTP scanning """
        self.test_case = "Pyflagtest01FTPScannerTestCase"
        env = pyflagsh.environment(case=self.test_case)

        ## First we drop the case in case it already exists
        ## Since it might not exist, we allow this to throw:
        try:
            pyflagsh.shell_execv(env=env,
                                 command = "delete_case",
                                 argv=[self.test_case])   

        except RuntimeError:
            pass
 
        ## Now we create it
        pyflagsh.shell_execv(env=env,
                             command = "create_case",
                             argv=[self.test_case])

        pyflagsh.shell_execv(command="execute", 
                            argv=["Load Data.Load IO Data Source", 
                              "case=%s" % self.test_case , 
                              "iosource=FTPTest1", 
                              "subsys=Advanced", 
                              "filename=NetworkForensics/ProtocolHandlers/"\
                                   "FTP/FTP_Cap1_BasicSession.pcap"])

        pyflagsh.shell_execv(command="execute", 
                             argv=["Load Data.Load Filesystem image", 
                                   "case=%s" %self.test_case , 
                                   "iosource=FTPTest1", 
                                   "fstype=PCAP Filesystem", 
                                   "mount_point=/FTPTest1"])

        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "FTPScanner"
                                  ])                   ## List of Scanners



        ## What should we have found?
        dbh = DB.DBO(self.test_case)


