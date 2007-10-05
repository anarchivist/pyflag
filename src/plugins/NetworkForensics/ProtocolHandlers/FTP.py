""" This module implements features specific for HTTP Processing """
# Michael Cohen <scudette@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
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
from pyflag.TableObj import StringType, TimestampType, InodeType, IntegerType, PacketType

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

    def __init__(self, forward_fd=None, reverse_fd=None):

        self.forward_fd = forward_fd
        self.reverse_fd = reverse_fd

        self.forward_stream_parsed = False
        self.reverse_stream_parsed = False

        self.reverse_commands = {}
        self.forward_commands = {}

        self.session_events = []
        self.session_meta_data = {}

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
            
            self.data_streams.append( { "source":"TODO",
                                   "destination":".".join(match.groups()[0:4]),
                                   "destination_port":(p2 + (256 * p1)),
                                   "source_port":"TODO" } )

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

    def parse(self):
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


    def saveToDb(self,dbh = None):
        # here we save everything in 
        # self.session_meta_data, self.session_events and self.data_streams

        pass

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

    def process_stream(self, stream, factories):

        def is_data_stream(stream):
            ## TODO
            # Search the DB to see if this is an FTP stream.
            return False

        ## We first need to check whether or not it's a data stream
        if is_data_stream(stream):
            #dataStream = 
            #self.process_data_stream(stream)
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
                                         reverse_fd = reverse_fd)

        ## Allow it to parse iteself
        controlStream.parse()

        ## How did we go? (debug)
        # controlStream.printStatus()
        


class FTPTables(FlagFramework.EventHandler):
    def create(self, dbh, case):
        pass
        
#        # ftp_sessions will give an overview of each "session" (control 
#        # connection
#        dbh.execute(
#            """CREATE TABLE if not exists `ftp_sessions` (
#            `id` INT(11) not null auto_increment,
#            `client_ip`
#            `server_ip`
#            `username`
#            `password`
#            `server_banner`
#            `total_bytes`
#            `starttime`
#
#            primary key (`id`)
#            )""")
#
#        # ftp_commands will list each ftp command
#        dbh.execute(
#            """CREATE TABLE if not exists `ftp_commands` (
#            `id` INT(11) not null auto_increment,
#            `ftp_session_id`
#            `command_type`
#            `command`
#            `data`
#            `timestamp`
#            `data_stream`
#
#            primary key (`id`)
#            )""")
#        
#        # ftp_data_streams will list each ftp data stream (directory 
#        # listings and also file transfers etc)
#        dbh.execute(
#            """CREATE TABLE if not exists `ftp_data_streams` (
#            `id` INT(11) not null auto_increment,
#            `ftp_session_id`
#            `source`
#            `source_port`
#            `destination`
#            `destination_port`
#            `purpose`
#            `inode`
#
#            primary key (`id`)
#            )""")

        
class BrowseFTPRequests(Reports.report):
    name = "Browse FTP Data"
    family = "Network Forensics"
    hidden = True
    
    def display(self,query,result):    
        result.heading("FTP Session Browser")
        result.para("NYI Sorry")


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


