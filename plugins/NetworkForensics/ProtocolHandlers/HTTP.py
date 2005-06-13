""" This module implements features specific for HTTP Processing """
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
import pyethereal,sys
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import pyflag.Reports as Reports

class HTTPScanner(GenScanFactory):
    """ Collect information about HTTP Transactions.
    """
    default = True

    def prepare(self):
        ## This is the information we store about each http request:
        ## inode - the inode this belongs too (comes from the StreamReassembler)
        ## offset- The offset into the inode where the request begins
        ## method- HTTP Method
        ## host  - The Host this is directed to
        ## request - The URI issed
        self.dbh.execute(
            """CREATE TABLE if not exists `http_request_%s` (
            `inode` VARCHAR( 255 ) NOT NULL ,
            `offset` INT NOT NULL ,
            `packet` int not null,
            `method` VARCHAR( 10 ) NOT NULL ,
            `host` VARCHAR( 255 ) NOT NULL,
            `request` VARCHAR( 255 ) NOT NULL 
            )""",(self.table,))

        ## This is the stuff we store about responses:
        self.dbh.execute(
            """CREATE TABLE if not exists `http_response_%s` (
            `response_id` int(11) unsigned NOT NULL auto_increment,
            `inode` VARCHAR( 255 ) NOT NULL ,
            `offset` INT NOT NULL ,
            `packet` int not null,
            `content_length` INT NOT NULL ,
            `content_type` VARCHAR( 255 ) NOT NULL,
            `content_encoding` VARCHAR( 255 ) NOT NULL,
            key `response_id` (`response_id`)
            )""",(self.table,))
        
    def reset(self):
        self.dbh.execute("drop table if exists http_request_%s",(self.table,))
        self.dbh.execute("drop table if exists http_response_%s",(self.table,))

    class Scan(NetworkScanner):
        def process(self,data,metadata=None):
            NetworkScanner.process(self,data,metadata)

            ## See if we can find a http request in this packet:
            try:
                method = self.proto_tree['http.request.method'].value()
                uri = self.proto_tree['http.request.uri'].value()
                host = self.proto_tree['http.host'].value()

                ## The offset is calculated as the offset from the
                ## start of this stream inode to the start of the
                ## request header:
                offset = metadata['stream_offset']

                ## Store in the request table
                self.dbh.execute("insert into http_request_%s set inode=%r,offset=%r,packet=%r,method=%r,host=%r,request=%r",(self.table, metadata['inode'],offset,self.packet_id,method,host,uri))
            except KeyError:
                pass

            ## See if there is a response in this packet:
            try:
                ## Is this a response?
                response = self.proto_tree['http.response']

                ## Default content_type:
                try:
                    content_type = self.proto_tree['http.content_type'].value()
                except:
                    content_type = "text/html"

                ## Default content_encoding
                try:
                    content_encoding = self.proto_tree['http.content_encoding'].value()
                except:
                    content_encoding = "plain"

                ## Default content_length
                try:
                    content_length = self.proto_tree['http.content_length'].value()
                except:
                    content_length = sys.maxint

                ## The offset is the position in the stream where the
                ## data starts:
                http = self.proto_tree['http']
                offset = metadata['stream_offset'] + http.length()

                self.dbh.execute("insert into http_response_%s set inode=%r,offset=%r, packet=%r, content_length=%r,content_type=%r,content_encoding=%r",(self.table,metadata['inode'],offset,self.packet_id,content_length,content_type,content_encoding))
                response_id = self.dbh.autoincrement()
                self.ddfs.VFSCreate(metadata['inode'],
                     ## Inode:
                      "o%s:%s" % (offset,content_length),
                     ## Path to new file:
                      "HTTP response %s" % (
                            response_id))

                ## Handle gziped encoding:
                if content_encoding=='gzip':
                    self.ddfs.VFSCreate(metadata['inode'],
                                        ## Inode:
                                        "o%s:%s|G1" % (offset,content_length),
                                        ## Path to new file:
                                        "HTTP response %s (uncompressed)" % (
                        response_id))
                    
            except KeyError,e:
                pass


class BrowseHTTPRequests(Reports.report):
    """ This allows users to search the HTTP Requests that were loaded as part of the PCAP File system.
    """
    parameters = { 'fsimage':'fsimage' }

    name = "Browse HTTP Requests"
    family = "Network Forensics"
    def form(self,query,result):
        try:
            result.case_selector()
            result.meta_selector(case=query['case'],property='fsimage')
        except KeyError:
            pass

    def display(self,query,result):
        result.heading("Requested URIs in %s" % query['fsimage'])
        result.table(
            columns = ['inode','packet','method','host','request'],
            names = [ 'Inode', "Packet", "Method" ," Host","Request URI" ],
            table="http_request_%s" % query['fsimage'],
            links = [
            FlagFramework.query_type((),
                                     family="Disk Forensics",case=query['case'],
                                     report="View File Contents",mode="Combined streams",
                                     fsimage=query['fsimage'],__target__="inode"),
            FlagFramework.query_type((),
                                     family=query['family'], report="View Packet",
                                     fsimage=query['fsimage'],case=query['case'],
                                     __target__='id')
            ], 
            case=query['case']
            )
