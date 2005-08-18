""" This module implements features specific for HTTP Processing """
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
import pyethereal,sys
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import pyflag.Reports as Reports
import plugins.NetworkForensics.PCAPFS as PCAPFS

class HTTPScanner(NetworkScanFactory):
    """ Collect information about HTTP Transactions.
    """
    default = True
    depends = ['StreamReassembler']
    
    def prepare(self):
        ## This stores a list of the inodes we discover during initial
        ## processing. Note that we are unable to rescan the newly
        ## discovered as soon as we find them, because we have not
        ## finalised the streams yet. Rescanning must only be done in
        ## the finish method to allow the stream reassembler to
        ## classify all the streams.
        self.http_inodes = []
        ## This is the information we store about each http request:
        ## inode - the inode this belongs to (comes from the StreamReassembler)
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

                return
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
                ## data starts. The data starts after the \r\n\r\n
                ## sequence. Sometimes this can be in the next packet,
                ## in which case we will miss it here.
                http = self.proto_tree['http']
                delimiter = "\r\n\r\n"
                end_of_headers = data[http.start():].find(delimiter)+len(delimiter)
                if end_of_headers<0: end_of_headers=http.length()
                offset = metadata['stream_offset'] + end_of_headers

                self.dbh.execute("insert into http_response_%s set inode=%r,offset=%r, packet=%r, content_length=%r,content_type=%r,content_encoding=%r",(self.table,metadata['inode'],offset,self.packet_id,content_length,content_type,content_encoding))
                response_id = self.dbh.autoincrement()
                path=self.ddfs.lookup(inode=metadata['inode'])
                path=os.path.dirname(path)
                new_inode = "%s|o%s:%s" % (metadata['inode'],offset,content_length)

                ## Handle chunked encodings
                try:
                    transfer_encoding = self.proto_tree['http.transfer_encoding'].value().lower()

                    if "chunked" in transfer_encoding:
                        new_inode=new_inode+"|c0"
                except:
                    pass
                
                self.ddfs.VFSCreate(
                    None,
                    ## Inode:
                    new_inode,
                    ## Path to new file:
                    "%s/HTTP/Response %s" % (path,response_id)
                    )

                ## This code is needed because magic does not always
                ## identify the gzip nodes correctly.
                ## Handle gziped encoding:
                if content_encoding=='gzip':
                    self.ddfs.VFSCreate(
                        None,
                        ## Inode:
                        "%s|G1" % new_inode,
                        ## Path to new file:
                        "%s/HTTP/Response %s (uncompressed)" % (path,response_id)
                        )

                ## Now recursively scan the nodes:
                self.outer.http_inodes.append(new_inode)

            except KeyError,e:
                pass

        def finish(self):
            """ Rescan all the discovered inodes """
            if not NetworkScanner.finish(self): return
            
            for inode in self.outer.http_inodes:
                try:
                    self.scan_as_file(inode)
                except Exception,e:
                    logging.log(logging.ERRORS,"CRITICAL: %s" % e)

class BrowseHTTPRequests(Reports.report):
    """ This allows users to search the HTTP Requests that were loaded as part of the PCAP File system.
    """
    parameters = { 'fsimage':'fsimage' }

    name = "Browse HTTP Requests"
    family = "Network Forensics"
    def form(self,query,result):
        try:
            result.case_selector()
            PCAPFS.draw_only_PCAPFS(query,result)
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


class Chunked(File):
    """ This reads chunked HTTP Streams.

    """
    specifier = 'c'

    def create_file(self,filename):
        delimiter="\r\n"
        
        self.cached_fd = open(filename,'w')
        self.fd.seek(0)
        self.data = self.fd.read()
        self.size=0
        
        while 1:
            end = self.data.find(delimiter)+len(delimiter)
            if end<0: break

            size = int(self.data[:end],16)
            if size==0: break
            self.cached_fd.write(self.data[end:end+size])
            self.size+=size
            self.data=self.data[end+size+len(delimiter):]

        self.cached_fd.close()
        
    def __init__(self, case, table, fd, inode):
        File.__init__(self, case, table, fd, inode)

        self.filename = FlagFramework.get_temp_path(self.case,self.inode)

        try:
            self.cached_fd=open(self.filename,'r')
        except IOError:
            self.create_file(self.filename)
            self.cached_fd=open(self.filename,'r')
            

    def seek(self,offset,whence=0):
        self.cached_fd.seek(offset,whence)

    def tell(self):
        return self.cached_fd.tell()

    def read(self,length=None):
        if length==None:
            length=self.size-self.tell()
            
        return self.cached_fd.read(length)
