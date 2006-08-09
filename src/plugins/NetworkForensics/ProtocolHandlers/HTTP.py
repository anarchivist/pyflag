""" This module implements features specific for HTTP Processing """
# Michael Cohen <scudette@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
import plugins.NetworkForensics.PCAPFS as PCAPFS
import re,time


def escape(uri):
    """ Make a filename from a URI by escaping / chars """
    filename = FlagFramework.normpath(uri).replace('/', '_')
    return filename

class HTTP:
    """ Class used to parse HTTP Protocol """
    def __init__(self,fd,dbh,ddfs):
        self.fd=fd
        self.dbh = dbh
        self.ddfs = ddfs
        self.request = { 'url':'/unknown_request' }
        self.response = {}
        self.request_re = re.compile("(GET|POST|PUT|OPTIONS) +([^ ]+) +HTTP/1\..",
                                     re.IGNORECASE)
        self.response_re = re.compile("HTTP/1\.. (\\d+) +", re.IGNORECASE)

    def read_headers(self, dict):
        while True:
            line = self.fd.readline()
            if not line or line=='\r\n':    
                return True

            tmp = line.split(':',1)
            try:
                dict[tmp[0].lower().strip()] =tmp[1].strip()
            except IndexError:
                pass

    def read_request(self, line):
        """ Checks if line looks like a URL request. If it is, we
        continue reading the fd until we finish consuming the request
        (headers including post content if its there).

        We should be positioned at the start of the response after this.
        """
        m=self.request_re.search(line)
        if not m: return False

        self.request = dict(url=m.group(2),
                            method=m.group(1),
                            packet_id = self.fd.get_packet_id(self.fd.tell())
                            )
        self.read_headers(self.request)

        return True
        
    def read_response(self, line):
        """ Checks if line looks like a HTTP Response. If it is, we
        continue reading the fd until we finish consuming the
        response.

        We should be positioned at the start of the next request after this.
        """
        m=self.response_re.search(line)
        if not m: return False

        self.response = dict(HTTP_code= m.group(1),
                             packet_id = self.fd.get_packet_id(self.fd.tell())
                             )
        self.read_headers(self.response)
        return True

    def skip_body(self, headers):
        """ Reads the body of the HTTP object depending on the values
        in the headers. This function takes care of correctly parsing
        chunked and encoding.

        We assume that the fd is already positioned at the very start
        of the object. After this function we will be positioned at
        the end of this object.
        """
        try:
            skip = int(headers['content-length'])
            self.fd.read(skip)
            return
        except KeyError:
            pass

        try:
            if "chunked" in headers['transfer-encoding'].lower():
                while True:
                    line = self.fd.readline()
                    try:
                        length = int(line,16)
                    except:
                        return
                    
                    if length == 0:
                        return

                    ## There is a \r\n delimiter after the data chunk
                    self.fd.read(length+2)
        except KeyError:
            pass
        
    def parse(self):
        """ We assume that we were given the combined stream and we parse it.

        We are a generator returning offset:length for HTTP messages,
        as well as their URLs.
        """
        while True:
            line=self.fd.readline()
            if not line: break

            ## Is this a request?
            if self.read_request(line):
                self.skip_body(self.request)

            ## Maybe a response?
            elif self.read_response(line):
                offset = self.fd.tell()
                self.skip_body(self.response)
                end = self.fd.tell()
                yield "%s:%s" % (offset, end-offset)

class HTTPScanner(StreamScannerFactory):
    """ Collect information about HTTP Transactions.
    """
    default = True
    
    class Drawer(Scanner.Drawer):
        description = "Network Scanners"
        name = "NetworkScanners"
        contains = [ "IRCScanner", "MSNScanner", "HTTPScanner", "POPScanner","SMTPScanner","RFC2822" ]
        default = True
        special_fs_name = 'PCAPFS'


    def prepare(self):
        self.http_inodes = {}
        ## This is the information we store about each http request:
        ## inode - the inode which represents the response to this request
        ## request_packet - the packet id the request was sent in
        ## method - method requested
        ## url - the URL requested (This is the fully qualified url with host header included if present).
        ## response_packet - the packet where the response was seen
        ## content_type - The content type
        self.dbh.execute(
            """CREATE TABLE if not exists `http` (
            `inode` VARCHAR( 255 ) NOT NULL ,
            `request_packet` int not null,
            `method` VARCHAR( 10 ) NOT NULL ,
            `url` VARCHAR( 255 ) NOT NULL,
            `response_packet` int not null,
            `content_type` VARCHAR( 255 ) NOT NULL,
            `referrer` VARCHAR(255) NULL,
            `date` int,
            `host` VARCHAR(255)
            )""")

        self.dbh.check_index("http", "inode")
        self.dbh.check_index("http", "url")
        
    def reset(self, inode):
        self.dbh.execute("drop table if exists http")

    def parse_date_time_string(self, s):
        try:
            return time.mktime(time.strptime(s, "%a, %d %b %Y %H:%M:%S %Z"))
        except:
            print "Cant parse %s as a time" % s
            return 0

    def process_stream(self, stream, factories):
        forward_stream, reverse_stream = self.stream_to_server(stream, "HTTP")
        if not reverse_stream or not forward_stream: return

        combined_inode = "I%s|S%s/%s" % (stream.fd.name, forward_stream, reverse_stream)
        logging.log(logging.DEBUG,"Openning %s for HTTP" % combined_inode)

        fd = self.fsfd.open(inode=combined_inode)
        p=HTTP(fd,self.dbh,self.fsfd)
        ## Iterate over all the messages in this connection
        for f in p.parse():
            if not f: continue

            ## Create the VFS node:
            path=self.fsfd.lookup(inode="I%s|S%s" % (stream.fd.name, forward_stream))
            path=os.path.dirname(path)
            new_inode="%s|o%s" % (combined_inode,f)

            try:
                if 'chunked' in p.response['transfer-encoding']:
                    new_inode += "|c0"
            except KeyError:
                pass

            try:
                if 'gzip' in p.response['content-encoding']:
                    new_inode += "|G1"

            except KeyError:
                pass

            self.fsfd.VFSCreate(None,new_inode,
                                "%s/HTTP/%s" % (path, escape(p.request['url'])),
                                mtime=stream.ts_sec
                                )

            ## Store information about this request in the
            ## http table:
            host = p.request.get("host",IP2str(stream.dest_ip))
            url = p.request.get("url")
            try:
                date = p.response.get("date")
                date = int(self.parse_date_time_string(date))
            except (KeyError,ValueError):
                date = 0

            try:
                referer = p.request['referer']
            except KeyError:
                try:
                    referer = p.request['referrer']
                except KeyError:
                    referer = ''

            if not url.startswith("http://") and not url.startswith("ftp://"):
                url = "http://%s%s" % (host, url)
            self.dbh.execute("insert into http set inode=%r, request_packet=%r, method=%r, url=%r, response_packet=%r, content_type=%r, date=%r, referrer=%r, host=%r",(new_inode, p.request.get("packet_id"), p.request.get("method"), url, p.response.get("packet_id"), p.response.get("content-type","text/html"), date, referer, host))

            ## Scan the new file using the scanner train. 
            self.scan_as_file(new_inode, factories)
        
class BrowseHTTPRequests(Reports.report):
    """ This allows users to search the HTTP Requests that were loaded as part of the PCAP File system.

    This is the information we store about each http request:

    <ul>
    <li><b>inode</b> - the inode which represents the response to this request</li>
    <li><b>request_packet</b> - the packet id the request was sent in</li>
    <li><b>method</b> - method requested</li>
    <li><b>url</b> - the URL requested (This is the fully qualified url with host header included if present).</li>
    <li><b>response_packet</b> - the packet where the response was seen</li>
    <li><b>content_type</b> - The content type of the response to this request.</li>
    </ul>
    """
    name = "Browse HTTP Requests"
    family = "Network Forensics"
    
    def display(self,query,result):    
        result.heading("Requested URLs")
        result.table(
            columns = ['from_unixtime(ts_sec,"%Y-%m-%d")','concat(from_unixtime(ts_sec,"%H:%i:%s"),".",ts_usec)','request_packet','inode','method','url', 'content_type'],
            names = [ "Date","Time",  "Request Packet", 'Inode', "Method" ,"URL", "Content Type" ],
            table=" http join pcap on request_packet=id ",
            links = [
            None,
            None,
            FlagFramework.query_type((),
                                     family=query['family'], report="View Packet",
                                     case=query['case'], __target__='id'),
            FlagFramework.query_type((),
                                     family="Disk Forensics",case=query['case'],
                                     report="View File Contents",mode="Combined streams",
                                     __target__="inode"),
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

            try:
                size = int(self.data[:end],16)
            except:
                logging.log(logging.DEBUG, "Expecting chunked data length, found %s. Losing sync." % self.data[:end])
                return
            
            if size==0: break
            self.cached_fd.write(self.data[end:end+size])
            self.size+=size
            self.data=self.data[end+size+len(delimiter):]

        self.cached_fd.close()
        
    def __init__(self, case, fd, inode, dbh=None):
        File.__init__(self, case, fd, inode, dbh)

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
