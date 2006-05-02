""" This module implements a simple stream reassembler.
"""
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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
import pyflag.Registry as Registry
from pyflag.Scanner import *
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import struct,re,os
import reassembler

class StreamReassembler(NetworkScanFactory):
    """ This scanner reassembles the packets into the streams.

    We internally use two tables. The first is connection_details,
    which contains ip and port tuples identifying the connection. The
    connection table contains a list of packets comprising each
    connection and some shortcuts to access their data.
    """
    default = True
    order=5

    class Drawer(Scanner.Drawer):
        description = "Network Scanners"
        name = "NetworkScanners"
        contains = [ "IRCScanner", "MSNScanner", "HTTPScanner", "POPScanner","SMTPScanner","RFC2822" ]
        default = True
        special_fs_name = 'PCAPFS'

    class Scan(NetworkScanner):
        """ Each packet will cause a new instantiation of this class. """
        def process_stream(self, stream):
            """ Calls all of the factory classes with the stream
            object to allow them to process the completed stream.
            """
            for factory in self.factories:
                if isinstance(factory, NetworkScanFactory):
                    factory.process_stream(stream, self.factories)
                
def combine_streams(query,result):
    """ Show both ends of the stream combined.

    In each screenfull we show a maximum of MAXSIZE characters per connection. We stop as soon as either direction reaches this many characters.
    """
    inode = query['inode']
    dbh = result.dbh
    try:
        iosource = inode[:inode.index("|")]
        stream_inode = inode[inode.rindex("|"):]
        forward_cid = int(stream_inode[2:])
    except ValueError:
        raise ValueError("Inode format is not correct. %s is not a valid inode." % inode)

    try:
        limit = int(query['stream_limit'])
    except:
        limit = 0
    
    reverse_cid  = find_reverse_stream(forward_cid, dbh)

    ## This gives us a handle to the VFS
    fsfd = Registry.FILESYSTEMS.fs['DBFS'](query['case'])

    number_of_rows = 0
    dbh.execute("select con_id, concat(\"%s|p0|O\",cast(packet_id as char),\"|o\",cast(data_offset as char),\":\",cast(`connection`.length as char)) as inode from `connection` join pcap on packet_id=pcap.id where con_id=%r or con_id=%r order by packet_id limit %s,%s",(iosource,forward_cid,reverse_cid, limit, config.PAGESIZE))
    for row in dbh:
        number_of_rows += 1
        fd = fsfd.open(inode = row['inode'])
        ## Get the data:
        data=fd.read()
        if row['con_id']==forward_cid:
            result.text(data,color="blue",font='typewriter',sanitise='full',wrap='full')
        else:
            result.text(data,color="red",font='typewriter',sanitise='full',wrap='full')    

    ## Make the paging buttons
    if limit > 0:
        del query['stream_limit']
        temp = limit-config.PAGESIZE
        if temp < 0:
            temp = 0
            
        query['stream_limit'] = temp
        result.toolbar(text="Previous page", icon="stock_left.png",
                       link = query )
    else:
        result.toolbar(text="Previous page", icon="stock_left_gray.png")

    if number_of_rows >= config.PAGESIZE:
        del query['stream_limit']
        query['stream_limit'] = limit+config.PAGESIZE
        result.toolbar(text="Next page", icon="stock_right.png",
                       link = query )
    else:
        result.toolbar(text="Next page", icon="stock_right_gray.png")
        
def show_packets(query,result):
    """ Shows the packets which belong in this stream """
    inode = query['inode']
    dbh = DB.DBO(query['case'])
    try:
        iosource = inode[:inode.index("|")]
        stream_inode = inode[inode.rindex("|"):]
        con_id = int(stream_inode[2:])
    except ValueError:
        raise ValueError("Inode format is not correct. %s is not a valid inode." % inode)

    ## This gives us a handle to the VFS
    fsfd = Registry.FILESYSTEMS.fs['DBFS'](query['case'])
            
    def show_data(value):
        fd = fsfd.open(inode=value)
        ui=result.__class__(result)
        ## We read at most this many chars from the packet:
        data=fd.read(50)

        if(len(data) ==50):
            data += "  ...."

        ui.text(data, sanitise='full', font='typewriter')
        return ui
    
    result.table(
        columns = ('concat("%s|p0|o",cast(packet_id as char))' % iosource, 'from_unixtime(pcap.ts_sec,"%Y-%m-%d")','concat(from_unixtime(pcap.ts_sec,"%H:%i:%s"),".",pcap.ts_usec)','seq','con.length','concat("%s|p0|O",cast(packet_id as char),"|o",cast(data_offset as char),":",cast(con.length as char))' % iosource),
        names = ('Packet ID','Date','Time','Sequence Number','Length',"Data"),
        links = [ FlagFramework.query_type((),
                                           family="Network Forensics",
                                           report='View Packet',
                                           case=query['case'],
                                           __target__='inode'),
                  ],
        table= '`connection` as con , pcap',
        where = 'con_id="%s" and packet_id=id ' % con_id,
        callbacks = { 'Data': show_data },
        case=query['case']
        )

class StremFile(File):
    """ A File like object to reassemble the stream from individual packets.
    
    Note that this is currently a very Naive reassembler. Stream Reassembling is generally considered a very difficult task. The approach we take is to make a very simple reassembly, and have a different scanner check the stream for potetial inconsistancies.

    The inode format is:
    Scon_id/con_id/con_id

    con_ids are the connection IDs. If more than one con_id is
    specified we merge all connections into the same stream based on
    arrival time.
    """
    stat_cbs = [ show_packets, combine_streams ]
    stat_names = [ "Show Packets", "Combined streams"]
    specifier = 'S'

    def __init__(self, case, fd, inode, dbh=None):
        File.__init__(self,case, fd, inode, dbh=None)
        if self.cached_fd: return

        inode = inode.split("|")[-1]

        ## We allow the user to ask for a number of streams which will
        ## be combined at the same time. This allows us to create a
        ## VFS node for both forward and reverse streams, or even
        ## totally unrelated streams which happen at the same time.

        ## This is handled by creating a "virtual stream" - a new
        ## stream with a new stream id which collects all the packets
        ## in the component streams in chronological order.

        ## We use the inode column in the connection_details table to
        ## cache this so we only have to combine the streams once.
        self.create_new_stream(inode[1:].split("/"))

    def create_new_stream(self,stream_ids):
        """ Creates a new stream by combining the streams given by the list stream_ids.
        
        @return the new stream id.
        """
        ## Store the new stream in the cache:
        self.dbh.execute("insert into `connection_details` set inode=%r",
                         (self.inode))
        con_id = self.dbh.autoincrement()
        self.dbh2 = self.dbh.clone()

        fds = {}
        for s in stream_ids:
            fds[int(s)] = open(FlagFramework.get_temp_path(
                self.dbh.case, "%s|S%s" % (self.fd.inode, s)))

        out_fd = open(FlagFramework.get_temp_path(self.dbh.case,
                                                  self.inode),"w")
        
        self.dbh.execute("select con_id,packet_id, length, cache_offset from `connection` where %s order by packet_id",(
            " or ".join(["con_id=%r" % a for a in stream_ids])
            ))

        self.dbh2.mass_insert_start("connection")
        for row in self.dbh:
            offset = out_fd.tell()
            fd=fds[row['con_id']]
            fd.seek(row['cache_offset']) 
            out_fd.write(fd.read(row['length']))
            self.dbh2.mass_insert(con_id=con_id,packet_id=row['packet_id'],
                                  seq=sum,length=row['length'],
                                  cache_offset=offset)

        self.dbh2.mass_insert_commit()

        out_fd.close()
        self.cached_fd = open(FlagFramework.get_temp_path(
            self.dbh.case, self.inode),"w")
        
class xStreamFile(File):
    """ A File like object to reassemble the stream from individual packets.

    Note that this is currently a very Naive reassembler. Stream Reassembling is generally considered a very difficult task. The approach we take is to make a very simple reassembly, and have a different scanner check the stream for potetial inconsistancies.

    The inode format is:
    Scon_id/con_id/con_id

    con_ids are the connection IDs. If more than one con_id is
    specified we merge all connections into the same stream based on
    arrival time.

    """
    stat_cbs = [ show_packets, combine_streams ]
    stat_names = [ "Show Packets", "Combined streams"]
#    specifier = 'S'
    
    def __init__(self, case, fd, inode, dbh=None):
        File.__init__(self, case, fd, inode, dbh)

        if self.cached_fd: return
        
        inode = inode.split("|")[-1]


    def readpkt(self,pkt_id,data_offset,start,end,result,result_offset):
        """ This function gets the data from pkt_id and pastes it into
        the file like object in result at offset result_offset.

        We basically do this: pkt_id.data[start:end] -> result[result_offset]
        @arg pkt_id: The packet ID
        @arg data_offset: The offset within the packet where the data starts
        @arg start: The start within the data segment where we want to copy from
        @arg end: The end point to copy till
        @arg result: A cStringIO object to copy the data to
        @arg result_offset: The position in the cStringIO to paste to
        """
##        dbh = DB.DBO(self.case)
##        dbh.execute("select offset from pcap where id=%r",(pkt_id))
##        row = dbh.fetch()

        self.fd.seek(data_offset+start)
        
        data = self.fd.read(end-start)
        result.seek(result_offset)
        result.write(data)

    def read(self,length = None):
        try:
            data=File.read(self,length)
            #print "Read %s from cache" % len(data)
            return data
        except IOError:
            pass

        if length==None:
            length=sys.maxint

        if length>self.size-self.readptr:
            length=self.size-self.readptr
        ##Initialise the output buffer:
        result = cStringIO.StringIO()

        ## Find out which packets fall within the range of interest
        self.dbh.execute("select packet_id, length, data_offset,seq from `connection` where con_id=%r and seq+length>=%r and seq<=%r order by seq",(
            self.con_id,
            self.isn+self.readptr, ## Start of range
            self.isn+self.readptr+length, ## End of range
            ))

        for row in self.dbh:
            self.seq = row['seq']
            ## This is the case where we start reading half way
            ## through a packet

            ##    row['seq']|--------->| row['length']
            ##      self.isn----->| readptr
            ##We are after  |<--->|
            if self.seq <= self.isn+self.readptr :
                start = self.isn + self.readptr - self.seq
            else:
                start = 0

            ## This is the case where the packet extends past where we
            ## want to read:
            ## LHS = Where the packet ends in the seq number space
            ## RHS = Where we want to stop reading

            ##        row['seq']|------->| row['length']
            ## self.isn--->readptr--->| length
            ##     We are after |<--->|
            if self.seq+row['length']>=self.isn+self.readptr+length:
                end=self.isn + self.readptr + length - self.seq

            ##    row['seq']|------->| row['length']
            ## self.isn--->readptr------>| length
            ## We are after |<------>|
            else:
                end=row['length']

            ## We create the output buffer here:
            ## current packet         |<--->|  (begings at start+row[seq])
            ## self.isn--->readptr|---------->| length
            ## Output buffer      |<--------->|
            ## We want the offset |<->|  for result_offset
         
            self.readpkt(
                row['packet_id'],
                row['data_offset'],
                start,
                end,
                result,
                start+self.seq-self.isn-(self.readptr))

        result.seek(0)
        data=result.read()
        result.close()
        self.readptr+=len(data)
        return data

    def get_packet_id(self, position=None):
        """ Gets the current packet id (where the readptr is currently at) """
        if not position:
            position = self.tell()
            
        self.dbh.execute("select con_id,isn from `connection_details` where inode=%r",(self.inode))
        row=self.dbh.fetch()
        if not row:
            self.dbh.execute("select con_id,isn from `connection_details` where con_id=%r",(self.con_id))
            row=self.dbh.fetch()
            
        con_id,isn = row['con_id'],row['isn']
        self.dbh.execute("""select packet_id from `connection` where
                         con_id = %r and seq <= (%r+%r) order by seq desc, length desc limit 1""",
                         (con_id, isn, position))
        row=self.dbh.fetch()
        return row['packet_id']

class OffsetFile(File):
    """ A simple offset:length file driver.

    The inode name specifies an offset and a length into our parent Inode.
    The format is offset:length
    """
    specifier = 'o'
    def __init__(self, case, fd, inode, dbh=None):
        File.__init__(self, case, fd, inode, dbh)

        ## We parse out the offset and length from the inode string
        tmp = inode.split('|')[-1]
        tmp = tmp[1:].split(":")
        self.offset = int(tmp[0])
        self.readptr=0
        
        ## Seek our parent file to its initial position
        self.fd.seek(self.offset)

        try:
            self.size=int(tmp[1])
        except IndexError:
            self.size=sys.maxint

    def seek(self,offset,whence=0):
        if whence==2:
            self.readptr=self.size+offset
        elif whence==1:
            self.readptr+=offset
        else:
            self.readptr=offset

        self.fd.seek(self.offset + self.readptr)

    def tell(self):
        return self.readptr
    
    def read(self,length=None):
        available = self.size - self.readptr
        if length==None:
            length=available
        else:
            if length > available:
                length = available

        if(length<0): return ''

        result=self.fd.read(length)
        
        self.readptr+=len(result)
        return result

import StringIO

## This is a memory cached version of the offset file driver - very useful for packets:
class MemroyCachedOffset(StringIO.StringIO,File):
    specifier = 'O'
    def __init__(self, case, fd, inode, dbh=None):
        File.__init__(self, case, fd, inode, dbh)

        ## We parse out the offset and length from the inode string
        tmp = inode.split('|')[-1]
        tmp = tmp[1:].split(":")
        fd.seek(int(tmp[0]))

        try:
            self.size=int(tmp[1])
        except IndexError:
            self.size=sys.maxint
            
        StringIO.StringIO.__init__(self, fd.read(self.size))
