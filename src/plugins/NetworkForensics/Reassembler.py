""" This module implements a simple stream reassembler.
"""
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
import struct,sys,StringIO
import pyflag.DB as DB
import pyflag.FileSystem as FileSystem
from pyflag.FileSystem import File
import pyflag.IO as IO
from pyflag.FlagFramework import query_type
from NetworkScanner import *
import struct,re,os
import reassembler
from pyflag.ColumnTypes import StringType, IntegerType, TimestampType
from pyflag.ColumnTypes import InodeIDType, IPType, PCAPTime
import pyflag.Reports as Reports
import pyflag.CacheManager as CacheManager

class DataType(StringType):
    hidden = True
    LogCompatible = False
    
    def __init__(self, name=None, combined_fd=None):
        StringType.__init__(self, name=name, column=name)
        self.combined_fd = combined_fd
        
    def select(self):
        return 'concat(connection.cache_offset, ",", connection.length)'

    def display(self, value, row, result):
        offset, length = value.split(",")
        ui=result.__class__(result)
        ## We read at most this many chars from the packet:
        self.combined_fd.seek(int(offset))
        data=self.combined_fd.read(min(int(length),50))
        
        if(len(data) ==50):
            data += "  ...."
            
        ui.text(data, sanitise='full', font='typewriter')
        return ui

class StreamFile(File):
    """ A File like object to reassemble the stream from individual packets.
    
    Note that this is currently a very Naive reassembler. Stream Reassembling is generally considered a very difficult task. The approach we take is to make a very simple reassembly, and have a different scanner check the stream for potetial inconsistancies.

    The inode format is:
    Sinode_id/inode_id/inode_id

    inode_ids are the connection IDs. If more than one inode_id is
    specified we merge all connections into the same stream based on
    arrival time.
    """
    specifier = 'S'

    def __init__(self, case, fd, inode):
        File.__init__(self,case, fd, inode)
        dbh = DB.DBO(self.case)
        
        ## Ensure we have an index on this column
        dbh.check_index("connection","inode_id")
        dbh.check_index("connection_details","inode_id")
        
        ## We use the inode column in the connection_details table to
        ## cache this so we only have to combine the streams once.
        inode = inode.split("|")[-1]
        self.inode_ids = [ int(x) for x in inode[1:].split("/")]

        ## Fill in some vital stats
        dbh.execute("select inode.inode_id, reverse, src_ip, dest_ip, src_port, dest_port, ts_sec, type from `connection_details` join inode on inode.inode_id = connection_details.inode_id where inode.inode=%r limit 1", self.inode)
        row=dbh.fetch()
        if not row:
            dbh.execute("select inode_id,reverse, src_ip, dest_ip, src_port, dest_port, ts_sec, type from `connection_details` where inode_id = %r", self.inode_ids[0])
            row = dbh.fetch()

        ## This updates our properties from the db
        if not row: return
        self.__dict__.update(row)

        ## We allow the user to ask for a number of streams which will
        ## be combined at the same time. This allows us to create a
        ## VFS node for both forward and reverse streams, or even
        ## totally unrelated streams which happen at the same time.
        self.look_for_cached()
        self.read(0)
        
        ## This is a cache of packet lists that we keep so we do not
        ## have to hit the db all the time.
        self.packet_list = None

    def make_tabs(self):
        names, cbs = File.make_tabs(self)

        names.extend( [ "Show Packets", "Combined stream"])
        cbs.extend([ self.show_packets, self.combine_streams ])

        return names, cbs

    def read(self,len=None):
        ## Call our baseclass to see if we have cached data:
        try:
            return File.read(self,len)
        except IOError:
            pass

        self.create_new_stream(self.inode_ids)
        self.look_for_cached()
        ## For the reassembler its sometimes legitimate to have no
        ## cached file - this is because the file length is 0 bytes,
        ## and the reassembler does not bother to create it
        try:
            return File.read(self,len)
        except IOError: return ''
        
    def create_new_stream(self,stream_ids):
        """ Creates a new stream by combining the streams given by the list stream_ids.
        
        @return the new stream id.
        """
        if len(stream_ids)<2: return
        
        ## Store the new stream in the cache:
        dbh = DB.DBO(self.case)

        ## This is a placeholder to reserve our inode_id
        dbh.insert('inode', inode=self.inode, _fast=True)
        self.inode_id = dbh.autoincrement()
        dbh.delete('inode', where="inode_id=%s" % self.inode_id, _fast=True)
        
        dbh2 = dbh.clone()

        ## These are the fds for individual streams
        fds = []
        for s in stream_ids:
            try:
                fd = CacheManager.MANAGER.open(dbh.case,
                                               "%s|S%s" % (self.fd.inode, s))
                fds.append(fd)
            except IOError,e:
                fds.append(-1)

        # These are the deltas to be applied to the sequence numbers of each
        # stream to bring it into an offset in the output file.
        deltas = [0,] * len(stream_ids)

        # Flags to indicate when the streams ISN is encountered
        initials = [ True,] * len(stream_ids)

        # The output file
        out_fd = CacheManager.MANAGER.create_cache_seakable_fd(dbh.case, self.inode,
                                                               inode_id=self.inode_id)

        min_packet_id = sys.maxint
        
        dbh.execute("select inode_id,seq,packet_id, length, cache_offset from `connection` where %s order by packet_id",(
            " or ".join(["inode_id=%r" % a for a in stream_ids])
            ))

        dbh2.mass_insert_start("connection")

        # This is the length of the output file
        outfd_len = 0
        outfd_position = 0
        for row in dbh:
            # This is the index for this specific stream in all the above arrays
            index = stream_ids.index(row['inode_id'])

            if min_packet_id > row['packet_id']:
                min_packet_id = row['packet_id']

            # First time we saw this stream - the seq is the ISN
            if initials[index]:
                deltas[index] -= row['seq'] - row['cache_offset']
                initials[index] = False

            # We need to find if we grew the output file at all:
            initial_len = outfd_len
            if row['seq'] + deltas[index]>0:
                outfd_position = row['seq']+deltas[index]
            
            # We only allow 64k to be written ahead - this is commonly
            # the window length and it stops weird sequence numbers
            # from growing the file too much
            if outfd_position - initial_len > 65000:
                outfd_position = initial_len

            try:
                #print "(Packet %s) Seeking to %s" % (row['packet_id'], outfd_position,)
                out_fd.seek(outfd_position)
            except Exception,e:
                print FlagFramework.get_bt_string(e)
                raise

            # Only try to write if there is a reverse file.
            if fds[index]:
                fds[index].seek(row['cache_offset'])
                data = fds[index].read(row['length'])
                #print "Writing %s %r" % (row['length'],data)
                out_fd.write(data)

            # Maintain the length of the file
            outfd_len = max(outfd_len, outfd_position+row['length'])

            # Basically each time we write a packet to the output fd we might
            # grow it. If we do grow it, we need to push the other streams
            # deltas to ensure that subsequent data will be written after the
            # newly written data. This is an approximation - but is adequate
            # when packets are out of order in an interactive protocol.
            for x in range(len(stream_ids)):
                if x != index:
                    deltas[x] += outfd_len-initial_len

            dbh2.mass_insert(
                inode_id=self.inode_id,
                packet_id=row['packet_id'],
                seq=outfd_position,
                length=row['length'],
                cache_offset=outfd_position,
                
                # This is the original id this
                # packet came from
                original_id = row['inode_id'])

        dbh2.mass_insert_commit()

        ## Close the output files, and the input files:
        out_fd.close()
        for fd in fds:
            try:
                fd.close()
            except: pass
        
        ## Now create the stream in the VFS:
        fsfd = FileSystem.DBFS(self.case)
        inode = self.inode[:self.inode.rfind("|")] +"|S%s" % stream_ids[0]
        old_pathname, inode, inode_id = fsfd.lookup(inode = inode)
        if not old_pathname: old_pathname = "lost+find/%s" % inode
        pathname = os.path.dirname(old_pathname)+"/combined"
       
        ## Get mtime 
        try:
            dbh2.execute("select pcap.ts_sec from pcap where pcap.id=%r", min_packet_id)
            metamtime=dbh2.fetch()['ts_sec']
        except (DB.DBError, TypeError), e:
            pyflaglog.log(pyflaglog.WARNING, "Failed to determine mtime of newly combined stream %s" % self.inode)
            metamtime=None
        
        ## Create VFS Entry 
        self.inode_id = fsfd.VFSCreate(None, self.inode, pathname, size=outfd_len, mtime=metamtime, inode_id=self.inode_id)
        
        ##  We also now fill in the details for the combined stream in 
        ##  the connection_details table...
        try:
            dbh2.insert("connection_details",
                        ts_sec = metamtime,
                        inode_id = self.inode_id,
                        src_ip = self.src_ip,
                        src_port = self.src_port,
                        dest_ip = self.dest_ip,
                        dest_port = self.dest_port,
                        )
        except DB.DBError, e:
            pyflaglog.log(pyflaglog.ERROR, "Failed to set the mtime for the combined stream %s" % self.inode)

    def get_packet_id(self, position=None):
        """ Gets the current packet id (where the readptr is currently at) """
        if not position:
            position = self.tell()

        if self.packet_list==None:
            dbh = DB.DBO(self.case)
            dbh.execute("""select packet_id,cache_offset,length from `connection` where inode_id = (select inode_id from inode where inode=%r limit 1) order by cache_offset asc, length desc """,
                        (self.inode))
            self.packet_list = [ (row['packet_id'],row['cache_offset'],row['length']) for row in dbh ]

        ## Now try to find the packet_id in memory:
        result = 0
        for packet_id,cache_offset,length in self.packet_list:
            #print self.inode_id, position, packet_id,cache_offset,length
            if cache_offset + length >= position:
                return packet_id

        return 0

    def packet_data(self):
        """ A generator which generates a packet at a time """
        self.get_packet_id(0)
        for packet_id,cache_offset,length in self.packet_list:
            self.seek(cache_offset)
            data = self.read(length)
            yield packet_id, cache_offset, data

    def get_packet_ts(self, position=None):
        """ Returns the timestamp of the current packet """
        packet_id = self.get_packet_id(position)
        dbh=DB.DBO(self.case)
        dbh.execute("select ts_sec from pcap where id = %r" , packet_id)
        row = dbh.fetch()
        if row:
            return row['ts_sec']

    def get_combined_fd(self):
        """ Returns an fd opened to the combined stream """
        ## If we are already a combined stream, we just return ourselves
        inode = self.inode.split("|")[-1]

        if '/' in inode:
            self.forward_id = int(inode[1:].split("/")[0])
            return self

        self.forward_id = self.inode_id
        fsfd = FileSystem.DBFS(self.case)
        return fsfd.open(inode="%s/%s" % (self.inode,self.reverse))

    def combine_streams(self, query,result):
        """ Show both ends of the stream combined.

        In each screenfull we show a maximum of MAXSIZE characters per connection. We stop as soon as either direction reaches this many characters.
        """
        combined_fd = self.get_combined_fd()

        try:
            limit = int(query['stream_limit'])
        except:
            limit = 0

        number_of_rows = 0
        dbh = DB.DBO(self.case)
        dbh.execute("select * from `connection` where inode_id = %r order by cache_offset limit %s, %s", (combined_fd.lookup_id(), limit, config.PAGESIZE))

        for row in dbh:
            number_of_rows += 1
            combined_fd.seek(row['cache_offset'])
            ## Get the data:
            data=combined_fd.read(row['length'])
            if row['original_id']==self.forward_id:
                result.text(data,style="blue",font='typewriter',sanitise='full',wrap='full')
            else:
                result.text(data,style="red",font='typewriter',sanitise='full',wrap='full')    

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

    def show_packets(self,query,result):
        """ Shows the packets which belong in this stream """
        combined_fd = self.get_combined_fd()

        result.table(
            elements = [ IntegerType('Packet ID','packet_id',
                                    link = query_type(family="Network Forensics",
                                                      report='View Packet',
                                                      case=query['case'],
                                                      open_tree ="/eth/payload/payload/data",
                                                      __target__='id')),
                         PCAPTime('Date','packet_id'),
                         IntegerType('Length','length'),
                         DataType('Data', combined_fd = combined_fd)
                         ],
            
            table= 'connection',
            where = 'inode_id="%s" ' % combined_fd.lookup_id(),
            case=query['case']
            )

    def explain(self, query, result):
        self.fd.explain(query, result)
        tmp = result.__class__(result)
        dbh = DB.DBO(self.case)
        combined_fd = self.get_combined_fd()

        tmp.row("Packet ID", "Offset", "Length", type='heading', **{'class': 'explain'})
        dbh.execute("select packet_id, offset, pcap.length as length from `connection` join pcap on pcap.id=`connection`.packet_id where inode_id = %r order by cache_offset", combined_fd.lookup_id())
        for row in dbh:
            tmp.row(row['packet_id'], row['offset'], row['length'], **{'class': 'explain'})

        result.row("Stream %s" % self.inode, tmp, **{'class':'explainrow'})

class ViewConnections(Reports.PreCannedCaseTableReports):
    """ View the connection table """
    description = "View the connection table"
    name = "/Network Forensics/View Connections"
    family = "Network Forensics"
    default_table = "ConnectionDetailsTable"
    columns = ['Inode', "Timestamp", "Source IP", "Source Port", "Destination IP",
               "Destination Port", "Type"]

config.add_option("MAX_SESSION_AGE", default=100000, type='int',
                  help="Maximum age (in packets) for a session before it "
                  "will be considered terminated.")
                  

import pyflag.tests

class NetworkForensicTests2(pyflag.tests.ScannerTest):
    """ Tests Reassembler with difficult to reassemble streams """
    test_case = "PyFlagTestCase"
    test_file = "stdcapture_0.4.pcap.e01"
    subsystem = "EWF"
    fstype = 'PCAP Filesystem'
