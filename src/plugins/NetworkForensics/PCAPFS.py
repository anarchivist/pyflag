""" Implements a Pyflag filesystem driver for processing of pcap files.

When a pcap file is loaded into a case, we create a virtual file in
the VFS called '/rawdata' at the root directory. This file will be
scanned by the scanners. The scanners will use the PCAPFile object to
read this file. We use an inode driver specifier of 'p' for this
special file.

The PCAPFile driver is a little unusual:

- seek(offset). Offset is interpreted as a packet id, seeking to that packet will cause read to return it. Note that packet ids are incremental integers.

- read(length): Causes the current packet to be read. Note that we only return a single packet, even if we return a short read.

The effect of this interface is that you can not assume:

fd.seek(x)
y=fd.read(1000)
fd.tell != x+y != x+1000

Further (fd.read(length)<length) does not indicate the end of
file. The end of file is always indicated by fd.read(length)==0. This
is a common misconception that is fueled by the fact that regular file
reads never return less data than is available and requested. However
this is common on sockets, so code should always be testing for a zero
return.
"""
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
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
from pyflag.FileSystem import DBFS,File
import pyflag.logging as logging
import pyflag.IO as IO
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.ScannerUtils as ScannerUtils
import pyflag.Registry as Registry
import os,sys
import dissect

description = "Network Forensics"

def draw_only_PCAPFS(query,result):
    """ Draws a selector with only PCAPFS filesystems """
    dbh = DB.DBO(query['case'])
    dbh2 = DB.DBO(query['case'])
    images = []
    ## Get a list of filesystems which are of type PCAPFS:
    dbh.execute("select * from meta where property='fsimage'")
    for row in dbh:
        t=dbh2.get_meta("fstype_%s" % row['value'])
        if t.startswith("PCAP"):
            images.append(row['value'])

    result.const_selector("Select filesystem",'fsimage',images,images)


class PCAPFS(DBFS):
    """ This implements a simple filesystem for PCAP files.

    We start off with a single file '/rawdata'. The scanners will do the rest.
    """
    name = 'PCAP Filesystem'

    def load(self):
        DBFS.load(self)
        sdbh = DB.DBO(self.case)
        ## This sets up the schema for pcap
        sdbh.MySQLHarness("%s/pcaptool -c -t pcap_%s" %(config.FLAG_BIN,self.table))
        ## This populates it 
        sql =  "%s/iowrapper  -i %s -o %s -f foo -- %s/pcaptool -t pcap_%s foo"%(config.FLAG_BIN,
                                                     self.iosource.subsystem,
                                                     self.iosource.make_parameter_list(),config.FLAG_BIN,
                                                     self.table)

        sdbh.MySQLHarness(sql)

        ## Add our VFS node
        self.VFSCreate(None,"p0",'rawdata');

        ## Creates indexes on id:
        sdbh.check_index("pcap_%s" % self.table,'id')

    def delete(self):
        DBFS.delete(self)
        sdbh = DB.DBO(self.case)
        sdbh.MySQLHarness("%s/pcaptool -d -t pcap_%s" % (config.FLAG_BIN,self.table))

class PCAPFile(File):
    """ A file like object to read packets from a pcap file.

    Read the module header for usage warnings. Many normal assumptions
    do not work with this driver.
    """
    specifier = 'p'

    def __init__(self, case, table, fd, inode):
        """ This is a top level File driver for opening pcap files.

        Note that pcap files are stored in their own filesystem. We expect the following initialisation:
        @arg fd: is an io source for the pcap file
        @arg inode: The inode of the pcap file in the pcap filesystem, currently ignored.
        """
        File.__init__(self, case, table, fd, inode)
        ## Calculates the size of this file:
        dbh = DB.DBO(self.case)
        self.dbh=dbh
        
        dbh.execute("select max(id) as max from pcap_%s" % table)
        row=dbh.fetch()
        self.size = row['max']

    def read(self,length=None):
        ## If we dont specify the length we get the full packet. Must
        ## be smaller than MAXINT
        if length==None: length=sys.maxint
        if self.readptr>=self.size: return ''

        ## Find out the offset in the file of the packet:
        self.dbh.execute("select * from pcap_%s where id=%r",(self.table,self.readptr,))
        row=self.dbh.fetch()
        self.fd.seek(row['offset'])

        self.link_type = row['link_type']
        self.ts_sec = row['ts_sec']
        self.readptr+=1
        
        if length<row['length']:
            return self.fd.read(length)
        else:
            return self.fd.read(row['length'])

class ViewDissectedPacket(Reports.report):
    """ View Dissected packet in a tree. """
    parameters = {'fsimage':'fsimage','id':'numeric'}
    name = "View Packet"
    family = "Network Forensics"
    description = "Views the packet in a tree"

    def form(self,query,result):
        try:
            result.case_selector()
            if query['case']!=config.FLAGDB:
                draw_only_PCAPFS(query,result)
            result.textfield('Packet ID','id')
        except KeyError:
            pass

    def display(self,query,result):        
        ## Get the IO Source
        io=IO.open(query['case'],query['fsimage'])

        ## Open the PCAPFS filesystem
        fsfd = Registry.FILESYSTEMS.fs['PCAPFS']( query["case"], query["fsimage"], io)
        ## Open the root file in the filesystem
        fd = fsfd.open(inode='p0')

        ## This is the packet we are after
        id = int(query['id'])
        
        fd.seek(id)
        
        ## This is the binary dump of the packet
        packet = fd.read()

        ## This is the link type of the packet (Etherenet by default)
        try:
            link_type = fd.link_type
        except AttributeError:
            link_type = 1

        ## Now dissect it.
        proto_tree = dissect.dissector(packet,link_type)
        
        def tree_cb(branch):
            try:
                if branch:
                    node = proto_tree[branch[-1]]
                else:
                    node = proto_tree
            except KeyError:
                node=proto_tree

            child = node.get_child()
            if not child: return
            for peer in child:
                if peer.get_child():
                    yield  ( peer.name(), "%s" % peer,'branch')
                else:
                    yield  ( peer.name(),"%s" % (peer),'leaf')
        
        def pane_cb(branch,result):
            try:
                if branch:
                    node = proto_tree[branch[-1]]
                else:
                    node = proto_tree
            except KeyError:
                node=proto_tree

            result.heading("%s" % node)
            start = node.start()
            length = node.length()
            ## Draw the hexdump
            h=FlagFramework.HexDump(packet,result)
            h.dump(highlight=start,length=length)

        result.tree(tree_cb=tree_cb, pane_cb=pane_cb, branch=['/'],layout="vertical")

        ## We add forward and back toolbar buttons to let people move
        ## to next or previous packet:
        new_query=query.clone()
        if id>0:
            del new_query['id']
            new_query['id']=id-1
            result.toolbar(text="Previous Packet",icon="stock_left.png",link=new_query)
        if id<fd.size:
            del new_query['id']
            new_query['id']=id+1
            result.toolbar(text="Next Packet",icon="stock_right.png",link=new_query)
