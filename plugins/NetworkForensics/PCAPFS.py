""" Implements a Pyflag filesystem driver for processing of pcap files.

We require libethereal for actually doing the processing, and access
to pyethereal - the python bindings for libethereal.

When a pcap file (or really any format that is supported by ethereal)
is loaded into a case, we create a virtual file in the VFS called
'/rawdata' at the root directory. This file will be scanned by the
scanners. The scanners will use the PCAPFile object to read this
file. We use an inode driver specifier of 'p' for this special file.

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
import pyethereal

description = "Network Forensics"

class PCAPFS(DBFS):
    """ This implements a simple filesystem for PCAP files.

    We start off with a single file '/rawdata'. The scanners will do the rest.
    """
    name = 'PCAP Filesystem'

    def load(self):
        DBFS.load(self)
        sdbh = DB.DBO(self.case)
        ## This sets up the schema for pcap
        sdbh.MySQLHarness("%s/pcaptool -c -t %s" %(config.FLAG_BIN,self.table))
        ## This populates it
        sdbh.MySQLHarness("%s/pcaptool -t %s" % (config.FLAG_BIN,self.table))

        ## Add our VFS node
        self.VFSCreate(None,"p0",'rawdata');

    def delete(self):
        DBFS.delete(self)
        sdbh = DB.DBO(self.case)
        sdbh.MySQLHarness("%s/pcaptool -d -t %s" % (config.FLAG_BIN,self.table))

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
        
        dbh.execute("select count(*) as size from pcap")
        row=dbh.fetch()
        self.size = row['size']

    def read(self,length=None):
        ## If we dont specify the length we get the full packet. Must
        ## be smaller than MAXINT
        if length==None: length=sys.maxint

        ## Find out the offset in the file of the packet:
        self.dbh.execute("select * from pcap where id=%r",(self.readptr,))
        row=self.dbh.fetch()
        self.fd.seek(row['offset'])
        
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
                result.meta_selector(case=query['case'],property='fsimage')
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

        print "%r" % packet,len(packet)
        ## Now dissect it.
        proto_tree = pyethereal.Packet(packet,id)
        
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
                print peer.name(),peer
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

            result.heading("%s" % node.name())
            result.text("value is %s" % node.value(),color='red')

        result.tree(tree_cb=tree_cb, pane_cb=pane_cb, branch=['/'])
