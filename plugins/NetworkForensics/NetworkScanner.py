""" This module contains functions which are shared among many plugins """
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry
from pyflag.Scanner import *
import pyflag.Scanner as Scanner
import pyethereal
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework

def IP2str(ip):
    """ Returns a string representation of the 32 bit network order ip """
    tmp = list(struct.unpack('BBBB',struct.pack('L',ip)))
    tmp.reverse()
    return ".".join(["%s" % i for i in tmp])

## FIXME: This is currently not implemented...
class Storage:
    """ This class enables Network scanners to store persistant information between packets.

    We need to ensure that this persistant information does not consume too much memory. Every time a new piece of information is stored, we store the current packet number where it came from. Periodically we go through and expire those items which are too old.
    """
    data = {}
    ages = {}
    time_to_check = 100
    _time_to_check = 100
    max_age = 0
    too_old = 100
    
    def store(self,age,key,value):
        self.data[key]=value
        self.ages[key]=age
        if age>self.max_age:
            self.max_age=age

        self.check_me()

    def __getitem__(self,item):
        self.check_me()
        return self.data[item]

    def check_me(self):
        if self._time_to_check<=0:
            self._time_to_check=self.time_to_check
            for k in data.keys():
                if self.ages[k]+self.too_old<self.max_age:
                    del self.data[k]
                    del self.ages[k]
                    
        self._time_to_check-=1

class NetworkScanFactory(GenScanFactory):
    """ All network scanner factories come from here.

    This is used for scanners which need to invoke factories on VFS
    nodes. The VFS nodes are not network packets, so we only invoke
    those scanners which do not derive from this class. This class is
    therefore used to tag those scanners which only make sense to
    run on network traffic.
    """
    pass
                
class NetworkScanner(BaseScanner):
    """ This is the base class for all network scanners.
    """
    ## Note that Storage is the same object across all NetworkScanners:
    store = Storage()
    proto_tree = {}

    def finish(self):
        """ Only allow scanners to operate on pcapfs inodes """
        try:
            if self.fd.link_type:
                return True
        except:
            return False
    
    def process(self,data,metadata=None):
        """ Pre-process the data for all other network scanners """
        try:
            ## We may only scan network related filesystems like
            ## pcapfs.
            link_type = self.fd.link_type
        except:
            return
        
        ## We try to get previously set proto_tree. We store it in
        ## a metadata structure so that scanners that follow us
        ## can reuse it. This ensure we do not un-necessarily
        ## dissect each packet.
        self.packet_id = self.fd.tell()-1
          
        try:
            self.proto_tree = metadata['proto_tree'][self.packet_id]
        except KeyError,e:
            ## Ensure ethereal doesnt fiddle with the sequence numbers
            ## for us:
            pyethereal.set_pref("tcp.analyze_sequence_numbers:false")

            ## Now dissect it.
            self.proto_tree = pyethereal.Packet(data,self.packet_id,link_type)

            ## Store it for the future
            metadata['proto_tree']={ self.packet_id: self.proto_tree }

    def scan_as_file(self,inode):
        """ Scans inode as a file (i.e. without any network scanners). """
        fd=self.ddfs.open(inode=inode)
        factories = [ x for x in self.factories if not isinstance(x,NetworkScanFactory) ]

        Scanner.scanfile(self.ddfs,fd,factories)
        fd.close()

def find_reverse_stream(forward_stream,table,dbh):
    """ Given a connection ID and a table name, finds the reverse connection.

    return None if there is not reverse stream
    """
    dbh.execute("select * from connection_details_%s where con_id=%r",
                (table,forward_stream))
    
    row=dbh.fetch()
    
    dbh.execute("select con_id from connection_details_%s where src_ip=%r and src_port=%r and dest_ip=%r and dest_port=%r",(table,row['dest_ip'],row['dest_port'],row['src_ip'],row['src_port']))
    row=dbh.fetch()

    try:
        return row['con_id']
    except:
        return None
