""" This module contains functions which are shared among many plugins """
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry
from pyflag.Scanner import *
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

class NetworkScanner(BaseScanner):
    """ This is the base class for all network scanners.
    """
    def process(self,data,metadata=None):
        """ Pre-process the data for all other network scanners """
        ## We try to get previously set proto_tree. We store it in
        ## a metadata structure so that scanners that follow us
        ## can reuse it. This ensure we do not un-necessarily
        ## dissect each packet.
        try:
            self.packet_id = self.fd.tell()-1
            self.proto_tree = metadata['proto_tree'][self.packet_id]
        except KeyError,e:
            ## Ensure ethereal doesnt fiddle with the sequence numbers
            ## for us:
            pyethereal.set_pref("tcp.analyze_sequence_numbers:false")

            ## Now dissect it.
            self.proto_tree = pyethereal.Packet(data,self.packet_id,self.fd.link_type)

            ## Store it for the future
            metadata['proto_tree']={ 'packet_id': self.proto_tree }
