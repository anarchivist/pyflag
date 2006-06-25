#!/usr/bin/python
# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
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

""" A library for reading metadata from OLE2 files (MS word/office).

Based heavily on Laola documentation:

http://user.cs.tu-berlin.de/~schwartz/pmh/guide.html
"""
import struct,sys
import format
from format import *

class Tree:
    """ A simple tree implementation """
    def __init__(self,data,parent):
        self.children=[]
        self.data=data
        self.parent=parent

    def add_child(self,data):
        """ Adds a new child containing data to this node.

        Note, only unique children are allowed.
        """
        child = self.__class__(data,self)
        self.children.append(child)
        return child

    def add_peer(self,data):
        return self.parent.add_child(data)

    def find_child(self,data):
        """ Searches through our children to find a node equal to data.

        @return tree node whose data is the same as data.
        """
        if data==self.data: return self
        
        for c in self.children:
            result=c.find_child(data)
            if result: return result

        return None

    def repr(self):
        """ The way we would like to represent the data """
        return self.data

    def __str__(self):
        result='\n%s' % self.repr()
        for c in self.children:
            r=("%s" % c).split("\n")
            result+="\n    ".join(r)

        return result

class PropertyTree(Tree):
    """ A Tree specifically designed for printing properties """
    def repr(self):
        return self.data['pps_rawname']    

class OLEException(Exception):
    """ OLE specific exception """

class OLEHeader(SimpleStruct):
    def size(self):
        """ The OLE Header size is always fixed """
        return 0x200
    
    def init(self):
        self.fields =[
            [ BYTE_ARRAY,8,"magic" ],
            [ LONG_ARRAY,4,'clsid'],
            [ WORD,1,'minor_version'],
            [ WORD,1,'major_version'],
            [ LONG,1,'endianness'],
            [ LONG,1,'bb_shift'],
            [ LONG,1,'sb_shift'],
            [ BYTE_ARRAY,4,'reserved'],
            [ LONG,1,'number_of_bbd_blocks'],
            [ LONG,1,'dirent_start'],
            [ LONG,1,'unknown2'],
            [ LONG,1,'threshold'],
            [ LONG,1,'sbd_startblock'],
            [ LONG,1,'no_sbd'],
            [ LONG,1,'metab_start'],
            [ LONG,1,'number_metab'],
            [ DepotList,1, 'bbd_list'],
            ]

class DepotList(LONG_ARRAY):
    """ This is an array of variable size which ends when one of the members is -1.

    The Depot is a list of block indexes which form chains. By starting at a given offset, a chain is found by reading the next block offset from the depot. See follow_chain.
    """
    def read(self,data):
        result=[]
        offset=0
        while 1:
            a=LONG(data[offset:],parent=self)
            offset+=a.size()
            result.append(a)
            if a.get_value()<0:
                break

        return result

class PPS_TYPE(BYTE_ENUM):
    types = { 1:'dir', 2:'file', 5:'root' }

class RawString(UCS16_STR):
    """ Unicode String based on string/length """        
    def read(self,data):
        size=WORD(data[0x40:]).get_value()
        if size>0:
            result=UCS16_STR(data,size).read(data)
        else:
            result=''
            
        return result

    def size(self):
        ## This is a fixed size record
        return 0x40+2
    
class PropertySet(SimpleStruct):
    """ A property set.

    This is effectively an inode in the OLE2 filesystem. Each PropertySet belongs in the tree below its parent and next to its prev/next peers. Note that prev/next do not form a complete list (i.e. the next PropertySet might not have us as a prev link at all).
    """
    def init(self):
        self.fields=[
            [ RawString,1,'pps_rawname'],
            [ PPS_TYPE,1,'pps_type'],
            [ BYTE,1,'pps_uk0'],
            [ LONG,1,'pps_prev'],
            [ LONG,1,'pps_next'],
            [ LONG,1,'pps_dir'],
            [ CLSID,1,'pps_clsid'],
            [ LONG,1,'pps_flags'],
            [ WIN_FILETIME, 1,'pps_ts1'],
            [ WIN_FILETIME, 1,'pps_ts2'],
            [ LONG,1,'pps_sb'],
            [ LONG,1,'pps_size'],
            [ LONG,1,'pad'],
            ]

class PropertySetArray(ARRAY):
    target_class=PropertySet
        
class OLEFile:
    """ A class representing the file """

    ## The blocksize of the large blocks
    blocksize=0x200
    ## The blocksize of small blocks
    small_blocksize=0x40

    ## The index of the root property
    root_dir_index=0
    
    def __init__(self,data):
        self.data=data
        self.header = OLEHeader(data)
        #Check the magic:
        if self.header['magic'] != '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            raise OLEException("File Magic is not correct %s" % self.header['magic'])

        ## Read the big block depot
        self.block_list = self.read_depot(self.header['bbd_list'],data,self.blocksize)

        ## Build the root block chain:
        self.root_blocks = self.follow_chain(self.header['dirent_start'].get_value(), self.block_list)

        ## The root chain is the chain of blocks for big blocks
        self.root_chain = self.read_run(self.root_blocks,
                                        self.data[self.header.size():],
                                        self.blocksize)

        ## Read property sets, there should be len(root_chain)/small_blocksize
        ## properties. Not all of them make sense though...
        self.properties = PropertySetArray(
            self.root_chain, ## Data
            len(self.root_chain)/0x80 ## Number of elements
            )

        self.small_chain = self.cat(self.properties[0])

        ## This builds an internal tree representation of the file
        self.root_tree =PropertyTree(self.properties[0],None)
        self.add_to_tree(self.properties[0],self.root_tree)


    def read_depot(self,list,data,blocksize):
        result=[]
        for i in list:
            v=i.get_value()

            if v>=0:
                result.extend(
                    LONG_ARRAY(data[v * self.blocksize + self.header.size():],
                               self.blocksize/4).get_value()
                    )
        return result

    def cat(self,property,force=None):
        """ returns the data within each property """
        size=property['pps_size'].get_value()
        pps_sb = property['pps_sb'].get_value()
        t = property['pps_type']
        threshold=self.header['threshold'].get_value()
        
        ## only attempt to read files here... We can not read dirs or
        ## unknowns. If the user really want us to do this, they can
        ## force us..
        if (t!='root' and t!='file') and not force:
            print "Dont know how to read property %s" % t
            return ''

        ## The root node is always taken from the big block list. If
        ## the size is bigger than the threshold, we get it from the
        ## big block list, otherwise from the small blocklist
        if size>=threshold or t=='root':
            ## Read from big blocks

            blocks = self.follow_chain(pps_sb, self.block_list)
            data=self.read_run(blocks,self.data[self.blocksize:],self.blocksize)
            return data[:size]
        else:
            ## Read from small blocks - Note: small_chain contains the
            ## reassembled data of all the small blocks. It is
            ## effectively the content of the root file.
            return self.small_chain[pps_sb*self.small_blocksize:pps_sb*self.small_blocksize+size]
        
    def root(self):
        """ Return the root node """
        return self.properties[self.root_dir_index]
    
    def ls(self,property):
        """ Given a property set, returns an array of file properties under that directory """
        node=self.root_tree.find_child(property)
        for child in node.children:
            yield child.data

    def  follow_chain(self,start,depot):
        """ Follows the chain through the given depot returning a list of blocks in the chain.
        
        @arg start: A starting block for the chain.
        @arg depot: A depot used for following the chains. A depot is just an array of blocks
        """
        result=[start]
        while result[-1]!=-2:
            result.append(depot[result[-1]])
            
        return result

    def read_run(self,run,data,blocksize):
        """ Reads a chain specified by run and returns it.

        @arg run: A list of blocks that build this chain
        """
        result=[ data[blocksize*(i):blocksize*(i+1)] for i in run if i>=0 ]
        result = ''.join(result)
        return result

    def add_to_tree(self,p,node):
        """ This is used to build an internal tree representation of the data """
        next=p['pps_next'].get_value()
        if next>0:
            np=self.properties[next]
            peer=node.add_peer(np)
            self.add_to_tree(np,peer)

        prev=p['pps_prev'].get_value()
        if prev>0:
            np=self.properties[prev]
            peer=node.add_peer(np)
            self.add_to_tree(np,peer)

        child=p['pps_dir'].get_value()
        if child>0:
            np=self.properties[child]
            c=node.add_child(np)
            self.add_to_tree(np,c)

if __name__ == "__main__":
    fd=open(sys.argv[1],'r')
    data=fd.read()
    fd.close()
    print sys.argv[1]
    a = OLEFile(data)
    count=0
    
    for p in a.properties:
        print "Property %s" % (count)
        print "%r"% p['pps_rawname'].get_value()
        print p
        data = a.cat(p)
        print "Data is %r length %s" % (data[:100],len(data))
        count+=1

    print [ x['pps_rawname'].get_value() for x in a.ls(a.root())]
    def print_dir(dir,prefix):
	print "%s" % dir['pps_rawname']
        for file in a.ls(dir):
            print "%s%s" % (prefix,file['pps_rawname'])
            print_dir(file,prefix+"  ")

    print_dir(a.root(),'')
