# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
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

""" This module contains classes considered to be part of the core functionality of PyFlag.

These are needed by both the DiskForensics and NetworkForensics
"""
import pyflag.FileSystem as FileSystem
import pyflag.IO as IO
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import os.path
import pyflag.DB as DB

class IO_File(FileSystem.File):
    """ A VFS Driver to make the io source available.

    Basically we proxy the IO source driver in here.
    """
    specifier = "I"

    def __init__(self, case, fd, inode):
        FileSystem.File.__init__(self, case, fd, inode)

        ## The format of the inode is Iname .Where name is the name of
        ## the IO source.
        self.name = inode[1:]
        self.io = IO.open(case, self.name)
        self.size = self.io.size

        dbh = DB.DBO(self.case)
        ## IO Sources may have block_size specified:
        try:
            dbh.execute("select value from filesystems where iosource=%r and property='block_size' limit 1", self.name);
            self.block_size = int(dbh.fetch()["value"])
        except TypeError:
            pass

        ## This source should not be scanned directly.
        self.ignore = True

    def read(self, length=None):
        return self.io.read(length)

    def seek(self, offset, rel=0):
        if rel==0:
            return self.io.seek(offset)
        elif rel==1:
            return self.io.seek(offset + self.tell())
        elif rel==2:
            return self.io.seek(offset + self.size)

    def tell(self):
        return self.io.tell()
        
    def explain(self, result):
        tmp = result.__class__(result)
        self.io.explain(tmp)
        dbh = DB.DBO(self.case)    
        result.row("IO Subsys %s:" % self.name, tmp, valign="top")
        result.row("Mount point",dbh.get_meta("mount_point_%s" % self.name))

import sys

class OffsetFile(FileSystem.File):
    """ A simple offset:length file driver.

    The inode name specifies an offset and a length into our parent Inode.
    The format is offset:length
    """
    specifier = 'o'
    def __init__(self, case, fd, inode):
        FileSystem.File.__init__(self, case, fd, inode)

        ## We parse out the offset and length from the inode string
        tmp = inode.split('|')[-1]
        tmp = tmp[1:].split(":")
        self.offset = int(tmp[0])
        self.readptr=0

        ## Seek our parent file to its initial position
        self.fd.seek(self.offset)

        try:
            self.size=int(tmp[1])
            if self.size == 0: self.size=sys.maxint
        except IndexError:
            self.size=sys.maxint

        # crop size if it overflows IOsource
        # some iosources report size as 0 though, we must check or size will
        # always be zero
        if fd.size != 0 and self.size + self.offset > fd.size:
            self.size = fd.size - self.offset

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

#### This is a memory cached version of the offset file driver - very useful for packets:
##class MemoryCachedOffset(StringIO.StringIO, FileSystem.File):
##    specifier = 'O'
##    def __init__(self, case, fd, inode):
##        FileSystem.File.__init__(self, case, fd, inode)

##        ## We parse out the offset and length from the inode string
##        tmp = inode.split('|')[-1]
##        tmp = tmp[1:].split(":")
##        fd.seek(int(tmp[0]))

##        try:
##            self.size=int(tmp[1])
##        except IndexError:
##            self.size=sys.maxint
            
##        StringIO.StringIO.__init__(self, fd.read(self.size))

class Help(Reports.report):
    """ This facility displays helpful messages """
    hidden = True
    family = "Misc"
    name = "Help"
    parameters = {'topic':'any'}

    def form(self,query,result):
        result.textfield("Topic",'topic')
    
    def display(self,query,result):
        fd=open("%s/%s.html" % (config.DATADIR, os.path.normpath(query['topic'])))
        result.result+=fd.read()
        result.decoration='naked'

## IO subsystem unit tests:
import unittest
import md5,random,time
import pyflag.tests as tests
from pyflag.FileSystem import DBFS

class IOSubsysTests(tests.FDTest):
    """ Testing IO Subsystem handling """
    def setUp(self):
        self.fd = IO_File('PyFlagNTFSTestCase', None, 'Itest')

class OffsetFileTests(tests.FDTest):
    """ Testing OffsetFile handling """
    test_case = "PyFlagNTFSTestCase"
    test_inode = "Itest|o1000:1000"
    
    def testMisc(self):
        """ Test OffsetFile specific features """
        ## Make sure we are the right size
        self.assertEqual(self.fd.size, 1000)
        
        fd2 = IO_File('PyFlagNTFSTestCase', None, 'Itest')
        fd2.seek(1000)
        data=fd2.read(1000)

        self.fd.seek(0)
        data2 = self.fd.read()

        ## Make sure that we are reading the same data with and
        ## without the offset:
        self.assertEqual(data2, data)
