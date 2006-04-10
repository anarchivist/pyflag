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

""" This module contains classes considered to be part of the core functionality of PyFlag.

These are needed by both the DiskForensics and NetworkForensics
"""
import pyflag.FileSystem as FileSystem
import pyflag.IO as IO

class IO_File(FileSystem.File):
    """ A VFS Driver to make the io source available.

    Basically we proxy the IO source driver in here.
    """
    specifier = "I"

    def __init__(self, case, fd, inode, dbh=None):
        FileSystem.File.__init__(self, case, fd, inode, dbh)

        ## The format of the inode is Iname .Where name is the name of
        ## the IO source.
        self.name = inode[1:]
        self.io = IO.open(case, self.name)

        ## IO Sources may have block_size specified:
        try:
            self.dbh.execute("select value from filesystems where iosource=%r and property='block_size'", self.name);
            self.block_size = int(self.dbh.fetch()["value"])
        except TypeError:
            pass


    def read(self, length=None):
        return self.io.read(length)

    def seek(self, offset, rel=0):
        if rel==0:
            return self.io.seek(offset)
        elif rel==1:
            return self.io.seek(offset + self.tell())

    def tell(self):
        return self.io.tell()
        
    def explain(self, result):
        tmp = result.__class__(result)
        self.io.explain(tmp)
        result.row("IO Subsys %s:" % self.name, tmp, valign="top")
        result.row("Mount point",self.dbh.get_meta("mount_point_%s" % self.name))
