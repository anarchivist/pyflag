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
#  Version: FLAG $Name:  $ $Date: 2004/10/07 13:04:02 $
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

""" Module used to interface to the flag version of sleuthkit.

This module provides an interface to the database management functions provided by the dbtool executable. dbtool generates SQL in a suitable format to be used for populating the Flag Databases. This format is then understood by the standard FileSystem.FileSystem class.

"""
import os,os.path
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.DB as DB
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
import time
import math
import bisect

def filesystems(iosource):
    """ This function returns a tuple containing the list of filesystems, and their names which are supported for the given IO source.

    @arg iosource: An already opened IO source (gotten by IO.open())
    @return: A tuple containing two tuples, the first is the names of each filesystem, and the second is the sleuthkit tag.
    """
    filesystems_dict={'default':(['linux-ext2','linux-ext3','bsdi','fat','fat12','fat16','fat32','freebsd','netbsd','ntfs','openbsd','solaris'],['Linux ext2','Linux ext3','BSDi FFS','auto-detect FAT','FAT12','FAT16','FAT32','FreeBSD FFS','NetBSD FFS','NTFS','OpenBSD FFS','Solaris FFS']), 'mounted':(['Mounted'],['mounted'])}
    class_name = "%s" % iosource.__class__
    try:
        return filesystems_dict[(class_name.split("."))[-1]]
    except KeyError:
        return filesystems_dict['default']

def load_sleuth(case,fstype,table,iosource):
    """ Loads the filesystem data into the case """

    # get the IO object to load, we dont really need to do this,
    # but its the easiest way to get the option string and helps to
    # ensure the next step will actually work.
    fd = IO.open(case,iosource)

    sdbh = DB.DBO(case)
    sdbh.MySQLHarness("%s -t %s -d create blah" %(config.SLEUTHKIT,table))
    
    class_name = (("%s" % fd.__class__).split("."))[-1]

    ## Handle special cases for unusual filesystems here
    if class_name == "mounted":

        dbh = DB.DBO(case)
        ## This deals with a mounted filesystem -
        ## we dont get the full forensic joy, but we can handle more filesystems than sleuthkit can.
        ## The downside is that the user has to mount the filesystem first,
        ## we also need to be running as root or we may not be able to stat all the files :-(
        def insert_into_table(mode,root,name):
            rel_root="/"+root[len(fd.mount_point):]+"/"
            if rel_root=="//": rel_root="/"
            s=os.stat(os.path.join(root,name))
            dbh.execute("insert into file_%s set inode=%r,mode=%r,status='alloc',path=%r,name=%r",(table, s.st_ino, mode, rel_root, name))
            try:
                link=os.readlink("%s/%s" % (root,name))
            except OSError:
                link=''
            
            dbh.execute("insert into inode_%s set inode=%r,uid=%r,gid=%r, mtime=%r,atime=%r,ctime=%r,mode=%r,links=%r,link=%r,size=%r",(table,s.st_ino,s.st_uid,s.st_gid,s.st_mtime,s.st_atime,s.st_ctime,str(oct(s.st_mode))[1:],s.st_nlink,link,s.st_size))

        ## Just walk over all the files and stat them all building the tables.
        for root, dirs, files in os.walk(fd.mount_point):
            for name in dirs:
                insert_into_table('d/d',root,name)
            for name in files:
                insert_into_table('r/r',root,name)

        ## End mounted filesystem handling
        return

    opts = ""
    for i in range(len(fd.parameters)-1):
        for j in range(len(fd.options[i+1])):
            opts += "%s=%s " % (fd.parameters[i+1][3:], fd.options[i+1][j])
    # run sleuthkit
    sdbh.MySQLHarness("%s -t %s -f %s -i %s %s"%(config.SLEUTHKIT,table,fstype,fd.options[0][0],opts))

def del_sleuth(case, table):
    """ Drops the tables for the given iosource identifier """
    dbh = DB.DBO(case)
    dbh.MySQLHarness("%s -t %s -d drop" %(config.SLEUTHKIT,table))


