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
#  Version: FLAG 0.4 (12-02-2004)
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

""" Python implementation of the interface to strings:

strings - print the strings of printable characters in files.
"""

import pyflag.DB
import pyflag.conf
config=pyflag.conf.ConfObject()

def load_strings(filename,dbh):
    """ Calculates the strings from the given filename and add them to the database """
    tablename=dbh.MakeSQLSafe(filename)
    dbh.execute("create table `strings_%s` (`offset` BIGINT NOT NULL ,`string` TEXT NOT NULL)",tablename)
    
    import os
    p_client=os.popen("strings -td %s/%s" % (config.UPLOADDIR,filename),'r')
    
    for i in p_client:
        i=i.lstrip()
        offset=i.index(" ")
        dbh.execute("insert into strings_%s values (%s,%r)",(tablename,i[:offset],i[offset:]))
    
    p_client.close()

import re

class StringExtracter:
    """ This class extracts strings from file like objects.

    @cvar regex: A regular extression used to isolate strings.
    """
    regex="(?sm)(?:[\w.#!@$%^&*()_\-\\\\`+={}\|\\:;'\"<>,.\[\]?/\t ]\x00?){4,}"
    re=None
    def __init__(self,fd):
        """ Initialise class.

        @arg fd: File like object to be used for extracting strings
        """
        self.fd=fd
        self.re=re.compile(self.regex)

    def extract_from_offset(self,offset):
        """ Extracts number strings from offsets.

        This is implemented as a generator returning a list each time.

        @arg offset: The file will be seeked to this offset before extracting the strings
        @return: We return a list (offset,string). offset being the file offset where the string was found.
        """
        self.fd.seek(offset)
        count=offset
        blocksize=1024*1024
        rex=re.compile(self.regex)
        
        while 1:
            f=self.fd.read(blocksize)
            if not f: break
            for match in re.finditer(rex,f):
                yield (match.start()+count,match.group(0).replace('\x00',''))

            count+=blocksize

    def find_offset_prior(self,offset,number):
        """ search through the file for the offset number strings prior to the specified offset.

        For example, say that offset is somewhere in the middle of the file, we effectively search backwards counting strings until we see number strings, then we return that offset.

        If we hit the start of file we return 0.

        @arg offset: Specified offset to start search from.
        @arg number: number of strings to count.
        @return: An offset such that extract_from_offset(offset) will return number strings up to the specified offset.
        """
        blocksize=1024*1024
        found=[]

        while len(found)<number and offset>0:
            offset-=blocksize
            if offset<0:
                blocksize=offset+blocksize
                offset=0

            self.fd.seek(offset)
            f=self.fd.read(blocksize)
            if not f: break
            found=[d for d in re.finditer(self.re,f)] + found

        if len(found)<=number: return 0
        return found[-number].start()+offset
