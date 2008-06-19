#!/usr/bin/env python
# ******************************************************
# Copyright 2006: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# David Collett <daveco@users.sourceforge.net>
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
""" A library for handling Mozilla/Firefox cache files.

    The format doesnt seem to be documented except in the source itself:

    http://lxr.mozilla.org/mozilla1.8/source/netwerk/cache/src/nsDiskCacheMap.h

"""
import os, sys

from format import *
from plugins.FileFormats.BasicFormats import *

kBuckets = 32
def BLOCK_SIZE_FOR_INDEX(index):
    if index:
    	return (256 << (2 * ((index) - 1)))
    return 0

def GenerateHash(key):
    """ Hashing algorithm used by Mozilla to match URL (keys) to files """
    h = 0
    for i in range(len(key)):
        h = (h >> (32 - 4)) ^ ((h & 0xFFFFFFF) << 4) ^ ord(key[i])

    if h==0: 
        return -1
    return h

data_files = [ "_CACHE_001_", "_CACHE_002_", "_CACHE_003_" ]

class DataLocation(BEULONG):
    """ Location Definition """

    LocationInitializedMask = 0x80000000
    LocationSelectorMask    = 0x30000000
    LocationSelectorOffset  = 28
    ExtraBlocksMask         = 0x03000000
    ExtraBlocksOffset       = 24
    ReservedMask            = 0x4C000000
    BlockNumberMask         = 0x00FFFFFF
    FileSizeMask            = 0x00FFFF00
    FileSizeOffset          = 8
    FileGenerationMask      = 0x000000FF
    FileReservedMask        = 0x4F000000

    def __init__(self, buffer, *args, **kwargs):
        BEULONG.__init__(self, buffer, *args, **kwargs)

        self.fields = {
        	'DataLocationInitialized' : bool(self.data & self.LocationInitializedMask),
        	'DataFile' : (self.data & self.LocationSelectorMask) >> self.LocationSelectorOffset,
        	'DataBlockCount' : ((self.data & self.ExtraBlocksMask) >> self.ExtraBlocksOffset) + 1,
        	'DataStartBlock' : self.data & self.BlockNumberMask,
        	'DataBlockSize' : BLOCK_SIZE_FOR_INDEX((self.data & self.LocationSelectorMask) >> self.LocationSelectorOffset),
        	'DataFileSize' : (self.data & self.FileSizeMask) >> self.FileSizeOffset,
        	'DataFileGeneration' : self.data & self.FileGenerationMask,
        	'Reserved' : self.data & self.ReservedMask,
        }

    def __str__(self):
        result = ""
        for key in self.fields:
        	result += "%s: %s\n" % (key, self.fields[key])
        return result

    def __getitem__(self, name):
        return self.fields[name]

class CacheRecord(SimpleStruct):
    fields = [
        [ 'HashNumber', BEULONG ],
        [ 'EvictionRank', BEULONG ],
        [ 'DataLocation', DataLocation ],
        [ 'MetaLocation', DataLocation ],
        ]

class CacheRecord_ARRAY(ARRAY):
    target_class = CacheRecord

class MapFile(SimpleStruct):
    fields = [
        [ 'Version', BEULONG ],
        [ 'DataSize', BELONG ],
        [ 'EntryCount', BELONG ],
        [ 'IsDirty', BEULONG ],
        [ 'RecordCount', BELONG ],
        [ 'EvictionRank', BEULONG_ARRAY, {"count":kBuckets} ],
        [ 'BucketUsage', BEULONG_ARRAY, {"count":kBuckets} ],
        [ 'CacheRecords', CacheRecord_ARRAY, dict(count = lambda x: x['RecordCount']) ],
        ]

class CacheMetaData(STRING):
    def __init__(self, buffer, *args, **kwargs):
        STRING.__init__(self, buffer, *args, **kwargs)

        self.fields = {}
        l = self.data.split('\x00')[:-1]
        for i in range(0, len(l), 2):
        	self.fields[l[i]] = l[i+1]

    def __str__(self):
        result = ""
        for key in self.fields:
        	result += "%s: %s\n" % (key, self.fields[key])
        return result

    def __getitem__(self, name):
        return self.fields[name]

class CacheEntry(SimpleStruct):
    fields = [
        [ 'HeaderVersion', BEULONG ],
        [ 'MetaLocation', BEULONG ],
        [ 'FetchCount', BELONG ],
        [ 'LastFetched', BEULONG ],
        [ 'LastModified', BEULONG ],
        [ 'ExpirationTime', BEULONG ],
        [ 'DataSize', BEULONG ],
        [ 'KeySize', BEULONG ],
        [ 'MetaDataSize', BEULONG ],
        [ 'KeyData', STRING, dict(length= lambda x: int(x['KeySize']))],
        [ 'MetaData', CacheMetaData, dict(length= lambda x: x['MetaDataSize'])],
        ]

class MozCacheRecord:
    def __init__(self, mozcache, record):
        self.mozcache = mozcache
        self.record = record
        self.meta = self._get_entry()

    def get_entry(self):
        return self.meta

    def _get_entry(self):
        fd = self.mozcache.data_fds[self.record['MetaLocation']['DataFile']-1]
        fd.seek(0)
        offset = 4096 + self.record['MetaLocation']['DataBlockSize'] * self.record['MetaLocation']['DataStartBlock']
        buffer = Buffer(fd=fd, offset=offset)
        return CacheEntry(buffer)

    def get_data_location(self):
        """ returns a tuple of (fileno, offset, length) specifying location
        of data """
        return (self.record['DataLocation']['DataFile'] - 1, 
                4096 + self.record['DataLocation']['DataBlockSize'] * self.record['DataLocation']['DataStartBlock'],
                int(self.meta['DataSize']))

    def get_data(self):
        if self.record['DataLocation']['DataFile'] == 0:
        	# read record from its own file
        	filename = "%s%s%08Xd01" % (self.mozcache.path, os.path.sep, self.record['HashNumber'])
        	fd = open(filename)
        	return fd.read()
        else:
            fd = self.mozcache.data_fds[self.record['DataLocation']['DataFile']-1]
            _, offset, length = self.get_data_location()
            fd.seek(offset)
            return fd.read(length)

class MozCache:
    def __init__(self, map_fd, data_fds):
        self.map_fd = map_fd
        self.data_fds = data_fds
        self.map_buffer = Buffer(fd=self.map_fd)
        self.mapfile = MapFile(self.map_buffer)

    def records(self):
        for record in self.mapfile['CacheRecords']:
    	    if record['DataLocation']['Reserved'] or record['MetaLocation']['Reserved']:
    		    continue

            if record['HashNumber'] != 0 and record['DataLocation']['DataLocationInitialized'] == True:
                yield MozCacheRecord(self, record)

    def __str__(self):
        result = [str(self.mapfile),]
        for record in self.records():
    	    result.append(str(record.record))
    	    entry = record.get_entry()
    	    result.append(str(entry))
    	return "".join(result)
 

class MozCache_path(MozCache):
    def __init__(self, path):
        self.path = path
        map_fd = open("%s/_CACHE_MAP_" % self.path)
        data_fds = [ 
            open("%s/_CACHE_001_" % self.path),
            open("%s/_CACHE_002_" % self.path),
            open("%s/_CACHE_003_" % self.path)
            ]
        MozCache.__init__(self, map_fd, data_fds)

if __name__ == "__main__":
    """ Test program for Mozilla/Firefox cache. It can export all internal
    cache entries and build a html index for browsing """

    html_page = """
    <html>
    <head>
    <title>Firefox Cache Viewer</title>
    <head>
    <body>
    <h2>Firefox Cache Viewer</h2>
    <table border=1>
    %s
    </table>
    </body>
    </html>
    """

    html_record = """
    <tr>
    <td><pre><a href=%s>%08X</a></pre></td>
    <td>%s</td>
    </tr>
    """

    mozcache = MozCache_path(sys.argv[1])
    #print mozcache.mapfile
    html_rec = []
    for record in mozcache.records():
    	#print record.record
    	entry = record.get_entry()
    	print entry
    	if record.record['DataLocation']['DataFile'] != 0:
    		data = record.get_data()
    		filename = "exported-%08Xd01" % record.record['HashNumber']
    		fd = open("%s/%s" % (mozcache.path, filename), "w")
    		fd.write(data)
    		fd.close()
    	else:
    	    filename = "%08Xd01" % record.record['HashNumber']

        html_rec.append(html_record % (filename, record.record['HashNumber'], entry['KeyData']))

    print "Building index in %s/index.html\n" % mozcache.path
    fd = open("%s/index.html" % mozcache.path, "w")
    fd.write(html_page % "\n".join(html_rec))
    fd.close()
