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
#  Version: FLAG $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
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
import format,sys
from format import *
from plugins.FileFormats.BasicFormats import *

kBuckets = 32
def BLOCK_SIZE_FOR_INDEX(index):
    if index:
    	return (256 << (2 * ((index) - 1)))
    return 0

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
        [ 'KeyData', STRING, dict(length= lambda x: x['KeySize'])],
        [ 'MetaData', CacheMetaData, dict(length= lambda x: x['MetaDataSize'])],
        ]

blocksizes = [256, 1024, 4096]

class MozCache:
    def __init__(self, path):
        self.path = path
        self.map_fd = open("%s/_CACHE_MAP_" % self.path)
        self.data_fds = [ 
            open("%s/_CACHE_001_" % self.path),
            open("%s/_CACHE_002_" % self.path),
            open("%s/_CACHE_003_" % self.path)
            ]
        self.map_buffer = Buffer(fd=self.map_fd)
        self.mapfile = MapFile(self.map_buffer)

    def get_entry(self, location):
        fd = self.data_fds[location['DataFile']-1]
        fd.seek(0)
        offset = location['DataBlockSize'] * location['DataStartBlock']
        buffer = Buffer(fd=fd, offset=location['DataBlockSize'] * location['DataStartBlock'])
        print "reading offset: %s(%s*%s) from file %s" % (offset, location['DataBlockSize'], location['DataStartBlock'], location['DataFile']-1)
        return CacheEntry(buffer)

def print_map(mapfile):
    mozcache = MozCache(sys.argv[1])
    print mozcache.mapfile
    internal = 0
    external = 0
    error = 0
    for record in mozcache.mapfile['CacheRecords']:
    	if record['DataLocation']['Reserved'] or record['MetaLocation']['Reserved']:
    		continue

        if record['HashNumber'] != 0 and record['DataLocation']['DataLocationInitialized'] == True:
        	print record
        	try:
    		    meta = mozcache.get_entry(record['MetaLocation'])
    		    print meta
    		    external += 1
    		except Exception, e:
    		    print Exception, e
    		    error += 1
    		#print "%Xd01" % record['HashNumber']

    print error
    print external

if __name__ == "__main__":
	print_map(sys.argv[1])
