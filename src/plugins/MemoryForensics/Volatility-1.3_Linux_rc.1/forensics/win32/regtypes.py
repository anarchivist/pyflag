# Volatility
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

regtypes = {
  '_CM_KEY_NODE' : [ 0x50, {
    'Signature' : [ 0x0, ['String', dict(length=2)]],
    'Flags' : [ 0x2, ['unsigned short']],
    'LastWriteTime' : [ 0x4, ['WinTimeStamp', {}]],
    'Spare' : [ 0xc, ['unsigned long']],
    'Parent' : [ 0x10, ['unsigned long']],
    'SubKeyCounts' : [ 0x14, ['array', 2, ['unsigned long']]],
    'SubKeyLists' : [ 0x1c, ['array', 2, ['unsigned long']]],
    'ValueList' : [ 0x24, ['_CHILD_LIST']],
    'ChildHiveReference' : [ 0x1c, ['_CM_KEY_REFERENCE']],
    'Security' : [ 0x2c, ['unsigned long']],
    'Class' : [ 0x30, ['unsigned long']],
    'MaxNameLen' : [ 0x34, ['unsigned long']],
    'MaxClassLen' : [ 0x38, ['unsigned long']],
    'MaxValueNameLen' : [ 0x3c, ['unsigned long']],
    'MaxValueDataLen' : [ 0x40, ['unsigned long']],
    'WorkVar' : [ 0x44, ['unsigned long']],
    'NameLength' : [ 0x48, ['unsigned short']],
    'ClassLength' : [ 0x4a, ['unsigned short']],
    'Name' : [ 0x4c, ['String', dict(length=lambda x: x.NameLength)]],
} ],
  '_CM_KEY_REFERENCE' : [ 0x8, {
    'KeyCell' : [ 0x0, ['unsigned long']],
    'KeyHive' : [ 0x4, ['pointer', ['_HHIVE']]],
} ],
  '_CHILD_LIST' : [ 0x8, {
    'Count' : [ 0x0, ['unsigned long']],
    'List' : [ 0x4, ['pointer', ['array', lambda x: x.Count,
                                 ['pointer', ['_CM_KEY_VALUE']]]]],
} ],
  '_CM_KEY_SECURITY' : [ 0x28, {
    'Signature' : [ 0x0, ['unsigned short']],
    'Reserved' : [ 0x2, ['unsigned short']],
    'Flink' : [ 0x4, ['unsigned long']],
    'Blink' : [ 0x8, ['unsigned long']],
    'ReferenceCount' : [ 0xc, ['unsigned long']],
    'DescriptorLength' : [ 0x10, ['unsigned long']],
    'Descriptor' : [ 0x14, ['_SECURITY_DESCRIPTOR_RELATIVE']],
} ],
  '_SECURITY_DESCRIPTOR_RELATIVE' : [ 0x14, {
    'Revision' : [ 0x0, ['unsigned char']],
    'Sbz1' : [ 0x1, ['unsigned char']],
    'Control' : [ 0x2, ['unsigned short']],
    'Owner' : [ 0x4, ['unsigned long']],
    'Group' : [ 0x8, ['unsigned long']],
    'Sacl' : [ 0xc, ['unsigned long']],
    'Dacl' : [ 0x10, ['unsigned long']],
} ],
  '_CM_KEY_VALUE' : [ 0x18, {
    'Signature' : [ 0x0, ['String', dict(length=2)]],
    'NameLength' : [ 0x2, ['unsigned short']],
    'DataLength' : [ 0x4, ['unsigned long']],
    'Data' : [ 0x8, ['unsigned long']],
    'Type' : [ 0xc, ['unsigned long']],
    'Flags' : [ 0x10, ['unsigned short']],
    'Spare' : [ 0x12, ['unsigned short']],
    'Name' : [ 0x14, ['String', dict(length=lambda x: x.NameLength)]],
} ],
  '_CM_KEY_INDEX' : [ 0x8, {
    'Signature' : [ 0x0, ['String', dict(length=2)]],
    'Count' : [ 0x2, ['unsigned short']],
    'List' : [ 0x4, ['array', lambda x: 2*x.Count.v(), ['pointer', ['_CM_KEY_NODE']]]],
} ],
  '_CMHIVE' : [ 0x49c, {
    'Hive' : [ 0x0, ['_HHIVE']],
    'FileHandles' : [ 0x210, ['array', 3, ['pointer', ['void']]]],
    'NotifyList' : [ 0x21c, ['_LIST_ENTRY']],
    'HiveList' : [ 0x224, ['_LIST_ENTRY']],
    'HiveLock' : [ 0x22c, ['pointer', ['_FAST_MUTEX']]],
    'ViewLock' : [ 0x230, ['pointer', ['_FAST_MUTEX']]],
    'LRUViewListHead' : [ 0x234, ['_LIST_ENTRY']],
    'PinViewListHead' : [ 0x23c, ['_LIST_ENTRY']],
    'FileObject' : [ 0x244, ['pointer', ['_FILE_OBJECT']]],
    'FileFullPath' : [ 0x248, ['_UNICODE_STRING']],
    'FileUserName' : [ 0x250, ['_UNICODE_STRING']],
    'MappedViews' : [ 0x258, ['unsigned short']],
    'PinnedViews' : [ 0x25a, ['unsigned short']],
    'UseCount' : [ 0x25c, ['unsigned long']],
    'SecurityCount' : [ 0x260, ['unsigned long']],
    'SecurityCacheSize' : [ 0x264, ['unsigned long']],
    'SecurityHitHint' : [ 0x268, ['long']],
    'SecurityCache' : [ 0x26c, ['pointer', ['_CM_KEY_SECURITY_CACHE_ENTRY']]],
    'SecurityHash' : [ 0x270, ['array', 64, ['_LIST_ENTRY']]],
    'UnloadEvent' : [ 0x470, ['pointer', ['_KEVENT']]],
    'RootKcb' : [ 0x474, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
    'Frozen' : [ 0x478, ['unsigned char']],
    'UnloadWorkItem' : [ 0x47c, ['pointer', ['_WORK_QUEUE_ITEM']]],
    'GrowOnlyMode' : [ 0x480, ['unsigned char']],
    'GrowOffset' : [ 0x484, ['unsigned long']],
    'KcbConvertListHead' : [ 0x488, ['_LIST_ENTRY']],
    'KnodeConvertListHead' : [ 0x490, ['_LIST_ENTRY']],
    'CellRemapArray' : [ 0x498, ['pointer', ['_CM_CELL_REMAP_BLOCK']]],
} ],
  '_HHIVE' : [ 0x210, {
    'Signature' : [ 0x0, ['unsigned long']],
     'GetCellRoutine' : [ 0x4, ['pointer', ['void']]],
     'ReleaseCellRoutine' : [ 0x8, ['pointer', ['void']]],
     'Allocate' : [ 0xc, ['pointer', ['void']]],
     'Free' : [ 0x10, ['pointer', ['void']]],
     'FileSetSize' : [ 0x14, ['pointer', ['void']]],
     'FileWrite' : [ 0x18, ['pointer', ['void']]],
     'FileRead' : [ 0x1c, ['pointer', ['void']]],
     'FileFlush' : [ 0x20, ['pointer', ['void']]],
    'BaseBlock' : [ 0x24, ['pointer', ['_HBASE_BLOCK']]],
    'DirtyVector' : [ 0x28, ['_RTL_BITMAP']],
    'DirtyCount' : [ 0x30, ['unsigned long']],
    'DirtyAlloc' : [ 0x34, ['unsigned long']],
    'RealWrites' : [ 0x38, ['unsigned char']],
    'Cluster' : [ 0x3c, ['unsigned long']],
    'Flat' : [ 0x40, ['unsigned char']],
    'ReadOnly' : [ 0x41, ['unsigned char']],
    'Log' : [ 0x42, ['unsigned char']],
    'HiveFlags' : [ 0x44, ['unsigned long']],
    'LogSize' : [ 0x48, ['unsigned long']],
    'RefreshCount' : [ 0x4c, ['unsigned long']],
    'StorageTypeCount' : [ 0x50, ['unsigned long']],
    'Version' : [ 0x54, ['unsigned long']],
    'Storage' : [ 0x58, ['array', 2, ['_DUAL']]],
} ],
  '_HBASE_BLOCK' : [ 0x1000, {
    'Signature' : [ 0x0, ['unsigned long']],
    'Sequence1' : [ 0x4, ['unsigned long']],
    'Sequence2' : [ 0x8, ['unsigned long']],
    'TimeStamp' : [ 0xc, ['_LARGE_INTEGER']],
    'Major' : [ 0x14, ['unsigned long']],
    'Minor' : [ 0x18, ['unsigned long']],
    'Type' : [ 0x1c, ['unsigned long']],
    'Format' : [ 0x20, ['unsigned long']],
    'RootCell' : [ 0x24, ['unsigned long']],
    'Length' : [ 0x28, ['unsigned long']],
    'Cluster' : [ 0x2c, ['unsigned long']],
    'FileName' : [ 0x30, ['array', 64, ['unsigned char']]],
    'Reserved1' : [ 0x70, ['array', 99, ['unsigned long']]],
    'CheckSum' : [ 0x1fc, ['unsigned long']],
    'Reserved2' : [ 0x200, ['array', 894, ['unsigned long']]],
    'BootType' : [ 0xff8, ['unsigned long']],
    'BootRecover' : [ 0xffc, ['unsigned long']],
} ],
  '_DUAL' : [ 0xdc, {
    'Length' : [ 0x0, ['unsigned long']],
    'Map' : [ 0x4, ['pointer', ['_HMAP_DIRECTORY']]],
    'SmallDir' : [ 0x8, ['pointer', ['_HMAP_TABLE']]],
    'Guard' : [ 0xc, ['unsigned long']],
    'FreeDisplay' : [ 0x10, ['array', 24, ['_RTL_BITMAP']]],
    'FreeSummary' : [ 0xd0, ['unsigned long']],
    'FreeBins' : [ 0xd4, ['_LIST_ENTRY']],
} ],
  '_HMAP_DIRECTORY' : [ 0x1000, {
    'Directory' : [ 0x0, ['array', 1024, ['pointer', ['_HMAP_TABLE']]]],
} ],
  '_HMAP_TABLE' : [ 0x2000, {
    'Table' : [ 0x0, ['array', 512, ['_HMAP_ENTRY']]],
} ],
  '_HMAP_ENTRY' : [ 0x10, {
    'BlockAddress' : [ 0x0, ['unsigned long']],
    'BinAddress' : [ 0x4, ['unsigned long']],
    'CmView' : [ 0x8, ['pointer', ['_CM_VIEW_OF_FILE']]],
    'MemAlloc' : [ 0xc, ['unsigned long']],
} ],
  '_CM_KEY_SECURITY_CACHE_ENTRY' : [ 0x8, {
    'Cell' : [ 0x0, ['unsigned long']],
    'CachedSecurity' : [ 0x4, ['pointer', ['_CM_KEY_SECURITY_CACHE']]],
} ],
  '_CM_KEY_SECURITY_CACHE' : [ 0x28, {
    'Cell' : [ 0x0, ['unsigned long']],
    'ConvKey' : [ 0x4, ['unsigned long']],
    'List' : [ 0x8, ['_LIST_ENTRY']],
    'DescriptorLength' : [ 0x10, ['unsigned long']],
    'Descriptor' : [ 0x14, ['_SECURITY_DESCRIPTOR_RELATIVE']],
} ],
  '_CM_CELL_REMAP_BLOCK' : [ 0x8, {
    'OldCell' : [ 0x0, ['unsigned long']],
    'NewCell' : [ 0x4, ['unsigned long']],
} ],
  '_LARGE_INTEGER' : [ 0x8, {
    'LowPart' : [ 0x0, ['unsigned long']],
    'HighPart' : [ 0x4, ['long']],
    'QuadPart' : [ 0x0, ['long long']],
} ],
}
