# Volatility
# Copyright (C) 2007 Volatile Systems
#
# Original Source:
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

xpsp2types = { \
  '_LIST_ENTRY' : [ 0x8, { \
    'Flink' : [ 0x0, ['pointer', ['_LIST_ENTRY']]], \
    'Blink' : [ 0x4, ['pointer', ['_LIST_ENTRY']]], \
} ], \
  '_KUSER_SHARED_DATA' : [ 0x338, { \
    'SystemTime' : [ 0x14, ['_KSYSTEM_TIME']], \
    'TimeZoneBias' : [ 0x20, ['_KSYSTEM_TIME']], \
} ], \
  '_LARGE_INTEGER' : [ 0x8, { \
    'LowPart' : [ 0x0, ['unsigned long']], \
    'HighPart' : [ 0x4, ['long']], \
} ], \
  '_KSYSTEM_TIME' : [ 0xc, { \
    'LowPart' : [ 0x0, ['unsigned long']], \
    'High1Time' : [ 0x4, ['long']], \
} ], \
  '_EPROCESS' : [ 0x260, { \
    'Pcb' : [ 0x0, ['_KPROCESS']], \
    'CreateTime' : [ 0x70, ['_LARGE_INTEGER']], \
    'ExitTime' : [ 0x78, ['_LARGE_INTEGER']], \
    'UniqueProcessId' : [ 0x84, ['pointer', ['void']]], \
    'ActiveProcessLinks' : [ 0x88, ['_LIST_ENTRY']], \
    'ObjectTable' : [ 0xc4, ['pointer', ['_HANDLE_TABLE']]], \
    'WorkingSetLock' : [ 0xcc, ['_FAST_MUTEX']], \
    'AddressCreationLock' : [ 0xf0, ['_FAST_MUTEX']], \
    'VadRoot' : [ 0x11c, ['pointer', ['void']]], \
    'InheritedFromUniqueProcessId' : [ 0x14c, ['pointer', ['void']]], \
    'ImageFileName' : [ 0x174, ['array', 16,['unsigned char']]], \
    'ThreadListHead' : [ 0x190, ['_LIST_ENTRY']], \
    'ActiveThreads' : [ 0x1a0, ['unsigned long']], \
    'Peb' : [ 0x1b0, ['pointer', ['_PEB']]], \
} ], \
  '_KPROCESS' : [ 0x6c, { \
    'DirectoryTableBase' : [ 0x18, ['array', 2,['unsigned long']]], \
} ], \
  '_PEB' : [ 0x210, { \
    'Ldr' : [ 0xc, ['pointer', ['_PEB_LDR_DATA']]], \
    'ProcessParameters' : [ 0x10, ['pointer', ['_RTL_USER_PROCESS_PARAMETERS']]], \
} ], \
  '_RTL_USER_PROCESS_PARAMETERS' : [ 0x290, { \
    'CommandLine' : [ 0x40, ['_UNICODE_STRING']], \
} ], \
  '_UNICODE_STRING' : [ 0x8, { \
    'Length' : [ 0x0, ['unsigned short']], \
    'Buffer' : [ 0x4, ['pointer', ['unsigned short']]], \
} ], \
  '_PEB_LDR_DATA' : [ 0x28, { \
    'InLoadOrderModuleList' : [ 0xc, ['_LIST_ENTRY']], \
} ], \
  '_LDR_MODULE' : [ 0x48, { \
    'InLoadOrderModuleList' : [ 0x0, ['_LIST_ENTRY']], \
    'BaseAddress' : [ 0x18, ['pointer', ['void']]], \
    'SizeOfImage' : [ 0x20, ['unsigned long']], \
    'FullDllName' : [ 0x24, ['_UNICODE_STRING']], \
} ], \
  '_ADDRESS_OBJECT' : [ 0x68, { \
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]], \
    'LocalIpAddress' : [ 0x0c, ['unsigned long']], \
    'LocalPort' : [ 0x30, ['unsigned short']], \
    'Protocol'  : [ 0x32, ['unsigned short']], \
    'Pid' : [ 0x148, ['unsigned long']], \
    'CreateTime' : [ 0x158, ['_LARGE_INTEGER']], \
} ], \
  '_TCPT_OBJECT' : [ 0x20, { \
  'Next' : [ 0x0, ['pointer', ['_TCPT_OBJECT']]], \
  'RemoteIpAddress' : [ 0xc, ['unsigned long']], \
  'LocalIpAddress' : [ 0x10, ['unsigned long']], \
  'RemotePort' : [ 0x14, ['unsigned short']], \
  'LocalPort' : [ 0x16, ['unsigned short']], \
  'Pid' : [ 0x18, ['unsigned long']], \
} ], \
  '_HANDLE_TABLE' : [ 0x44, { \
    'TableCode' : [ 0x0, ['unsigned long']], \
    'UniqueProcessId' : [ 0x8, ['pointer', ['void']]], \
    'HandleTableList' : [ 0x1c, ['_LIST_ENTRY']], \
    'HandleCount' : [ 0x3c, ['long']], \
} ], \
  '_HANDLE_TABLE_ENTRY' : [ 0x8, { \
    'Object' : [ 0x0, ['pointer', ['void']]], \
} ], \
  '_OBJECT_HEADER' : [ 0x20, { \
    'Type' : [ 0x8, ['pointer', ['_OBJECT_TYPE']]], \
    'Body' : [ 0x18, ['_QUAD']], \
} ], \
  '_OBJECT_TYPE' : [ 0x190, { \
    'Name' : [ 0x40, ['_UNICODE_STRING']], \
} ], \
  '_FILE_OBJECT' : [ 0x70, { \
    'Type' : [ 0x0, ['short']], \
    'FileName' : [ 0x30, ['_UNICODE_STRING']], \
} ], \
'_KPCR' : [  0xd70, { \
  'KdVersionBlock' : [ 0x34, ['pointer', ['void']]], \
} ], \
  '_KDDEBUGGER_DATA32' : [ 0x44, { \
  'PsLoadedModuleList' : [ 0x70, ['unsigned long']], \
  'PsActiveProcessHead' : [ 0x78, ['unsigned long']], \
} ], \
  '_KDDEBUGGER_DATA64' : [ 0x44, { \
  'PsLoadedModuleList' : [ 0x48, ['unsigned long']], \
  'PsActiveProcessHead' : [ 0x50, ['unsigned long']], \
} ], \
'_DBGKD_GET_VERSION64' : [  0x2a, { \
  'DebuggerDataList' : [ 0x20, ['unsigned long']], \
} ], \
'_MMVAD_LONG' : [  0x34, { \
  'StartingVpn' : [ 0x0, ['unsigned long']], \
  'EndingVpn' : [ 0x4, ['unsigned long']], \
  'Parent' : [ 0x8, ['pointer', ['_MMVAD']]], \
  'LeftChild' : [ 0xc, ['pointer', ['_MMVAD']]], \
  'RightChild' : [ 0x10, ['pointer', ['_MMVAD']]], \
  'u' : [ 0x14, ['__unnamed']], \
  'ControlArea' : [ 0x18, ['pointer', ['_CONTROL_AREA']]], \
  'FirstPrototypePte' : [ 0x1c, ['pointer', ['_MMPTE']]], \
  'LastContiguousPte' : [ 0x20, ['pointer', ['_MMPTE']]], \
  'u2' : [ 0x24, ['__unnamed']], \
  'u3' : [ 0x28, ['__unnamed']], \
  'u4' : [ 0x30, ['__unnamed']], \
} ], \
'_MMVAD' : [  0x28, { \
  'StartingVpn' : [ 0x0, ['unsigned long']], \
  'EndingVpn' : [ 0x4, ['unsigned long']], \
  'Parent' : [ 0x8, ['pointer', ['_MMVAD']]], \
  'LeftChild' : [ 0xc, ['pointer', ['_MMVAD']]], \
  'RightChild' : [ 0x10, ['pointer', ['_MMVAD']]], \
  'u' : [ 0x14, ['__unnamed']], \
  'ControlArea' : [ 0x18, ['pointer', ['_CONTROL_AREA']]], \
  'FirstPrototypePte' : [ 0x1c, ['pointer', ['_MMPTE']]], \
  'LastContiguousPte' : [ 0x20, ['pointer', ['_MMPTE']]], \
  'u2' : [ 0x24, ['__unnamed']], \
} ], \
'_MMVAD_SHORT' : [  0x18, { \
  'StartingVpn' : [ 0x0, ['unsigned long']], \
  'EndingVpn' : [ 0x4, ['unsigned long']], \
  'Parent' : [ 0x8, ['pointer', ['_MMVAD']]], \
  'LeftChild' : [ 0xc, ['pointer', ['_MMVAD']]], \
  'RightChild' : [ 0x10, ['pointer', ['_MMVAD']]], \
  'u' : [ 0x14, ['__unnamed']], \
} ], \
'_CONTROL_AREA' : [  0x30, { \
  'Segment' : [ 0x0, ['pointer', ['_SEGMENT']]], \
  'DereferenceList' : [ 0x4, ['_LIST_ENTRY']], \
  'NumberOfSectionReferences' : [ 0xc, ['unsigned long']], \
  'NumberOfPfnReferences' : [ 0x10, ['unsigned long']], \
  'NumberOfMappedViews' : [ 0x14, ['unsigned long']], \
  'NumberOfSubsections' : [ 0x18, ['unsigned short']], \
  'FlushInProgressCount' : [ 0x1a, ['unsigned short']], \
  'NumberOfUserReferences' : [ 0x1c, ['unsigned long']], \
  'u' : [ 0x20, ['__unnamed']], \
  'FilePointer' : [ 0x24, ['pointer', ['_FILE_OBJECT']]], \
  'WaitingForDeletion' : [ 0x28, ['pointer', ['_EVENT_COUNTER']]], \
  'ModifiedWriteCount' : [ 0x2c, ['unsigned short']], \
  'NumberOfSystemCacheViews' : [ 0x2e, ['unsigned short']], \
} ], \
'_POOL_HEADER' : [  0x8, { \
  'Ulong1' : [ 0x0, ['unsigned long']], \
  'ProcessBilled' : [ 0x4, ['pointer', ['_EPROCESS']]], \
  'PoolTag' : [ 0x4, ['unsigned long']], \
  'AllocatorBackTraceIndex' : [ 0x4, ['unsigned short']], \
  'PoolTagHash' : [ 0x6, ['unsigned short']], \
} ], \
'_FAST_MUTEX' : [  0x20, { \
  'Event' : [ 0xc, ['_KEVENT']], \
} ], \
'_KEVENT' : [  0x10, { \
  'Header' : [ 0x0, ['_DISPATCHER_HEADER']], \
} ], \
'_DISPATCHER_HEADER' : [  0x10, { \
  'Type' : [ 0x0, ['unsigned char']], \
  'Size' : [ 0x2, ['unsigned char']], \
} ], \
'_ETHREAD' : [  0x258, { \
  'Tcb' : [ 0x0, ['_KTHREAD']], \
  'Cid' : [ 0x1ec, ['_CLIENT_ID']], \
  'LpcReplySemaphore' : [ 0x1f4, ['_KSEMAPHORE']], \
  'ThreadsProcess' : [ 0x220, ['pointer', ['_EPROCESS']]], \
  'StartAddress' : [ 0x224, ['pointer', ['void']]], \
} ], \
'_CLIENT_ID' : [  0x8, { \
  'UniqueProcess' : [ 0x0, ['pointer', ['void']]], \
  'UniqueThread' : [ 0x4, ['pointer', ['void']]], \
} ], \
'_KTHREAD' : [  0x1c0, { \
  'Header' : [ 0x0, ['_DISPATCHER_HEADER']], \
  'Timer' : [ 0xf0, ['_KTIMER']], \
  'SuspendSemaphore' : [ 0x19c, ['_KSEMAPHORE']], \
} ], \
'_KTIMER' : [  0x28, { \
  'Header' : [ 0x0, ['_DISPATCHER_HEADER']], \
} ], \
'_KSEMAPHORE' : [  0x14, { \
  'Header' : [ 0x0, ['_DISPATCHER_HEADER']], \
} ], \
}
