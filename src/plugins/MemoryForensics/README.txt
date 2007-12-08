============================================================================
Volatility Framework - Volatile memory extraction utility framework
============================================================================

The Volatility Framework is a completely open collection of tools,
 implemented in Python under the GNU General Public License, for the
extraction of digital artifacts from volatile memory (RAM) images.
The extraction techniques are performed completely independent of the
system being investigated but offer visibilty into the runtime state
of the system. The framework is intended to introduce people to the
techniques and complexities associated with extracting digital artifacts
from volatile memory images and provide a platform for further work into
this exciting area of research.

The Volatility distribution is available from 
http://volatilesystems.com/VolatileWeb/volatility.gsp

Volatility should run on any platform that supports 
Python (http://www.python.org)

Volatility supports investigations of Microsoft Windows XP Service 
Pack 2 memory images. 

Volatility does not provide memory image acquisition
capabilities. For acquisition, there are both free and commercial
solutions available. If you would like suggestions about suitable 
acquisition solutions, please contact us at:

volatility (at) volatilesystems (dot) com

Volatility currently provides the following extraction capabilities for 
memory images:

  - Image date and time
  - Running processes
  - Open network sockets
  - Open network connections
  - DLLs loaded for each process
  - Open files for each process
  - OS kernel modules
  - Mapping physical offsets to virtual addresses
  - Virtual Address Descriptor information
  - Scanning examples: processes, threads, sockets, connections


Mailing Lists
=============

Mailing lists to support the users and developers of Volatility
can be found at the following address:

http://www.volatilesystems.com/mailman/listinfo


Contact
=======
For information or requests, contact:

Volatile Systems
http://www.volatilesystems.com/

volatility (at) volatilesystems (dot) com


Requirements
============
- Python 2.5 or later. http://www.python.org

Quick Start
===========
1. Unpack the latest version of Volatility from
   http://www.volatilesystems.com/volatility

2. To see available options, run "python volatility"

   Example:

  > python volatility

	Volatile Systems Volatility Framework v1.1.1
	Copyright (C) 2007 Volatile Systems
	This is free software; see the source for copying conditions.
	There is NO warranty; not even for MERCHANTABILITY or FITNESS
	FOR A PARTICULAR PURPOSE.

	usage: volatility cmd [cmd_opts]

	Run command cmd with options cmd_opts
	For help on a specific command, run 'volatility cmd --help'

	Supported Commands:
		connections    	Print list of open connections
		connscan       	Scan for connection objects
		datetime       	Get date/time information for image
		dlllist        	Print list of loaded dlls for each process (VERY verbose)
		files          	Print list of open files for each process (VERY verbose)
		ident          	Identify image properties such as DTB and VM type (may take a while)
		modules        	Print list of loaded modules
		pslist         	Print list of running processes
		psscan         	Scan for EPROCESS objects
		sockets        	Print list of open sockets
		sockscan       	Scan for socket objects
		strings        	Match physical offsets to virtual addresses (may take a while, VERY verbose)
		thrdscan       	Scan for ETHREAD objects
		vaddump        	Dump the Vad sections to files
		vadinfo        	Dump the VAD info
		vadwalk        	Walk the vad tree

	Example: volatility pslist -f /path/to/my/file

3. To get more information on an image and make sure Volatility
   supports that image type, run 'python volatility ident -f <imagename>'

   Example:
   
  > python volatility ident -f c:\images\image1.dump
              Image Name: c:\images\image1.dump
              Image Type: XP SP2
                 VM Type: nopae
                     DTB: 0x39000
                Datetime: Mon Feb 19 20:52:08 2007

4. Run some other tools. -f is a required option for all tools. Some
   also require/accept other options. Run "volatility <cmd> --help" for
   more information on a particular command.


Licensing and Copyright
=======================

Copyright (C) 2007 Volatile Systems

Original Source:
Copyright (C) 2007 Komoku, Inc.
All Rights Reserved

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  
02111-1307, USA.


Bugs and Support
================
There is no support provided with Volatility. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. Bugs may be reported to volatility (at) volatilesystems (dot) com. 
However, Volatile Systems makes no guarantees of any corrective
action or reply, written or verbal.

Missing or Truncated Information
================================
Volatile Systems makes no claims about the validity or correctness of the
output of Volatility. Many factors may contribute to the
incorrectness of output from Volatility including, but not
limited to, malicious modifications to the operating system,
incomplete information due to swapping, and information corruption on
image acquisition. 


Command Descriptions
====================
The following is a short description of some commands supported by
Volatility.

connections
-----------
Lists all open connections that were active at the time of the memory
image's acquisition. If -t and -b are not specified, Volatility
will attempt to infer reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)

connscan
--------
Scans the flat physical address space for connection objects. 

  Options:
     -f   <Image>   Image file to load
     -s   <start>   Hexadecimal physical offset to begin scan
     -e   <end>     Hexadecimal physical offset to end scan
     -l             Scan in slow mode (verifies all constraints)

datetime
--------
Print the system date and time recognized by the Windows kernel at the
time the image was acquired. If -t and -b are not specified, Volatility
will attempt to infer reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)


dlllist
-------
For each process running in the system, identify the base virtual
address, size, and filesystem path to all DLLs loaded in that
process. If -t and -b are not specified, Volatility
will attempt to infer reasonable values. 

NOTE: dlllist output may be very verbose. 

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)


files
-----
For each process running in the system, identify all open file handles
and the absolute filesystem path to that file. If -t and -b are not
specified, Volatility will attempt to infer reasonable values.

NOTE: files output may be very verbose. 

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)


ident
-----
For the given image, attempt to identify the operating system type,
virtual address translation mechanism, and a starting directory table
base (DTB). The output of ident can be used to speedup other commands
when using the -t and -b options with those commands. Options -t and
-b will be ignored when running ident itself.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    IGNORED
     -t   <type>    IGNORED


modules
-------
For the given image, list all kernel modules loaded at the time of
acquisition. If -t and -b are not specified, Volatility will
attempt to infer reasonable values. 

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)


pslist
------
For the given image, list all processes that were running, along with
some corresponding metadata such as process creation time. If -t and
-b are not specified, Volatility will attempt to infer reasonable
values.  

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)


psscan
------
Scans the flat physical address space for EPROCESS objects. 

  Options:
     -f   <Image>   Image file to load
     -s   <start>   Hexadecimal physical offset to begin scan
     -e   <end>     Hexadecimal physical offset to end scan
     -l             Scan in slow mode (verifies all constraints)


sockets
-------
For the given image, list all open sockets registered with the kernel
and the corresponding process for which the socket was opened and
associated socket creation time. If -t and -b are not specified,
Volatility will attempt to infer reasonable values. 

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)


sockscan
------
Scans the flat physical address space for socket objects. 

  Options:
     -f   <Image>   Image file to load
     -s   <start>   Hexadecimal physical offset to begin scan
     -e   <end>     Hexadecimal physical offset to end scan
     -l             Scan in slow mode (verifies all constraints)


strings
-------
For a given image and a file with lines of the form <offset>:<string>,
output the corresponding process and virtual addresses where that
string can be found. Expected input for this tool is the output of
Microsoft Sysinternals' Strings utility, or another utility that
provides similarly formatted offset:string mappings. Note that the
input offsets are physical offsets from the start of the file/image. 
If -t and -b are not specified, Volatility will attempt to infer
reasonable values. 

NOTE: strings output may be very verbose.

  Options:
     -f   <Image>       Image file to load
     -s   <Stringfile>  File with lines of the form <offset>:<string>
     -b   <base>        Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>        Image type (pae, nopae, auto)


thrdscan
------
Scans the flat physical address space for ETHREAD objects. 

  Options:
     -f   <Image>   Image file to load
     -s   <start>   Hexadecimal physical offset to begin scan
     -e   <end>     Hexadecimal physical offset to end scan
     -l             Scan in slow mode (verifies all constraints)


vadwalk
-------

For the given image, print the Virtual Address Descriptors (VAD)
tree associated with a particular process. Depending on the command
line options the information will be printed in a number of different
formats. If -t and -b are not specified, Volatility will attempt
to infer reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of a valid EPROCESS object
     -e             Print VAD tree in tree format
     -l             Print VAD tree in table format
     -d             print VAD tree in Dot file format


vadinfo
-------

For the given image, print detailed information about each object
found in the Virtual Address Descriptors (VAD) tree associated with a
particular process.  If -t and -b are not specified, Volatility
will attempt to infer reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of a valid EPROCESS object


vaddump
-------

For the given image, traverse the Virtual Address Descriptors (VAD)
tree and dump the ranges of memory to files for further analysis. If
-t and -b are not specified, Volatility will attempt to infer
reasonable values.

  Options:
     -f   <Image>   Image file to load
     -b   <base>    Hexadecimal physical offset of any valid Directory Table Base
     -t   <type>    Image type (pae, nopae, auto)
     -o   <offset>  Hexadecimal physical offset of a valid EPROCESS object
