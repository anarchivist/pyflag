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
#  Version: FLAG $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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
""" A library for reading MS Windows Event log file.

Note that Event log files are not actually suitable for auditing or logging since they are increadibly braindead. The event logs themselves do not contain enough information to display the log messages. This is not a problem with dealing with a proprietary file format, but a serious limitation of the logging system itself.

In an event log file each entry contains the following fields:

Service Name
Message ID, Class ID
List of args.

In order to properly display the event message, one needs to find the association between the Service Name and a certain DLL. The DLL contains messages as a resource section. Once the resource section is found, the Message ID/Class ID can be used to reference into the resource section to find the message. The Args are expanded into the message id.

It gets even worse - In order to find the association between the Service Name and the specific dll to use, one must look in the registry here:

HKEY_LOCAL_MACHINE
    SYSTEM
     CurrentControlSet
       Services
         EventLog
            Application
              AppName
            Security
            System
              DriverName

However, the CurrentControlSet branch is not stored on disk - it is a virtual region of the registry which is created at run time. When a service is started it registers its dll to handle its messages by placing a registry key under AppName above with the name of a dll. This occurs each time the service is started (or the machine boots).

The problem here is that since the log file does not contain _all_ the information about its messages, it is not self contained and depends on future system state in order to actually read the messages. The assumption is that the system at a future time will be able to provide the missing crucial information necessary for perusing the log file. This is a stupid assumption which defeats the whole point of logging. Take the following scenarios:

- An attacker compromises the system, the system administrator loads old event log files to trace past messages - If the attacker is able to change a single registry mapping, they can effectively change all _past_, _future_ and _preset_ messages on the system.

- A service crashes and fails to start after a system reboot. The administrator tries to work out whats wrong, but since the service is unable to register its dll association it is impossible to view events which were recorded in the past, when the system was working - the log files may contains clues as to why the system failed. (How stupid is this? whats the point of logging anything if you cant read what happened in the future?)

- An administrator takes an event log file from one system to view it on another system - since the system which is trying to view the messages does not have the same services installed, it is unable to find the dll association (or probably doesnt even have the dll installed at all). It is impossible to move event log files between machines. This restriction is important for forensics.

Due to the above reasons its generally impossible to read the event logs on a different system to that which generated them, off a dead system, or after a major system malfunction. Even if the same system is booted there is no guarantee that the services have all started properly. Making the event log as a primary logging mechanism for a major os is severely inadequte.

Developers should not use the windows event logging mechanism for anything serious. (Although a windows developer I know told me that you need to do so to get 'windows certified' - Im not sure what that means if anything, but it certainly motivates them to use it).

Windows System adminsitrators need to be aware of the limitations, and in fact should probably install a syslog server to record all logging messages. There are a number of event log to syslog plugins which do the job.

Forensic examiners have to live with it, and should use PyFlags event log message database to guess what the log files say (That sounds rediculous, but unfortunately thats how it is).
"""
from format import *
import sys

class EventType(WORD_ENUM):
    types = {
        1:"Error",
        2:"Warning",
        4:"Information",
        }

class TERMINATED_UCS16(TERMINATED_STRING):
    """ The UCS16 strings in the array are seperated by 3 nulls """
    terminator='\x00\x00\x00'
    def read(self,data):
        result=TERMINATED_STRING.read(self,data)
        ## Note that result includes the terminator, so we subtract 2
        ## nulls to remove it and still maintain a sane Unicode string
        try:
            string=UCS16_STR(result,len(result)-2)
            "%s" % string
        except:
            string=UCS16_STR('',0)
            self.raw_size=0
        
        return string

class TERMINATED_UCS16_Array(ARRAY):
    target_class=TERMINATED_UCS16
    
class Event(SimpleStruct):
    """ The Event log file is a sequence of event structures followed by a list of NULL terminated UCS16 strings.
    """
    def init(self):
        self.fields = [
            [ LONG,1,'size' ],
            [ STRING,4,'Magic'],
            [ LONG,1,'RecordNumber'],
            [ TIMESTAMP,1,'TimeGenerated'],
            [ TIMESTAMP,1,'TimeWritten'],
            [ WORD,1,'EventID'],
            [ WORD,1, 'pad'],
            [ EventType,1, 'EventType'],
            [ WORD,1, 'NumStrings'],
            [ WORD,1, 'EventCategory'],
            [ BYTE_ARRAY,26,'Unknown'],
            ]

    def read(self,data):
        result=SimpleStruct.read(self,data)
        if result['Magic']!='LfLe':
            raise IOError('LfLe record not found at location 0x%08X' % data.offset)
        
        ## Following the struct is an array of NumStrings UCS16 strings:
        NumStrings=result['NumStrings'].get_value()
        self.add_element(result,TERMINATED_UCS16_Array(data[14*4:],NumStrings),'Strings')
        return result
    
    def size(self):
        """ The size of this structure is determined by the size element """
        if not self.data:
            self.initialise()
            
        return self['size'].get_value()
       
if __name__ == "__main__":
    fd=open(sys.argv[1],'r')

    buffer = Buffer(fd=fd)
    while 1:
        try:
            event = Event(buffer)
            print event
            buffer=buffer[event.size():]
        except IOError,e:
            print e
            break
