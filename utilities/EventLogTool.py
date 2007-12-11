#!/usr/bin/python
""" EventLogTool is a stand alone event log manipulation utility.

It uses the main PyFlag Event log messge database to resolve messages
in event logs (.evt files).

Windows event logs do not contain the entirety of the message. They
typically refer to service name containing specific messages. The
service name in turns names a DLL through the registry which contains
the messages in its .rsrc section. (For more details see
FileFormats/EVTLog.py)

PyFlag maintains a database linking messages with services. This is so
that event logs may be read independantly from the registry and files
on the system. Unfortunately, the messages themselves can not be
distributed with PyFlag due to copyright reasons, hence EventLogTool
must first populate the database from an existing known good system.

PyFlag maintains two main event log tables:

EventServices: links the Event log service name with the dll name
EventMessages: links messages with the dll name

prior to being able to load event logs with PyFlag, you must populate
the event messages and services in the database.

First populate the dll associations via the registry:
pyflag_launch utilities/EventLogTool --mode=reg /dos/windows/system32/config/system

Then populate the event messages (This will recurse throughout the
mounted directory to find all PE executables and add their messages,
if any, to the database).

pyflag_launch utilities/EventLogTool --mode=dll /dos/

Finally to be able to view the event log file:
pyflag_launch utilities/EventLogTool AppEvent.evt

Note:
This is only needed when using the standalone EventLogTool, or
before using the EventLog log driver within the PyFlag GUI. For a
forensic image loaded into a PyFlag case, you just need to enable the
EventLog scanner (which is enabled by default) during a filesystem
scan.
"""
# ******************************************************
# Copyright 2004-2006
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC5 Date: Wed Dec 12 00:45:27 HKT 2007$
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
from optparse import OptionParser
import os,sys
from format import *
from plugins.FileFormats.BasicFormats import *
import DB
import pyflag.pyflaglog as logging
import sys
import pyflag.conf
config=pyflag.conf.ConfObject()

config.set_usage(usage="""%prog [options]

Will perform according to mode the following functions:
-m dll:      Search all dlls under path for message resources and insert into the pyflag DB.
-m reg:     Extrach service name to dll mappings from registry files.
-m event:  Print all event logs in an evt file based on values in the pyflag DB.""",
                 version="Version: %prog PyFlag "+config.VERSION)

config.optparser.add_option("-m", "--mode", default='dll', choices=['dll', 'event', 'reg'], type='choice',
                            help="Set mode for operation (see above)")

config.optparser.add_option("-H", "--more_help", default=None, action='store_true',
                            help="Print more help")

config.parse_options()

if config.more_help:
    print __doc__
    sys.exit(-1)

def recurse(path):
    """ Recurses into all directories under path yielding real files """
    try:
        for f in os.listdir(path):
            for i in recurse("%s/%s" % (path,f)):
                yield i
    except OSError:
        yield path

if config.mode == 'dll':
    import FileFormats.PElib as PElib
    import FlagFramework

    dbh=DB.DBO()
    dbh.execute("""CREATE TABLE if not exists `EventMessages` (
    `filename` VARCHAR( 50 ) NOT NULL ,
    `message_id` INT unsigned NOT NULL ,
    `message` TEXT NOT NULL ,
    `offset` INT NOT NULL,
    UNIQUE KEY `filename,message_id` (`filename`,`message_id`)
    ) """)

    Magic=FlagFramework.Magic()

    for directory in config.args:
        for F in recurse(directory):
            f=F.lower()
            fd = open(F)
            data = fd.read(1024)
            magic = Magic.buffer(data)
            if "PE" in magic:
                fd.seek(0)
                b = Buffer(fd=fd)
                
                logging.log(logging.DEBUG, "Opening %s to extract messages" % F)
                dbh.mass_insert_start('EventMessages')
                try:
                    m=PElib.get_messages(b)
                    for k,v in m.messages.items():
                        dbh.mass_insert(filename = os.path.basename(f),
                                        message_id = k,
                                        message = v['Message'],
                                        offset = v.buffer.offset,
                                        )

                except (IndexError, IOError, AttributeError):
                    logging.log(logging.VERBOSE_DEBUG, "%s does not contain messages" % f)

                dbh.mass_insert_commit()

elif config.mode == 'reg':
    import FileFormats.RegFile as RegFile
    dbh=DB.DBO()

    dbh.execute("""CREATE TABLE if not exists `EventMessageSources` (
    `filename` VARCHAR( 50 ) NOT NULL ,
    `source` VARCHAR(250),
    UNIQUE KEY `filename` (`filename`)
    ) """)

    for filename in config.args:
        fd = open(filename)
        b = Buffer(fd=fd)

        header = RegFile.RegF(b)
        root_key = header['root_key_offset'].get_value()
        
        key = RegFile.get_key(root_key, 'ControlSet001/Services/Eventlog')
        for log_types in key.keys():
            for application in log_types.keys():
                appname = application['key_name']
                try:
                    v = application.value('EventMessageFile')
                    filename = v['data'].__str__().lower()
                    filename=os.path.basename(filename.replace("\\","/"))
                    dbh.execute("insert into EventMessageSources set filename=%r, source=%r",(filename,appname))
                    print "Added source '%s' as file %r" % (appname, filename)
                except (KeyError, DB.DBError):
                    pass

elif config.mode == 'event':
    import FileFormats.EVTLog as EVTLog
    dbh=DB.DBO()

    for filename in config.args:
        fd = open(filename)
        b = Buffer(fd=fd)
        header = EVTLog.Header(b)
        b=b[header.size():]
        
        while 1:
            try:
                event = EVTLog.Event(b)

                source = event['Source'].get_value()
                machine = event['Machine'].get_value()

                ## Find the filename for this source:
                dbh.execute("select filename from EventMessageSources where source=%r", source)
                row=dbh.fetch()
                if row:
                    dbh.execute("select message from EventMessages where filename=%r and message_id=%r", (row['filename'], event['EventID'].get_value()))
                    row = dbh.fetch()
                    if row:
                        message=EVTLog.format_message(row['message'],event['Strings'])
                    ## Message not found
                    else:
                        message="Unable to find message format string (Maybe file was not loaded with --mode=dll?). Parameters are: %s" % event['Strings']
                        
                ## Filename not found for this source:
                else: message="Unable to locate file for source %s. Maybe you need to run EventLogTool with the --reg flag on the SYSTEM registry hive? Parameters are: %s " % (source,event['Strings'])

                print "%s '%s' %s %s %s" % (event['TimeGenerated'],event['Source'],event['EventType'], event['Machine'],message)
                b=b[event.size():]
            except IOError,e:
##                print e
                break

