""" EventLogTool is a stand along event log manipulation utility. It uses the main PyFlag Event log messge database to resolve messages in event logs (.evt files).

Note that windows event logs do not contain the entirety of the message. They typically refer to service name containing specific messages. The service name in turns names a DLL through the registry which contains the messages in its .rsrc section.

PyFlag maintains a database linking messages with services. This is so that event logs may be read independantly from the registry and files on the system. Unfortunately, the messages themselves can not be distributed with PyFlag due to copyright reasons, hence EventLogTool must first populate the database from an existing known good system.

PyFlag maintains two main event log tables:

EventServices: links the Event log service name with the dll name
EventMessages: links messages with the dll name

"""
# ******************************************************
# Copyright 2004
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
import os
from format import *
from plugins.FileFormats.BasicFormats import *
import DB
import logging

parser = OptionParser()

parser.add_option("-m", "--mode", default='dll',
                  help="search a list of directories for dll with messages")

(options, args) = parser.parse_args()

if options.mode == 'dll':
    import FileFormats.PElib as PElib

    dbh=DB.DBO()
    dbh.execute("""CREATE TABLE if not exists `EventMessages` (
    `filename` VARCHAR( 50 ) NOT NULL ,
    `message_id` INT unsigned NOT NULL ,
    `message` TEXT NOT NULL ,
    `offset` INT NOT NULL
    ) """)

    for directory in args:
        for dirpath, dirnames, filenames in os.walk(directory):
            for F in filenames:
                f=F.lower()
                if f.endswith('dll'):
                    logging.log(logging.DEBUG, "Opening %s/%s to extract messages" % (dirpath,f))
                    fd = open("%s/%s" % (dirpath,F))
                    b = Buffer(fd=fd)
                    
                    dbh.mass_insert_start('EventMessages')
                    try:
                        m=PElib.get_messages(b)
                        for k,v in m.messages.items():
                            dbh.mass_insert(filename = f,
                                            message_id = k,
                                            message = v['Message'],
                                            offset = v.buffer.offset,
                                            )

                    except (IndexError, IOError, AttributeError):
                        logging.log(logging.VERBOSE_DEBUG, "%s does not contain messages" % f)

                    dbh.mass_insert_commit()

elif options.mode == 'reg':
    import FileFormats.RegFile as RegFile
    dbh=DB.DBO()

    for filename in args:
        fd = open(filename)
        b = Buffer(fd=fd)

        header = RegFile.RegF(b)
        root_key = header['root_key_offset'].get_value()
        
        key = RegFile.get_key(root_key, 'ControlSet001/Services/Eventlog')
        for log_types in key.keys():
            for application in log_types.keys():
                appname = application['key_name']
                print "Appname %s " % appname
                for v in application.values():
                    print v
                    
                try:
                    v = application.value('EventMessageFile')
                    print appname, v['data']
                except KeyError:
                    pass
