""" This is a scanner and log viewer to assist in analysing Windows Event logs on a forensic image.

Windows event logs do not contain the entirety of the message. They typically refer to service name containing specific messages. The service name in turns names a DLL through the registry which contains the messages in its .rsrc section. (For more details see FileFormats/EVTLog.py)

This scanner populates the PyFlag message database with those messages it finds in PE executables encountered during a filesystem scan. This is useful in case the suspect system has software installed which was never encountered before by this installation of PyFlag. Once the installation stores the messages, the stand alone EventLogTool may be used.

The overall effect is that PyFlag will be able to analyse event log messages even after the target system has uninstalled its dll. This is commonly seen by the windows event log viewer indicating a messgae such as:

The description for Event ID ( xxx ) in Source ( yyy ) cannot be found. The local computer may not have the necessary registry information or message DLL files to display messages from a remote computer.

"""
# ******************************************************
# Copyright 2004
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
import pyflag.pyflaglog as pyflaglog
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import FileFormats.PElib as PElib
from format import *
import os
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework

class DLLInitDB(FlagFramework.EventHandler):
    ## This will be used to init the default db
    def init_default_db(self, dbh, case):
        dbh.execute("""CREATE TABLE if not exists `EventMessages` (
        `filename` VARCHAR( 50 ) NOT NULL ,
        `message_id` INT unsigned NOT NULL ,
        `message` TEXT NOT NULL ,
        `offset` INT NOT NULL,
        UNIQUE KEY `filename,message_id` (`filename`,`message_id`)
        ) """)

        dbh.execute("""CREATE TABLE if not exists `EventMessageSources` (
        `filename` VARCHAR( 50 ) NOT NULL ,
        `source` VARCHAR(250)
        ) """)

class DLLScan(Scanner.GenScanFactory):
    """ Extract EventLog Messages from DLLs """
    default = True
    depends = [ 'TypeScan', 'RegistryScan']

    def destroy(self):
        ## populate the EventMessageSources table from the registry
        dbh=DB.DBO(self.case)
        dbh.execute("select * from reg where reg_key='EventMessageFile'")
        for row in dbh:
            service = os.path.basename(os.path.normpath(row['path']))
            self.pydbh.execute("select * from EventMessageSources where source=%r limit 1",service)
            pyrow=self.pydbh.fetch()
            if not pyrow:
                filename = row['value'].split("\\")[-1].lower()
                self.pydbh.execute("insert ignore into EventMessageSources set filename=%r, source=%r" , (filename, service))

    class Scan(Scanner.StoreAndScanType):
        types = [ 'application/x-dosexec' ]

        def external_process(self, fd):
            filename = self.ddfs.lookup(inode=self.inode)
            b = Buffer(fd=fd)

            pyflaglog.log(pyflaglog.DEBUG, "Opening %s to extract messages" % self.inode)
            pydbh = DB.DBO()
            pydbh.mass_insert_start('EventMessages')
            try:
                m=PElib.get_messages(b)
                for k,v in m.messages.items():
                    pydbh.mass_insert(filename = os.path.basename(filename),
                                    message_id = k,
                                    message = v['Message'],
                                    offset = v.buffer.offset,
                                    )

            except (IndexError, IOError, AttributeError):
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "%s does not contain messages" % filename)

## FIXME: This is not finished yet - need to finish the log viewer
