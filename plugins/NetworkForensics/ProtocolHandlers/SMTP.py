""" This module implements features specific for SMTP Processing """
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.76 Date: Sun Apr 17 21:48:37 EST 2005$
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
import pyflag.conf
config=pyflag.conf.ConfObject()
from pyflag.Scanner import *
import pyethereal,sys
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
import pyflag.FlagFramework as FlagFramework
from NetworkScanner import *
import pyflag.Reports as Reports

class SMTPScanner(GenScanFactory):
    """ Collect information about SMTP transactions.

    This is an example of a scanner which uses the Ethereal packet dissection, as well as the result of the Stream reassembler.
    """
    default = True

    def prepare(self):
        self.dbh.execute(
            """ CREATE TABLE if not exists `smtp_%s` (
            `inode` VARCHAR(255) NOT NULL,
            `offset` int,
            `length` int,
            `from` VARCHAR(255) NOT NULL,
            `to` VARCHAR(255) NOT NULL,
            `message_id` int(11) unsigned NOT NULL auto_increment
            ) """,(self.table,))
            
        def reset(self):
            self.dbh.execute("drop table if exists smtp_%s",(self.table,))

        class Scan(NetworkScanner):
            def process(self,data,metadata=None):
                NetworkScanner.process(self,data,metadata)

                ## Is this an SMTP request?
                try:
                    request = self.proto_tree['smtp.req.command'].value()
                    value = self.proto_tree['smtp.req.parameter'].value()

                    ## Check the store to see if we are currently tracking this:
                    key = "smtp_%s" % metadata['inode']
                    try:
                        track = self.store[key]
                    except KeyError:
                        track = {}
                        self.store.store(self.packet_id,key,track)
                except KeyError:
                    pass
                    
