""" This module implements features specific for POP Processing """
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
import re
from NetworkScanning import *

class POPScanner(GenScanFactory):
    """ Collect information about POP transactions.

    This is an example of a scanner which uses the Ethereal packet dissection, as well as the result of the Stream reassembler.
    """
    default = True

    def prepare(self):
        self.pop_connections={}
        
    ## Do we want to store pop specific things at all here???
##    def prepare(self):
##        ## This dict simply stores the fact that a certain Inode is
##        ## a POP stream. We deduce this by checking if ethereal
##        ## decodes it as such. I guess if we want to parse POP
##        ## streams which are not on port 110, we need to tell ethereal
##        ## this via its config file.
##        self.pop_connections = {}

##        ## This one stores messages within the pop stream. Note that a
##        ## single pop stream may contain multiple messages.
##        self.dbh.execute(
##            """ CREATE TABLE if not exists `pop_messages_%s` (
##            `id` int(11) unsigned NOT NULL auto_increment,
##            `inode` VARCHAR(255) NOT NULL,
##            `offset` int,
##            `length` int,
##            key `id` (`id`)
##            ) """,(self.table,))
            
##    def reset(self):
##        self.dbh.execute("drop table if exists pop_messages_%s",(self.table,))

    class Scan(NetworkScanner):
        def process(self,data,metadata=None):
            NetworkScanner.process(self,data,metadata)

            ## Is this a POP request?
            try:
                request = self.proto_tree['pop.request'].value()

                self.outer.pop_connections[metadata['inode']]=1
            except KeyError:
                pass

        def finish(self):
            for key in self.outer.pop_connections.keys():
                forward_stream = key[1:]
                ## Find the reverse stream:
                self.dbh.execute("select * from connection_details_%s where con_id=%r",(self.table,forward_stream))
                row=self.dbh.fetch()

                self.dbh.execute("select con_id from connection_details_%s where src_ip=%r and src_port=%r and dest_ip=%r and dest_port=%r",(self.table,row['dest_ip'],row['dest_port'],row['src_ip'],row['src_port']))
                row=self.dbh.fetch()
                reverse_stream=row['con_id']
                combined_inode = "S%s/%s" % (forward_stream,reverse_stream)

                print "inode S%s/%s is a pop connection" % (forward_stream,reverse_stream)

                ## We open the file and scan it for emails:
                fd = self.ddfs.open(inode=combined_inode)
                offset=0
                while 1:
                    data = fd.read(10000)
                    if len(data)==0: break
                    for match in re.finditer(r"(?sim)RETR\s+(\d+)\r?\n\+OK\s+(\d+)[^\n]*",data):
                        ## Add a new VFS node
                        path=self.ddfs.lookup(inode="S%s" % forward_stream)
                        path=os.path.dirname(path)
                        self.ddfs.VFSCreate(None,combined_inode+"|o%s:%s" % (match.end()+offset , match.group(2)),path+"/POP/Message_" + match.group(1))
