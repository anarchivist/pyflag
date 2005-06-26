# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
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
""" This scanner scans a file for its mime type and magic """
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem
import pyflag.DB as DB
import os.path
import pyflag.logging as logging
import pyflag.Scanner as Scanner

class TypeScan(Scanner.GenScanFactory):
    """ scan file and record file type (magic)

    In addition to recording the file type, this class can also perform
    an action based on the mime type of the file"""
    order=5
    default=True
    def __init__(self,dbh, table,fsfd):
        dbh.execute(""" CREATE TABLE IF NOT EXISTS `type_%s` (
        `inode` varchar( 20 ) NOT NULL,
        `mime` varchar( 50 ) NOT NULL,
        `type` tinytext NOT NULL )""" , table)
        self.dbh=dbh
        self.table=table

        ## Create indexes on this table immediately because we need to select
        self.dbh.check_index('type_%s' % table,'inode')

    def reset(self):
        Scanner.GenScanFactory.reset(self)
        self.dbh.execute("drop table if exists `type_%s`",self.table)

    def destroy(self):
        pass
#        self.dbh.execute('ALTER TABLE type_%s ADD INDEX(inode)', self.table)

    class Scan(Scanner.BaseScanner):
        size=0
        
        def __init__(self, inode,ddfs,outer,factories=None,fd=None):
            Scanner.BaseScanner.__init__(self, inode,ddfs,outer,factories)
            self.filename=self.ddfs.lookup(inode=inode)
            self.type_mime = None
            self.type_str = None
        
        def process(self, data,metadata=None):
            if(self.size < 100):
                magic = FlagFramework.Magic(mode='mime')
                magic2 = FlagFramework.Magic()
                self.type_mime = magic.buffer(data)
                self.type_str = magic2.buffer(data)
                metadata['mime']=self.type_mime
                metadata['magic']=self.type_str

            self.size = self.size + len(data)

        def finish(self):
            # insert type into DB
            self.dbh.execute('INSERT INTO type_%s VALUES(%r, %r, %r)', (self.table, self.inode, self.type_mime, self.type_str))
            # if we have a mime handler for this data, call it
            logging.log(logging.DEBUG, "Handling inode %s = %s, mime type: %s, magic: %s" % (self.inode,self.filename,self.type_mime, self.type_str))
