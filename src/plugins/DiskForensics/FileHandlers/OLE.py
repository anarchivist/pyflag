# ******************************************************
# Copyright 2007: Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
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
""" This is a scanner which find properties in various OLE (microsoft
Office) files.
"""

import pyflag.Scanner as Scanner
import pyflag.DB as DB
import FileFormats.OLE2 as OLE2
from pyflag.format import Buffer
import re
import pyflag.FlagFramework as FlagFramework
import pyflag.FileSystem as FileSystem

class OLEScan(Scanner.GenScanFactory):
    """ Scan OLE2 files """
    default = True
    depends = ['TypeScan']

    class Scan(Scanner.StoreAndScanType):
        types = (
            'application/msword',
            )

        def mesg_property(self, property, file):
            return OLE2.mesg_property(property,file)

        def mesg_attach(self, property, file):
            return OLE2.mesg_attach(property,file)

        def mesg_receipt(self, property, file):
            return OLE2.mesg_receipt(property,file)

        def parse_summary_info(self, property, file):
            return OLE2.parse_summary_info(property, file)

        dispatch = {
            "__substg1.0": mesg_property,
            "__attach_version1.0": mesg_attach,
            "__recip_version1.0": mesg_receipt,
            "SummaryInformation": parse_summary_info,
            }

        def store_file(self, metadata):
            """ Creates the VFS node and scans it """
            try:
                data = metadata['Attachment data']
            except KeyError: return

            path = self.ddfs.lookup(inode = self.fd.inode)
            new_inode = "%s|O%s" % (self.fd.inode, self.count)
            self.count+=1
            filename = metadata.get('Attach filename', metadata.get('Attach long filenm','Attachment'))
            print "Creating a new inode %s on %s/%s" % (new_inode, path, filename)
            
            ## Create a cache file:
            out_fd = open(FlagFramework.get_temp_path(self.case, new_inode),'w')
            out_fd.write(data)
            out_fd.close()

            self.ddfs.VFSCreate(None, new_inode,
                                "%s/%s" % (path, filename),
                                size = len(data))


            new_fd = self.ddfs.open(inode = new_inode)
            Scanner.scanfile(self.ddfs, new_fd, self.factories)
            
        
        def external_process(self, fd):
            attach_metadata = {}
            metadata = {}
            self.count = 0
            dbh = DB.DBO(self.case)
            dbh.mass_insert_start('xattr')
            f = OLE2.OLEFile(Buffer(fd=fd))
            for p in f.properties:
                for i in self.dispatch.keys():
                    property_name = p['pps_rawname'].__str__()
                    if re.search(i,property_name):
                        for prop, value in self.dispatch[i](self, p,f):
                            ## We store related metadata for 
                            if prop.startswith("Attach"):
                                ## If we have a repreated attachement
                                ## property - we flush the old set and
                                ## start again - this is for the case
                                ## when we have multiple attachments.
                                if attach_metadata.has_key(prop):
                                    self.store_file(attach_metadata)
                                    attach_metadata = {}
                                else:
                                    attach_metadata[prop] = value
                            else:
                                ## Not Attachment: Store the metadata
                                ## in the xattr table:
                                value = value.__str__().strip()
                                if len(value)>1:
                                    dbh.mass_insert(inode_id = self.fd.inode_id,
                                                    property = prop,
                                                    value = value)
                                metadata[prop] = value

            ## Finalise the attachments
            self.store_file(attach_metadata)

## This is basically a noop because the scanner caches the file on
## disk. FIXME: This is very lazy... It would be nice if we could
## recreate the file if the cache does not exist. This way we can
## delete all files in the cache with no effect.
class OLEFile(FileSystem.File):
    specifier = 'O'

## UnitTests:
import unittest
import pyflag.pyflagsh as pyflagsh
from pyflag.FileSystem import DBFS
import pyflag.tests

class OLETests(pyflag.tests.ScannerTest):
    """ Tests OLE Scanner """
    test_case = "PyFlag Test Case"
    test_file = "pyflag_stdimage_0.2.sgz"
    subsystem = 'SGZip'
    offset = "16128s"

    def test01OLEScanner(self):
        """ Test OLE Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "OLEScan", "TypeScan"
                                   ])                   ## List of Scanners
