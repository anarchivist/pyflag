# Michael Cohen <scudette@users.sourceforge.net>
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
""" This module adds support for Microsoft Outlook personal file folders (pst files).

There is a scanner which executs the scanner factory train on files
within the pst file, such files include email bodies and attachments,
contact details, appointments and journal entries.
"""
import pyflagsh
import pyflag.tests
import pyflag.Scanner as Scanner
import pyflag.CacheManager as CacheManager
import os, subprocess
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.FileSystem as FileSystem

class PstScan(Scanner.GenScanFactory):
    """ Recurse into Pst Files """
    default = True
    order=99
    depends = ['TypeScan', 'RFC2822' ]
    group = "FileScanners"

    class Drawer(Scanner.Drawer):
        description = "File Type Related Scanners"
        group = "FileScanners"
        default = True

    class Scan(Scanner.StoreAndScanType):
        types = (
            'application/x-msoutlook',
            )
        
        def external_process(self,fd):
            """ This is run on the extracted file """
            filename = CacheManager.MANAGER.provide_cache_filename(self.case, self.fd.inode)

            dirname = filename+"_"
            try:
                os.mkdir(dirname)
            except OSError: pass

            ## We spawn libpst rather than incorporate in process to
            ## protect ourselves against memory leaks and seg faults
            ## in libpst.
            readpst_binary = os.path.join(config.FLAG_BIN, "readpst")
            subprocess.call([readpst_binary, '-o', dirname, "-w", filename])

            ## Create the required VFS Inodes
            for t in ['Inbox','Sent Items']:
                new_inode_id = self.ddfs.VFSCreate(self.fd.inode,
                                                   "x"+t, t )

                CacheManager.MANAGER.create_cache_from_file(self.case,
                                                            self.fd.inode + "|x" + t,
                                                            os.path.join(dirname,t),
                                                            inode_id = new_inode_id)

                ## Scan the inbox:
                fd = self.ddfs.open(inode_id = new_inode_id)
                Scanner.scanfile(self.ddfs, fd, self.factories)


class PstScannerTest(pyflag.tests.ScannerTest):
    """ Test handling of pst files """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.4.e01"
    subsystem = 'EWF'
    offset = "16128s"
    
    def test01RunScanner(self):
        """ Test Zip scanner handling of pst files """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'PstScan'])
