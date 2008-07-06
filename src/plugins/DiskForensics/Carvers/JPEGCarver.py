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
""" This module implements a carver looking for specific file types in
the image.

The carver uses the indexer to pre-locate carved headers which makes
it very fast. We create VFS nodes for carved files, which means that
the carved files do not actually take storage space. This stratgy
allows PyFlag's Carver to be extremely fast.

Carved files are scanned with the usual scanners once they are
discovered.
"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import PIL.Image
import pyflag.Registry as Registry
import pyflag.FileSystem as FileSystem
import pyflag.format as format
import plugins.FileFormats.BasicFormats as BasicFormats
import plugins.FileFormats.DAFTFormats as DAFTFormats
import pyflag.Indexing as Indexing
import pyflag.pyflaglog as pyflaglog

## Carvers raise this exception
class CarverError(RuntimeError):
    pass

## This is a basic file format which reads in jpeg files. Its mostly
## used to work out how long a jpeg is for the carver.
class JPEG(BasicFormats.SimpleStruct):
    fields = [
        [ 'magic', BasicFormats.USHORT_CONSTANT, dict(expected = 0xFFD8, endianess='big') ],
        ]

    error = False
    
    def read(self):
        result = BasicFormats.SimpleStruct.read(self)
        while 1:
            marker = BasicFormats.USHORT(self.buffer[self.offset:], endianess='big')
            #print marker, self.offset

            self.offset += marker.size()
            
            if (0xFF00 & int(marker)) != 0xFF00:
                raise CarverError("Incorrect marker at %X, stopping prematurely" % self.offset)
                self.error = True
                break

            if marker==0xFFD9:
                return result

            if marker==0xFF01 or marker==0xFFFF:
                #print "Found lengthless section"
                continue

            if marker==0xFFDA:
                def cmp(data, offset):
                    if data[offset+1]=='\x00':
                        return False

                    code = ord(data[offset+1])
                    if code >= 0xD0 and code <= 0xD7:
                        return False

                    return True
                
                #print "Looking for end marker (Which is a sequence 0xFFxx but not 0xFF00 or 0xFFDx)"
                marker = DAFTFormats.SearchFor(self.buffer[self.offset:],
                                               search="\xff", within=2000000,
                                               cmp = cmp)
                self.offset+=marker.size()
                #print "Found end marker at %s " % self.offset
            else:        
                size = BasicFormats.USHORT(self.buffer[self.offset:], endianess='big')
                if int(size)<2:
                    #print "Section size is out of bounds"
                    self.error = True
                    break

                self.offset+=int(size)

        return result

    def size(self):
        return self.offset

def ensure_carver_signatures_in_dictionary(carver):
    for word in carver.regexs:
        id = Indexing.insert_dictionary_word(word, word_type='regex',
                                             classification='_Carver',
                                             binary=True)
        ## Make sure the carver knows about it
        carver.ids.append(id)

class CarverScan(Scanner.BaseScanner):
    def get_length(self, fd, offset):
        """ Returns the length of the carved image from the inode
        fd. We should use fd rather than self.fd in order to not
        touch self.fd's readptr.
        """
        ## By default we just read a fixed number of bytes - Note
        ## that its better to calculate the length properly.
        length = min(self.fd.size-offset, self.outer.length)
        return length

    def add_inode(self, fd, offset):
        """ This is called to allow the Carver to add VFS inodes.

        Returns the new inode_id.
        """
        ## Calculate the length of the new file
        length = self.get_length(fd,offset)
        new_inode = "%s|o%s:%s" % (self.fd.inode, offset, length)
        path, inode, inode_id = self.fsfd.lookup(inode_id = self.fd.inode_id)
        name = DB.expand("%s/%s.%s",(path,offset, self.outer.extension))

        ## By default we just add a VFS Inode for it.
        new_inode_id = self.fsfd.VFSCreate(None,
                                           new_inode,
                                           name,
                                           size = length,
                                           )
        
        pyflaglog.log(pyflaglog.DEBUG, DB.expand("Added Carved inode %s (id %s) as %s",
                                                 (new_inode, new_inode_id,
                                                  name)))

    def examine_hit(self, fd, offset, length):
        """ This function is called on each regex hit to examine
        it further. Here we need to decide if its a false positive
        and ignore it - or else call add_inode() to add a new
        inode.
        """
        ## Just call add_inode - here we would implement any
        ## special checks to eliminate false positives.
        self.add_inode(fd, offset)

    def finish(self):
        ## Open another fd
        self.fsfd = FileSystem.DBFS(self.fd.case)
        fd = self.fsfd.open(inode_id = self.fd.inode_id)

        ## Work out our or clause:
        or_claus = " or ".join(["id=%s" % x for x in self.outer.ids])

        dbh=DB.DBO(self.fd.case)
        ## Find the matches for our classes:
        dbh.execute("select offset, length from LogicalIndexOffsets "
                    "where offset>0 and offset<%r and inode_id = %r and "
                    "word_id in (select id from `%s`.dictionary where "
                    "class='_Carver' and (%s))",
                    (self.fd.size, self.fd.inode_id, config.FLAGDB, or_claus))

        for row in dbh:
            ## Now examine each hit in detail to see if its valid:
            self.examine_hit(fd, row['offset'], row['length'])


class JPEGCarver(Scanner.GenScanFactory):
    """ Carve out JPEG Image files """
    ## We must run after the Index scanner
    order = 300
    default = False
    depends = 'IndexScan'
    group = 'Carvers'
    regexs = ["\xff\xd8....JFIF", "\xff\xd8....EXIF"]
    ## This will contain the ids of all our regexes
    ids = []
    extension = 'jpg'        
    length = 600000

    class Drawer(Scanner.Drawer):
        description = "File Carvers"
        group = 'Carvers'
        default = False

    class Scan(CarverScan):
        def get_length(self, fd, offset):
            """ Returns the length of the JPEG by reading the blocks.
            Algorithm taken from Samuel Tardieu <sam@rfc1149.net>
            * http://www.rfc1149.net/devel/recoverjpeg
            """
            try:
                buf = format.Buffer(fd=fd)[offset:]
                j = JPEG(buf)
                return j.size()
            except CarverError,e:
                pyflaglog.log(pyflaglog.DEBUG, "Carver failed: %s" % e)
                return  min(self.fd.size-offset, self.outer.length)
            
ensure_carver_signatures_in_dictionary(JPEGCarver)

## Unit tests:
import unittest
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class JPEGCarverTest(pyflag.tests.ScannerTest):
    """ JPEG Carver tests """
    test_case = "PyFlagIndexTestCase"
    test_file = "pyflag_stdimage_0.4.e01"
    subsystem = 'EWF'
    order = 30
    offset = "16128s"
    
    def test01CarveImage(self):
        """ Carving from Image """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'JPEGCarver'])

        ## See if we found the two images from within the word
        ## document:
        expected = [ "Itest|K1289-0-0|o150712:85550", "Itest|K1289-0-0|o96317:141763"]
        
        dbh = DB.DBO(self.test_case)
        for inode in expected:
            dbh.execute("select inode from inode where inode=%r limit 1", inode)
            row = dbh.fetch()
            self.assert_(row != None)


if __name__ == '__main__':
    import sys
    fd = open(sys.argv[1])
    b = format.Buffer(fd=fd)
    h = JPEG(b)
    print "Size of jpeg is %s" % h.size()
    
