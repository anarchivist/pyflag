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
            #print "0x%08X" % self.offset,
            marker = BasicFormats.USHORT(self.buffer[self.offset:], endianess='big')
            self.offset += marker.size()
            #print marker,
            
            if (0xFF00 & int(marker)) != 0xFF00:
                #print  "Incorrect marker at %X, stopping prematurely\n" % self.offset
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
            else:        
                size = BasicFormats.USHORT(self.buffer[self.offset:], endianess='big')
                # print size
                if int(size)<2:
                    #print "Section size is out of bounds"
                    self.error = True
                    break

                self.offset+=int(size)

        return result

    def size(self):
        return self.offset
            
class JpegCarver(Scanner.Carver):
    regexs = ["\xff\xd8....JFIF", "\xff\xd8....EXIF"]
    extension = 'jpg'        

    def get_length(self, fd, offset):
        """ Returns the length of the JPEG by reading the blocks.
        Algorithm taken from Samuel Tardieu <sam@rfc1149.net>
        * http://www.rfc1149.net/devel/recoverjpeg
        """
        buf = format.Buffer(fd=fd)[offset:]
        j = JPEG(buf)
        if j.error:
            return Scanner.Carver.get_length(self, fd,offset)
        else:
            return j.size()
    
#class CarveScan(Scanner.GenScanFactory):
class CarveScan:
    """ Carve out files """
    ## We must run after the Index scanner
    order = 300
    default = False
    depends = 'IndexScan'

    def __init__(self,fsfd):
        Scanner.GenScanFactory.__init__(self, fsfd)

        dbh = DB.DBO()
        self.ids = {}
        self.case = fsfd.case
        ## We need to ensure that the scanner regexs are in the
        ## dictionary:
        for c in Registry.CARVERS.classes:
            for expression in c.regexs:
                dbh.execute("select id from dictionary where word=%r limit 1", expression)
                row = dbh.fetch()
                if not row:
                    dbh.insert("dictionary", **{'word': expression,
                                                'class':'_Carver', 
                                                'type':'regex' })
                    id = dbh.autoincrement()
                else:
                    id = row['id']

                self.ids[id] = c


    class Scan(Scanner.BaseScanner):
        def finish(self):
            dbh=DB.DBO(self.fd.case)
            ## Find the matches for our classes:
            sql = " or ".join(["word_id = '%s'" % x for x in self.outer.ids.keys()])
            dbh.execute("select word_id,offset from LogicalIndexOffsets where offset>0 and offset<%r and inode_id = %r and (%s)",
                        (self.fd.size, self.fd.inode_id, sql))
            for row in dbh:
                ## Ignore matches which occur within the length of the
                ## previously found file:
                #if row['offset']<offset: continue
                offset = row['offset']
                ## Allow the carver to work with the offset:
                fsfd = FileSystem.DBFS(self.case)
                carver = self.outer.ids[row['word_id']](fsfd)
                carver.add_inode(self.fd, offset, self.factories)
                
                
## Unit tests:
import unittest
import pyflag.pyflagsh as pyflagsh
import pyflag.tests

class CarverTest(pyflag.tests.ScannerTest):
    """ Carving Tests """
    test_case = "PyFlagIndexTestCase"
    test_file = "pyflag_stdimage_0.4.sgz"
    subsystem = 'SGZip'
    order = 30
    offset = "16128s"
    
    def test01CarveImage(self):
        """ Carving from Image """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'CarveScan', 'IndexScan','TypeScan'])

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
