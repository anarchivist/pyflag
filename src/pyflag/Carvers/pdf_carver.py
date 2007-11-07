#!/usr/bin/python2.4
# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
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

"""
PDF File carving
================

The PDF format is describe in 'The PDF Reference' 6th edition
available from the Adobe web site.

The format is essentially a line oriented text based format with
embedded binary data. An implementation of a tokeniser and parser for
PDF can be found in the file PDF.py. Here we just describe some high
level properties of the PDF format.

The Objects
-----------
PDFs Contain a sequence of objects within the file. Objects are high
level containers for other data and in particular stream data may be
contained in the object. Objects are numbered by an object number and
a generation number and followed by the object tag which looks like:

x y obj

where x is the object number, y is the generation number.

XREF Tables
-----------
For fast access into the file, the standard defines XREF tables. These
tables contain runs of offsets into the file for each object ID
specified. An XREF table is followed by a trailer section which
describes a number of different properties of the table. Some of the
more useful properties include the document ID (which can be used to
collate XREF tables belonging to the same document together) and the
/Prev tag which specifies the offset to the previous XREF table.

The XREF tables provide us with a large number of identified points,
because they satisfy the basic properties for identified point
sources:

1) They reference an exact offset within the reassembled file.

2) It is possible to determine with a high level of confidence if the
point refered to is in fact the point expected.

The first property comes about from the offsets to all the objects in
the document. While the second point comes about from being able to
identify the specific object referenced (i.e. if we follow a reference
to object 3, we can verify if this is object 3 when we look at
it). Furthermore, given a model of fragmentation (i.e. that
fragmentation can only occur on sector boundaries) it is possible to
find all objects on the disk which satisfy this requirement.

These properties make the identification of points much simpler. We
use this to build the carver object, and identify the required points.

The algorithm then proceeds in the following steps:

1) All objects and xref tables are found and indexed on the disk.
2) possible objects are located from the index for each xref table by
assuming framentation on sector boundaries (i.e. offset required % 512
= object offset % 512).

3) The XREF tables belonging to the same file are merged together
(using the document ID as a common ID)

4) For each file, a carver object is instantiated and identified
points are added to the object.

5) Each reassembled file is parsed using the PDF parser to locate
discontinuities.

6) When a discontinuity is detected, an identified point is added and
the carver attempts to resolve it by reverse interpolation. If this
works the discontinuity was a first level discontinuity (i.e. only 1
discontinuity between the identified points).

7) If this does not work, an exhaustive search is required to find the
sector which works correctly. When the correct sector is found, a new
identified point is added, and the search for a first level
discontinuity restarts.

8) Once all discontinuities are resolved, the parser is used to locate
the end of the document.

9) The document is saved to disk.

"""

from optparse import OptionParser
import FileFormats.PDF as PDF
import re,sys
import pickle
import Carver
SECTOR_SIZE = 512

class PDFDiscriminator:
    slow = False

    def __init__(self, reassembler, verbose=None):
        self.reassembler = reassembler
        self.p = PDF.PDFParser(reassembler)

        if verbose:
            self.p.verbose = verbose

    def parse(self, length_to_test):
        """ Runs a PDF parser over the carver until end_offset"""
        ## Rewind back to a convenient spot if we are allowed to:
        if self.slow:
            print "Making new parser"
            self.p = PDF.PDFParser(self.reassembler)
            self.reassembler.seek(0)
        else:
            self.p.restore_state()

        ## We are only willing to tolerate a small number of errors
        while self.p.processed < length_to_test and self.p.error < 10:
            self.p.next_token()
            
        ## Return the error count
        return self.p.error

class PDFCarver(Carver.CarverFramework):
    ## These are the artifacts we index:
    regexs = {
        'OBJECTS': '(\d+) (\d+) obj',
        'XREFS'  : '([\r\n ])xref([\r\n])',
        'STARTXREF' : 'startxref([\r\n])',
        }

    def build_maps(self, index_file):
        hits = self.load_index(index_file)
        image_fd = open(self.args[0],'r')
        total_xrefs = {}
        carvers = {}
        
        for xref in hits['XREFS']:
            print "Reading XREFs table from %s "% xref
            image_fd.seek(xref, 0)

            p = PDF.PDFParser(image_fd)
            
            ## Read until the EOF marker
            while p.next_token() != "RESET_STATE" and p.error < 10:
                pass

            if p.error > 0: print "Errors parsing the XREF table this will probably be corrupted"
            total_xrefs[xref] = p.pdf
            c = self.make_carver_from_xref(p.pdf, image_fd, hits)
            c.save_map("%s.map" % xref)
            carvers[xref] = c

        ## Now try to coalesce xref tables together:
        for x in total_xrefs.keys():
            for xref_offset in total_xrefs[x].xref_offsets:
                for y in total_xrefs.keys():
                    ## Only coalesce the tables once:
                    if y>x: continue

                    ## Can the two offsets plausibly be related by the
                    ## modulo rule? (The +1 is related to the regex
                    ## above having an extra \r\n at the start)
                    if xref_offset % SECTOR_SIZE == y % SECTOR_SIZE + 1:
                        print "Xref at offset %s is possibly related to xref at offset %s (modulo rule)" % (y, x)
                        print "%s's range is %s, %s's range is %s" % (y,total_xrefs[y].xref_range,
                                                                      x,total_xrefs[x].xref_range,)
                        # Search for us refering to them:
                        if total_xrefs[y].xref_range[0] == total_xrefs[x].xref_range[1] or \
                               total_xrefs[y].xref_range[1] == total_xrefs[x].xref_range[0]:
                            print "Ranges for xref tables match - coalescing..."
                            carvers[x].coalesce(carvers[y])
                            ## Save the new mapping function
                            carvers[x].save_map("%s-%s.map" % (x,y))
            
    def make_carver_from_xref(self, pdf, image_fd, hits):
        """ Derives a carver object from a pdf object containing XREF tables.

        We basically find objects which are plausible for this xref
        table (i.e. satisfy the modulo rule).
        """
        c = Carver.Reassembler(None)

        for id, offset, generation, type in pdf.xref:
            if type == 'n':
                ## Enumerate all the possibilities which obey the
                ## modulo rule
                possibles = [ x for x in hits['OBJECTS']
                              if x % SECTOR_SIZE == offset % SECTOR_SIZE ]

                ## Check the object with the correct ID:
                for possibility in possibles:
                    image_fd.seek(possibility)
                    line = image_fd.read(SECTOR_SIZE)
                    ## These are not the objects we are looking for:
                    if not line.startswith("%s %s obj" % (id, generation)):
                        continue

                    c.add_point(offset, possibility, "Object_%s" % id)

        return c

    slow = False

    def __init__(self):
        ## Add a couple of extra command line args:
        Carver.CarverFramework.__init__(self)
        self.parser.add_option('-s', '--slow', default=False, action='store_true',
                               help = 'Disable state saving optimisations (Not usually needed)')

        self.parser.add_option('-v', '--verbose', default=0, type='int',
                               help = "Verbosity")

    def generate_function(self, c):
        d = PDFDiscriminator(c, self.options.verbose)
        d.slow = self.options.slow

        for x in range(0, c.size(), SECTOR_SIZE):
            y_forward, left = c.interpolate(x, True)
            y_reverse, left = c.interpolate(x, False)

            if y_reverse < 0: continue

            ## This is an ambiguous point:
            if y_forward != y_reverse:
                print "Ambiguous point found at offset %s: forward=%s vs reverse=%s..." % (x, y_forward, y_reverse)

                c.add_point(x, y_reverse, comment = "Forced")

                ## Check a reasonable way after the next identified point
                ## (This might need some work)
                until_offset = left + x + SECTOR_SIZE

                print "Checking until %s" % (until_offset)

                ## Check the errors:
                try:
                    error_count = d.parse(until_offset)
                except Exception,e:
                    print "Exception occured %s" % e
                    error_count = 10
                    
                if error_count == 0:
                    sys.stderr.write("Found a hit at %s\n" % x)
                else:
                    ## No thats not the right point.
                    c.del_point(x)
                    print "Total errors were %s" % error_count

        ## Perform a complete start to finish verification to find the
        ## end of file:
        print "Verifying complete file:"
        if self.options.slow:
            p = PDF.PDFParser(c)
            c.seek(0)
        else:
            p = d.p
            p.restore_state()
        
        while 1:
            token = p.next_token()
            if token == 'RESET_STATE' and p.processed > c.points[-1]:
                c.add_point(p.processed, c.interpolate(p.processed), 'EOF')
                print "Error count = %s" % p.error
                break

            if p.error > 10:
                print "Too many errors - reconstructed file is likely to be corrupted"
                break

if __name__=="__main__":
    c = PDFCarver()
    c.parse()
