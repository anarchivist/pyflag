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
from Carver import Reassembler
SECTOR_SIZE = 512


parser = OptionParser(usage="""%prog """)
parser.add_option('-i', '--index', default=None,
                  help = 'Index file to operate on')

parser.add_option('-c', '--create', default=False, action="store_true",
                  help = 'Create a new index file')

parser.add_option('-m', '--maps', default=False,  action="store_true",
                  help = 'Carve the index file by creating initial map files')

parser.add_option('-p', '--print', default=False, action="store_true",
                  help = 'print the index hits')

(options, args) = parser.parse_args()

if not options.index:
    print "Need an index file to operate on."
    sys.exit(1)

## For now use regex - later convert to pyflag indexs:
regexs = {
    'OBJECTS': '(\d+) (\d+) obj',
    'XREFS'  : '([\r\n ])xref([\r\n])',
    'STARTXREF' : 'startxref([\r\n])',
    }

cregexs = {}
hits = {}

def build_index():
    ## Compile the res
    for k,v in regexs.items():
        cregexs[k] = re.compile(v)

    BLOCK_SIZE = 409600

    p = pickle.Pickler(open(options.index,'w'))

    offset = 0
    fd = open(args[0],'r')
    while 1:
        data = fd.read(BLOCK_SIZE)
        if len(data)==0: break

        for k,v in cregexs.items():
            for m in v.finditer(data):
                print "Found %s in %s" % (k, offset + m.start())
                try:
                    hits[k].append(offset + m.start())
                except KeyError:
                    hits[k] = [ offset + m.start(), ]

        offset += len(data)

    ## Serialise the hits into a file:
    p.dump(hits)

    print hits

def save_map(filename, pdf, image_fd, hits):
    """ Saves a carving map from an xref table.

    We look through the hits to see which object is likely to belong
    to each item of the xref table.


    The file name is chosen as the offset of the table.
    """
    description = '\n#'.join(pdf.__str__().splitlines())
    fd = open("%s.map" % filename, 'w')
    fd.write("#"+description+"\n")
    
    for id, offset, generation, type in pdf.xref:
        print "%s - %s %s" % (id, offset, type)
        if type == 'n':
            possibles = [ x for x in hits['OBJECTS'] if x % 512 == offset % 512 ]
            for possibility in possibles:
                image_fd.seek(possibility,0)
                line = image_fd.readline()
                if not line.startswith("%s %s" % (id, generation)):
                    continue
                
                fd.write("%s %s Object_%s\n" % (offset, possibility,id))

    fd.close()
    
def print_xrefs():
    p = pickle.Unpickler(open(options.index,'r'))
    hits = p.load()

    image_fd = open(args[0],'r')

    total_xrefs = {}

    for xref in hits['XREFS']:
        print "Reading XREFs table from %s "% xref
        image_fd.seek(xref, 0)
        
        p = PDF.PDFParser(image_fd)

        ## Read until the EOF marker
        while p.next_token() != "RESET_STATE" and p.error < 10:
            pass

        #print p.objects
        ## Try to grab an XREF offset
        p.START_XREF(None,None)
        
        #print p.pdf
        total_xrefs[xref] = p.pdf
        save_map(xref, p.pdf, image_fd, hits)

    ## See if this xref table is related to another table:
    print total_xrefs.keys()
    for x in total_xrefs.keys():
        print "Node %s has the following xrefs: " % x
        for xref_offset in total_xrefs[x].xref_offsets:
            for y in total_xrefs.keys():
                if y>x: continue
                
                print "Checking %s against xref at %s (%s,%s)" % (xref_offset, y, xref_offset % 512, y % 512)
                # Search for us refering to them: (The +1 is related
                # to the regex above having an extra \r\n at the
                # start)
                if xref_offset % SECTOR_SIZE == y % SECTOR_SIZE + 1:
                    print "Xref at offset %s is possibly related to xref at offset %s" % (y, x)
                    print "My range is %s, their range is %s" % (total_xrefs[y].xref_range,
                                                                 total_xrefs[x].xref_range,)
                    if total_xrefs[y].xref_range[0] == total_xrefs[x].xref_range[1] or \
                       total_xrefs[y].xref_range[1] == total_xrefs[x].xref_range[0]:
                        new_pdf = PDF.PDFFile()
                        new_pdf.xref = total_xrefs[x].xref + total_xrefs[y].xref
                        new_pdf.xref_range = [ min(total_xrefs[y].xref_range[0],
                                                   total_xrefs[x].xref_range[0]),
                                               max(total_xrefs[y].xref_range[1],
                                                   total_xrefs[x].xref_range[1]),
                                               ]
                        
                        print "Ranges for xref tables match - coalescing..."
                        save_map("%s-%s" % (x,y), new_pdf, image_fd, hits)

if options.create:
    build_index()
    
elif options.maps:
    print_xrefs()
    
elif getattr(options,'print'):
    p = pickle.Unpickler(open(options.index,'r'))
    hits = p.load()
    print hits

else: print "Nothing to do... try -h"
