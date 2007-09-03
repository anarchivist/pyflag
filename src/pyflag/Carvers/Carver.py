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
import sys, re, os, pickle

""" This class abstracts the reassembled file 

Carving a file from an image can be seen as a mathematical operation
mapping sectors in the image into sectors in the logical reassembled
file.

If we plot the sequences of bytes from the file to the bytes in the
image it might look like this:

Bytes  |          /
In     |         /
Image  |     /|  |
       |    / |  |
       |   /  |  |
       |   |  | /
       |   |   /
       |  /
       | /
       |/
       ------------------>
       0     Bytes in File ->

The function mapping the bytes in the file to the bytes in the image
has a number of properties:

1) The slope of the function is always 1 (because there is a 1-1
mapping for the image with the file).

2) There are a number of discontiuities in the function at various
places.

3) The function is invertible - i.e. there is at most one file offset
for each value of the image offset (if such a value exists).

4) Discontinuities can only occur on sector boundaries (512 bytes).

The process of carving essentially boils down to estimating the
mapping function.

For a finite size image, there are actually only a finite number of
mapping functions, resulting from the permutations of all sectors with
each other (this number may be absolutely huge but it is actually
finite).

In order to find the correct mapping function, a series of deductions
and algorithms may be used to impose constraints on the function. The
constraints may be positive or negative constraints:

A positive constraint is a deduction which positively identifies a
point on the function's graph. This identification may stem from an
observation specific to the file format in question. For example, a
positively identified file header places a constraint on the first
sector of the file. Sometimes, depending on the file format, positive
constaints may be identified throughout the file.

A negative constraint can be defined as an observation that a certain
sector does not belong within the sequence observed. This might occur
if the sector clearly does not exhibit the characteristics required
from this file type (e.g. sector with binary bytes following a HTML
sector etc).

The job of the carver is therefore to first add as many positive
constraints as possible, and then iterate through the file and
discount those sectors which do not belong. (Hence imposing negative
constraints).

Consider the following possible mapping function:
         /| (1)
   |    / |
   |    | | 
   |    |/|  x 
   | (2)/ | /
   |   /| |/
   |  / | /  Potential discontinueties.
   | /  |/ (3)
   |x   /
   ----------------->

This function has 2 positively identified points (marked with
x). Since the points do not lie on the same line of slope one, there
must be at least one discontinuty between them. The figure shows 3
possibilities. Possibility 1 has 2 discontinuities. Possibilities 2
and 3 only have a single discontinuity.

We say that possibilities 2 and 3 exihibit first order fragementation,
while possibility 3 exhibits second order (or higher order)
framentation.

Interpolation:
--------------
In order to estimate the mapping function we must predict values on
the function which do not correspond to identified points. This
process is called interpolation. There are 2 possible ways to
interpolate between two identified points:
                
   |       
   |   Forward Interpolation
   |     /|    
   |P1  / | /
   |   x  |/
   |  /|  x  P2
   | / | /    
   |/  |/ Reverse Interpolation
   ----------------->

Forward interpolation
---------------------
The value is interpolated forward from P1 through a straight line of
unit slope which goes through P1. The line terminates where the file
offset is the same as that of P2.

Reverse interpolation
---------------------
The value is interpolated backwards from P2 through a straight line of
unit slope which goes through P2. The line terminates where the file
offset is the same as that of P1.


Ambiguous points
----------------
Note that any point between identified points dont need to lie on the
line connecting them. However, if we assume first order fragmentation
(i.e. only a single discontinuity between the two points), there are
two possible values for image offsets for a given file offset:

 Image offset
   |       
   |   X1 /|
   |     x |    
   |P1  /  |/
   |   x   x
   |  /|  /  P2
   | / | x    
   |/  |/ X2
   ----------------->  File offset

X1 and X2 are the possible points for a given file offset. X1 is
obtained for forward interpolation, while X2 is obtained by reverse
interpolation.

If P1 and P2 lie on the same line, X1==X2 and there is only a single
possibility. We term the case where P1 and P2 do not lie on the same
line as ambiguous. Of course the correct mapping function could only
have either X1 or X2, and our problem is to determine which one is
correct.


Although in theory there can be as many discontinuities between the
positively identified points as there are sectors, in practice the
total number of discontinuities is as low as possible (filesystems
generally try to keep data contiguous). Hence preference should be
given to those mapping functions with less discontinuities.

This file implements classes which make this simpler.
"""
import bisect

class Reassembler:
    """ This class presents a file like object for interpolating
    between identified points on the mapping function.
    """
    ## This controls if we will interpolate forward from one
    ## identified point to the next or interpolate backwards
    interpolate_forward = True
    readptr = 0
    ## This is how much we read after the last identified point
    overread = 100*1024
    
    def __init__(self, fd):
        self.fd = fd
        ## This list is the file position coordinates of all the points,
        ## this is sorted.
        self.points = []

        ## This is the image_pos for each file_pos inserted.
        self.mapping = {}
        
        ## This is a comment attached to each file_pos identified.        
        self.comments = {}

    def del_point(self, file_pos):
        """ Remove the point at file_pos if it exists """
        idx = self.points.index(file_pos)
        try:
            del self.mapping[file_pos]
            self.points.pop(idx)
        except: pass

    def add_point(self, file_pos, image_pos, comment=None):
        """ Adds a new point to the mapping function. Points may be
        added in any order.
        """
        bisect.insort_left(self.points, file_pos)
        ## We already have this position in here - we need to decide
        ## if this is a better value. Its not a hard and fast rule,
        ## but generally if the current position is not too far away
        ## from the interpolated position, we dont want to update
        ## it. FIXME: Make this able to take multiple number of
        ## possibilties.
        if self.mapping.has_key(file_pos):
            expected, left = self.interpolate(file_pos-1)
            if abs(image_pos - expected) > abs(self.mapping[file_pos] - expected):
                return
            
        self.mapping[file_pos] = image_pos
        self.comments[file_pos] = comment
        
    def seek(self, offset, whence=0):
        if whence==0:
            self.readptr = offset
        elif whence==1:
            self.readptr += offset
        elif whence==2:
            self.readptr = self.points[-1]

    def interpolate(self, file_offset, direction_forward = None):
        """ Provides a tuple of (image_offset, valid length) for the
        file_offset provided. The valid length is the number of bytes
        until the next discontinuity.
        """
        if direction_forward == None:
            direction_forward = self.interpolate_forward
            
        ## We can't interpolate forward before the first point - must
        ## interpolate backwards.
        if file_offset < self.points[0]:
            direction_forward = False

        ## We can't interpolate backwards after the last point, we must
        ## interpolate forwards.
        elif file_offset > self.points[-1]:
            direction_forward = True

        ## If we are asked to interpolate an identified point its
        ## always the same as itself.
        if file_offset in self.points:
            return self.mapping[file_offset], 1

        elif direction_forward:
            l = bisect.bisect_right(self.points, file_offset)-1
            try:
                left = self.points[l+1] - file_offset
            except:
                left = self.overread
                
            #print "Forward interpolation %s %s %s" % (self.points[l],file_offset,self.points[l+1])
            return self.mapping[self.points[l]]+file_offset - self.points[l], left
        else:
            r = bisect.bisect_right(self.points, file_offset)
            #print "Reverse interpolation %s %s %s" % (self.points[r],file_offset, r)
            return self.mapping[self.points[r]] - (self.points[r] - file_offset), self.points[r] - file_offset

    def tell(self):
        return self.readptr

    def read(self, length):
        result = ''
        while length>0:
            try:
                m, left = self.interpolate(self.readptr)
                self.fd.seek(m,0)
            except:
                left = 1000

            want_to_read = min(left, length)

            assert(want_to_read > 0)
            data = self.fd.read(want_to_read)
            if not data: break

            self.readptr += min(left, length)
            result += data
            length -= len(data)

        return result

    def save_map(self, fd):
        """ Saves the map onto the fd 
        The format of the map file is as follows:

        - Comment lines start with #
        - First column, file offset
        - Second column, image offset
        - If a number of possible locations are present, there will be a
        number of image offsets for the same file offset.
        
        The idea is that different map files may be coalesced together by
        simply using 'cat'.
        """
        try:
            ## Does it have a write method?
            fd.write
        except AttributeError:
            ## It might be a string
            fd = open(fd, 'w')
        
        for x in self.points:
            fd.write("%s %s %s\n" % (x, self.mapping[x], self.comments[x]))

    def load_map(self, mapfile):
        """ Opens the mapfile and loads the points from it """
        fd = open(mapfile)
        for line in fd:
            line = line.strip()
            if line.startswith("#"): continue
            try:
                temp = re.split("[\t ]+", line, 2)
                off = temp[0]
                image_off = temp[1]
                try:
                    id = temp[2]
                except: id=''
                
                self.add_point(int(off), int(image_off), comment=id)
            except (ValueError,IndexError),e:
                pass

    def plot(self, title, filename=None, type='png'):
        max_size = self.points[-1] + self.overread
        p = os.popen("gnuplot", "w")
        if filename:
            p.write("set term %s\n" % type)
            p.write("set output \"%s\"\n" % filename)
        else:
            p.write("set term x11\n")
            
        p.write('pl "-" title "%s" w l, "-" title "." w p ps 5\n' % title)

        offset = 1
        while 1:
            x,length = self.interpolate(offset-1)
            p.write("%s %s\n" % (offset,x))

            x,length = self.interpolate(offset)
            p.write("%s %s\n" % (offset,x))
            offset += length

            if offset > self.points[-1] + self.overread: break
            
        p.write("e\n")

        print len(self.points)
        for i in self.points:
            if self.comments[i] != "Forced":
                p.write("%s %s\n" % (i,self.mapping[i]))

        p.write("e\n")
        if not filename:
            p.write("pause 10\n")
            
        p.flush()

        return p

    def get_point(self, name):
        for p in self.points:
            if self.comments[p] == name:
                return p

    def size(self):
        return self.get_point("EOF") or (self.points[-1] + self.overread)

    def extract(self, fd):
        """ Write the reconstructed file into fd """
        length = self.size()
        self.seek(0)
        while length > 0:
            data = self.read(min(1024*1024, length))
            if len(data)==0: break
            
            length -= len(data)
            fd.write(data)

        fd.close()

    def coalesce(self, c):
        """ Coalesce the current mapping function with the carver provided """
        for p in c.points:
            self.add_point(p, c.mapping[p], c.comments[p])

from optparse import OptionParser

class CarverFramework:
    """ This base class is the framework for building advanced
    carvers. This is basically just a way to provide the same kind of
    functionality to all carvers using a unified command line
    interface.
    """

    usage = """%prog [options] [image_file]"""

    def __init__(self):
        parser = OptionParser(usage=self.usage)
        parser.add_option('-i', '--index', default=None,
                          help = 'Index file to operate on')

        parser.add_option('-c', '--create', default=False, action="store_true",
                          help = 'Create a new index file')

        parser.add_option('-m', '--maps', default=False,  action="store_true",
                          help = 'Carve the index file by creating initial map files')

        parser.add_option('-P', '--print', default=False, action="store_true",
                          help = 'print the index hits')

        parser.add_option('-e', '--extract', default=None,
                          help = 'extract the zip file described in MAP into the file provided')

        parser.add_option('-M', '--map', default=None,
                          help = 'map file to read for analysis') 

        parser.add_option('-f', '--force', default=None,
                          help = "Force the map file given in --map and write as the specified filename")

        parser.add_option('-F', '--forced_map', default=None,
                          help = "Saved forced map into this filename")

        parser.add_option('-p', '--plot', default=False, action="store_true",
                          help = "Plot the mapping function specified using --map")

        parser.add_option('', '--plot_file', default=None,
                          help = "The file to save the plot to")

        parser.add_option('', '--plot_type', default="png",
                          help = "The file type to save the plot to (e.g. png, eps)")

        self.parser = parser

    cregexs = {}
    regexs = {}
    
    def build_index(self, index_file):
        hits = {}
        ## Compile the res
        for k,v in self.regexs.items():
            self.cregexs[k] = re.compile(v)

        BLOCK_SIZE = 4096

        p = pickle.Pickler(open(index_file,'w'))

        offset = 0
        fd = open(self.args[0],'r')
        while 1:
            data = fd.read(BLOCK_SIZE)
            if len(data)==0: break

            for k,v in self.cregexs.items():
                for m in v.finditer(data):
                    print "Found %s in %s" % (k, offset + m.start())
                    try:
                        hits[k].append(offset + m.start())
                    except KeyError:
                        hits[k] = [ offset + m.start(), ]

            offset += len(data)

        ## Serialise the hits into a file:
        p.dump(hits)
        return hits

    def generate_function(self, c):
        """ Generates test functions and uses a discriminator to
        evolve the carver object c into the best suitable one.

        This is an abstract method.
        """ 

    def build_maps(self):
        """ Generates a set of initial mapping functions.
        """

    def load_index(self, index_file):
        p = pickle.Unpickler(open(index_file,'r'))
        hits = p.load()

        return hits

    def print_index(self, index_file):
        print self.load_index(index_file)

    def parse(self):
        (self.options, self.args) = self.parser.parse_args()
        self.action_parse()

    def action_parse(self):
        """ This function is called to parse the command line options
        in a consistant way
        """
        if self.options.map:
            try:
                arg = open(self.args[0])
                print "Opening file %s" % self.args[0]
            except IndexError:
                arg = None

            c = Reassembler(arg)
            c.load_map(self.options.map)

            if self.options.force != None:
                self.generate_function(c)
                if not arg: raise RuntimeError("Image name not specified")
                
                print "Extracting into file %s" % self.options.force
                c.extract(open(self.options.force,'w'))
                
                if self.options.forced_map:
                    print "Saving map in %s" % self.options.forced_map
                    c.save_map(open(self.options.forced_map,'w'))

            elif self.options.extract:
                if not arg: raise RuntimeError("Image name not specified")
                print "Extracting into file %s" % self.options.extract
                c.extract(open(self.options.extract,'w'))

            elif self.options.plot:
                c.plot(os.path.basename(self.options.map), self.options.plot_file,
                       self.options.plot_type)

        elif self.options.create:
            if not self.options.index:
                raise RuntimeError("Need an index file to operate on.")

            self.build_index(self.options.index)

        elif self.options.maps:
            if not self.options.index:
                raise RuntimeError("Need an index file to operate on.")

            self.build_maps(self.options.index)

        elif getattr(self.options, "print"):
            if not self.options.index:
                raise RuntimeError("Need an index file to operate on.")

            self.print_index(self.options.index)

        else:
            raise RuntimeError("Nothing to do, use -h for help")


import unittest

class CarverTest(unittest.TestCase):
    filename = "Carver_Test_file"
    def setUp(self):
        """ Build a test file """
        text = ''.join([chr(x) for x in range(0,100) ]) * 100
        text = text[512:] + text[:512]
        fd = open(self.filename,'w')
        fd.write(text)
        fd.close()

    def test_Carver(self):
        """ Test that we can interpolate forward and backward around
        transition points
        """
        fd = open(self.filename)
        c = Reassembler(fd)

        c.add_point(512,0)
        c.add_point(0,512)

        print c.interpolate(50, True)
        print c.interpolate(520, True)

if __name__=='__main__':    
    unittest.main()
