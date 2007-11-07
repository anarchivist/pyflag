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
JPEG File carving
=================

"""

from optparse import OptionParser
import re,sys
import pickle
import Carver
SECTOR_SIZE = 512
import jpeg

class JPEGDiscriminator:
    def __init__(self, reassembler, verbose=None):
        self.reassembler = reassembler

    def parse(self, length_to_test):
        """ Runs a JPEG parser over the carver until end_offset"""
        return 0

class JPEGCarver(Carver.CarverFramework):
    ## These are the artifacts we index:
    regexs = {
        'HEADERS': r'\xFF\xD8....(JFIF|EXIF)',
        }

    def build_maps(self, index_file):
        hits = self.load_index(index_file)

        for header in hits['HEADERS']:
            c = Carver.Reassembler(None)
            c.add_point(0, header, "File Header")
            c.save_map(open("%s.map" % header, 'w'))

    def __init__(self):
        ## Add a couple of extra command line args:
        Carver.CarverFramework.__init__(self)
        self.parser.add_option('-1', '--max_estimate', default=1000, type='int',
                               help = 'Maximum level of the estimate where an error is detected')

        self.parser.add_option('-s', '--slow', default=False, action='store_true',
                               help = 'Disable state saving optimisations (Not usually needed)')

        self.parser.add_option('-v', '--verbose', default=0, type='int',
                               help = "Verbosity")

    def find_discontinuity(self, c):
        d = jpeg.decoder(c)        
        start = d.decode() or 0

        old_x = 0
        old_y = 0
        width, height, components = d.dimensions()

        print "Discontinuity detected after %s" % d.last_good_sector()
        for sector in range(d.last_good_sector()-10, d.last_good_sector()+30):
            d = jpeg.decoder(c)
            print "Trying to decompress %s" % sector
            d.decode(sector)

            x,y = d.find_frame_bounds()
            print "Frame bounded at %s, %s" % (x,y)

            if old_y==y:
                estimate = d.estimate(y, old_x, x)
                print "Integral calculated %s, %s - %s, value %s" % (y, old_x, x,estimate)
            else:
                e1 = d.estimate(old_y, old_x, width)
                e2 = d.estimate(y, 0, x)
                estimate = (e1+e2)/2
                print "Integral calculated %s, %s - %s (%s), %s, %s - %s (%s) (%s)" % (old_y, old_x, width, e1,
                                                                                       y, 0, x, e2, estimate)

            if self.options.verbose > 1:
                d.save(open("output_test%s.ppm" % sector,'w'))
                
            if estimate > self.options.max_estimate:
                print "Estimate too large - returning sector %s" % (sector-2)
                return sector-2, x, y

            if d.warnings()>0:
                return sector-2, x, y
            
            print "Last sector %s" % d.last_sector()
            if d.last_sector() < sector:
                return d.last_sector(), x, y

            old_x = x
            old_y = y

    def generate_function(self, c):
        d = JPEGDiscriminator(c, self.options.verbose)
        d.slow = self.options.slow

        ## Find the next discontinuity:
        s, x, y = self.find_discontinuity(c)

        for 
        
    
if __name__=="__main__":
    c = JPEGCarver()
    c.parse()
