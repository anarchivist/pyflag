#!/usr/bin/python
# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
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
    row_height = 0
    start_sector = 0
    
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

    def estimate(self, x_old, y_old, d):
        """ Estimates the average integral from x_old,y_old to the current frame bound """
        width, height, components = d.dimensions()
        x,y = d.find_frame_bounds()

        ## Row height is the height in pixels of each DCT macroblock -
        ## it must be a multiple of 8 pixels
        if self.row_height==0 and y != 0:
            self.row_height = (y // 8) * 8
            
        print "Row height is %s" % self.row_height

        if self.row_height==0: return 0
        
        y_min = y - self.row_height
        print "Will try to estimate from %s,%s to %s,%s" % (x_old, y_old, x, y_min)
            
        e = 0
        length = 1
        for tmp_y in range(y_old, y_min+1, self.row_height):
            if tmp_y==y_old:
                if y_min == y_old:
                    e += d.estimate(tmp_y, x_old, x)
                    length += x-x_old
                else:
                    e += d.estimate(tmp_y, x_old, width)
                    length += width-x_old
            elif tmp_y==y_min:
                e += d.estimate(tmp_y, 0, x)
                length += x
            else:
                e += d.estimate(tmp_y, 0, width)
                length += width

        return e
#        return e / length
    
    def find_discontinuity(self, c):
        c.overread = 1000 * 1024
        i = 1
        while not self.row_height:
            d = jpeg.decoder(c)
            d.decode(i)
            self.estimate(0,0,d)
            i+=1

        d = jpeg.decoder(c)
        d.decode(self.start_sector-1)    
        old_x, old_y = d.find_frame_bounds()

        print "Discontinuity detected after %s" % d.last_good_sector()
##        for sector in range(d.last_good_sector()-10, d.last_good_sector()+30):
        sector = self.start_sector
        while 1:
            sector += 1 
            d = jpeg.decoder(c)
            print "Trying to decompress %s" % sector
            d.decode(sector)
            x, y = d.find_frame_bounds()
            print "Frame bounded at %s, %s, %s" % (x,y, y-self.row_height)

            estimate = self.estimate(old_x, old_y, d)

#            x,y, y_min = d.find_frame_bounds()


#            if y==height: return sector, width, height

#            if y_min > old_y_min:
#                e1 = d.estimate(old_y_min, old_x, width)
#                e2 = d.estimate(y_min, 0, x)
#                estimate = (e1+e2)/2
#            else:
#                estimate = d.estimate(old_y_min, old_x, x)

            print "Sector %s Integral calculated %s" % (sector, estimate)

            if self.options.verbose > 1:
                d.save(open("output_test%03u.ppm" % sector,'w'))
                
            if estimate > self.options.max_estimate:
                print "Estimate too large - returning sector %s" % (sector-2)
                return sector-2

            if d.warnings()>0:
                print "Warnings are %s" % d.warnings()
                return sector-2
            
            print "Last sector %s" % d.last_sector()
            if d.last_sector() < sector:
                return d.last_sector()

            old_x = x
            old_y = y - self.row_height

    def generate_function(self, c):
        ## Find the next discontinuity:
        s_old = self.find_discontinuity(c)

        d = jpeg.decoder(c)
        d.decode(s_old)
        x_old, y = d.find_frame_bounds()
        y_old = y - self.row_height
        ## This is the image coordinate of the discontinuity:
        image_offset, left = c.interpolate(s_old * 512)

        ## Try to fuzz the discontiuity
        for image_offset_to in range(image_offset, image_offset + 10 * 512, 512):
            for s_from in range(s_old, s_old + 2):
                ## Enforce the projection rule
                if s_from * 512 > image_offset_to: continue

                c.add_point(s_from * 512, image_offset_to , "Test_point")
                d = jpeg.decoder(c)
                print "Will decode up to %s" % ((s_from + 5) * 512)
                d.decode(s_from + 10)
                e = self.estimate(x_old, y_old, d)
                print "Estimate %s-%s %s" % (s_from, image_offset_to / 512, e)
                d.save(open("estimate_%s-%s.ppm" % (s_from, image_offset_to / 512),'w'))
                c.del_point(s_from * 512)

if __name__=="__main__":
    c = JPEGCarver()
    c.parse()
