#!/usr/bin/env python
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

""" This is a script that brute forces the map across discontinuities
to try and recover the more accurate discontinuities possible.
"""

import Carver
import sys
import FileFormats.PDF as PDF

def check_errors(p, end_offset):
    """ Runs a PDF parser over the carver until end_offset"""
    ## Rewind back to a convenient spot:
    p.restore_state()

    ## We are only willing to tolerate a small number of errors
    while p.processed < end_offset and p.error < 10:
        p.next_token()
            
    ## Return the error count
    return p.error
from optparse import OptionParser

if __name__=='__main__':
    parser = OptionParser(usage="""%prog """)
    parser.add_option('-m', '--map', default=None,
                      help = 'Approximate map file to operate on (Mandatory)')

    parser.add_option('-r', '--reconstructed', default=None,
                      help = 'The file to write the reconstructed map onto (optional)')

    parser.add_option('-o', '--output', default=None,
                      help = 'The reconstituted PDF file to write (Mandatory)')
    
    parser.add_option('-v', '--verbose', default=0, type='int',
                      help = 'Verbosity level')
    
    parser.add_option('-s', '--slow', default=False, action="store_true",
                      help = 'Turn off state recovery. This makes brute forcing very slow because PDF needs to be parsed from the begining for each attempt. It might be needed if the PDF state cant be saved reliably')

    (options, args) = parser.parse_args()

    if not options.output or not options.map:
        print "Error using tool - try -h for help"
        sys.exit(1)

    if len(args)!=1:
        print "You must specify the name of the image"
        sys.exit(1)
        
    c= Carver.Reassembler(open(args[0]))
    p = PDF.PDFParser(c)
    p.verbose = options.verbose

    ## Load the map file
    c.load_map(options.map)
    
    for i in range(0,c.points[-1]/512 + 10):
        y_forward, left = c.interpolate(i*512, True)
        y_reverse, left = c.interpolate(i*512, False)

        ## This is an ambiguous point:
        if y_forward != y_reverse:
            sys.stderr.write("Sector %s is ambiguous - testing\n" % (i))

            ## Write the file out:
            #print "Adding a point at %s,%s" % (i*512, y_reverse)
            c.add_point(i*512, y_reverse)

            ## Check a reasonable way after the next identified point
            ## (This might need some work)
            until_offset = left + i*512 + 4000

            print "Checking until %s" % (until_offset)

            if options.slow:
                c.seek(0)
                p = PDF.PDFParser(c)
                p.verbose = options.verbose

            ## Check the errors:
            error_count = check_errors(p, until_offset)
            if error_count == 0:
                sys.stderr.write("Found a hit at %s\n" % i)
            else:
                ## No thats not the right point.
                c.del_point(i*512)

            print "Error count is %s" % error_count

    ## Now document the new map file:
    if options.reconstructed:
        sys.stderr.write("Writing reconstructed file: %s\n" % options.reconstructed)
        fd = open(options.reconstructed,'w')
        for x in c.points:
            fd.write("%s %s\n" % (x, c.mapping[x]))

        fd.close()
    
    ## Now save the file out - We basically parse the file completely
    ## until we get a RESET_STATE token (goes with the EOF tag) which
    ## occurs after all identified points. This accomodates for the
    ## multiple XREF tables within the file:
    sys.stderr.write("Writing file: %s\n" % options.output)
    fd = open(options.output,'w')
    c.seek(0)
    p = PDF.PDFParser(c)
    p.verbose = options.verbose
    
    while 1:
        token = p.next_token()
        fd.write(p.processed_buffer)
        p.processed_buffer = ''
        
        if token == 'RESET_STATE' and p.processed > c.points[-1]:
            break

    sys.stderr.write("Total reconstructed file error count: %s\n" % p.error)
    fd.close()
