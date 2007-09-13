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
import FileFormats.PDF as PDF
import re,sys
import pickle
import Carver
SECTOR_SIZE = 512

class JPEGDiscriminator:
    def __init__(self, reassembler, verbose=None):
        self.reassembler = reassembler

    def parse(self, length_to_test):
        """ Runs a JPEG parser over the carver until end_offset"""
        return 0

class PDFCarver(Carver.CarverFramework):
    ## These are the artifacts we index:
    regexs = {
        'HEADERS': '\xFF\xD8\xFF\xE1',
        }
    
if __name__=="__main__":
    c = PDFCarver()
    c.parse()
