#!/usr/bin/python
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
Zip File Carving
================

Zip files are described in the application note:
http://www.pkware.com/documents/casestudies/APPNOTE.TXT

Although the application note discusses a Zip64 standard with
different format, it seems to suggest that much of that standard is
covered by patent claims. This means that in practice its uncommon to
see and most zip files use the old structures. We only support the old
structures here. We also do not support multi-disk archives since they
very uncommon these days.

The zip file consists of a sequence of compressed files preceeded by a
file header. These are then followed by a central directory (CD). The
CD is a sequence of CDFileHeader structs each of which describes a
file in the Zip file. This sequence is the followed by an
EndCentralDirectory struct. (For a full description of these structs,
see Zip.py)

In terms of carving, there are a number of good candidates for
identified points:

1) The EndCentralDirectory struct has an offset_of_cd ULONG indicating
the offset of the CD. We can determine if this is correct by using the
CD signature (0x02014b50).

2) The CD is a sequence of CDFileHeader structs, each of which has
relative_offset_local_header ULONG which points to the start of the
FileHeader struct. We also have in the CDFileHeader struct the
filename of the compressed file. Note that the filename also appears
in the FileHeader and depending on the zip program used to generate
the file, one of these locations may be empty. Sometimes, however,
(e.g. the linux zip program), both the locations contain the same
filename. This may be used to assist in confirming the identified
point.

3) FileHeader structs contain the compr_size field. We expect to see
the next FileHeader struct right after the compressed file. This is
not needed usually as the same identified point should be recovered
from the CD (if its a normal - untampered zip file) but if we need to
reconstruct the file without a CD this could be useful.
"""
from format import Buffer
import FileFormats.Zip as Zip
import re,sys,binascii
import pickle, zlib, os, re
import Carver

zip_header_re = re.compile("PK[\x01\x03\x05][\x02\x04\x06]")

SECTOR_SIZE = 512

class ZipDiscriminator:
    """ We test the provided carved zip file for errors by reading it
    sequentially
    """
    def __init__(self, reassembler):
        self.r = reassembler

        ## Try to load the central directory if possible: This may
        ## fail if the cd is fragmented. FIXME: be able to handle
        ## fragmentation at the CD.
        cd_x = self.r.get_point("Central_Directory")
        self.cds = []
        if cd_x:
            b = Buffer(self.r)[cd_x:]
            while 1:
                try:
                    cd = Zip.CDFileHeader(b)
                except RuntimeError,e:
                    print "Finished reading CD (%s items)" % len(self.cds)
                    break

                self.cds.append(cd)
                b = b[cd.size():]

    def decode_file(self, b, length_to_test):
        """ Attempts to decode and verify a ZipFileHeader """
        fh = Zip.ZipFileHeader(b)
        #print "Zip File Header @ offset %s (name %s) " % (b.offset, fh['zip_path'])

        ## The following is necessary because some Zip writers do not
        ## write the same information in both the ZipFileHeader and
        ## CDFileHeader - FIXME: what do we do if the information is
        ## actually different but set? (This is a common way for
        ## malware to break email filtering or virus scanners ala zip
        ## bombs).
        compression_method = fh['compression_method'].get_value()
        compressed_size = fh['compr_size'].get_value()
        uncompr_size = fh['uncompr_size'].get_value()
        crc32 = fh['crc32'].get_value()

        for cd in self.cds:
            if cd['filename']==fh['zip_path']:
                ## Found the CD entry for our file, if any of the
                ## above parameters are not set in the ZipFileHeader,
                ## try to get them from the CD:
                if not compression_method:
                    compression_method = cd['compression'].get_value()

                if not compressed_size:
                    compressed_size = cd['compressed_size'].get_value()

                if not uncompr_size:
                    uncompr_size = cd['uncompr_size'].get_value()

                if not crc32:
                    crc32 = cd['crc-32'].get_value()

        ## Deflate:
        if compression_method==8:
            dc = zlib.decompressobj(-15)
            crc = 0

            self.offset = b.offset + fh.size()
            self.r.seek(self.offset)

            total = 0

            to_read = compressed_size

            while to_read > 0:
                cdata = self.r.read(min(SECTOR_SIZE,to_read))
                #print "Read %s" % len(cdata)
                to_read -= len(cdata)
                data = dc.decompress(cdata)
                total += len(data)
                self.offset += len(cdata)
                crc = binascii.crc32(data, crc)

                ## Only test as much as was asked
                if self.offset > length_to_test: return length_to_test

            ## Finalise the data:
            ex = dc.decompress('Z') + dc.flush()
            total += len(ex)
            crc = binascii.crc32(ex, crc)

            if total != uncompr_size:
                print "Total decompressed data: %s (%s)" % (total, uncompr_size)
                raise IOError("Decompressed file does not have the expected length")

            if crc<0: crc = crc + (1 << 32)
            if crc != crc32:
                print "CRC is %d %s" % (crc, crc32)
                raise IOError("CRC does not match")
            
        else:
            print "Unable to verify compression_method %s - not implemented, skipping file" % compression_method

        ## Sometimes there is some padding before the next file is
        ## written. We try to account for this if possible by scanning
        ## ahead a little bit. This occurs if the file has a data
        ## descriptor record. We ignore this record because its values
        ## are usually present in the CD anyway.
        total_size = fh.size() + compressed_size
        
        data = self.r.read(SECTOR_SIZE)
        m = zip_header_re.search(data)
        if m:
            total_size += m.start()

        #print fh
        return total_size

    def decode_cd_file(self, b, length_to_test):
        cd = Zip.CDFileHeader(b)
        print "Found CD Header: %s" % cd['filename']

        return cd.size()

    def decode_ecd_header(self, b, length_to_test):
        ecd = Zip.EndCentralDirectory(b)

        print "Found ECD %s" % ecd
        return ecd.size()
    
    def parse(self, length_to_test):
        """
        Reads the reassembled zip file from the start and detect errors.

        Returns the offset where the last error occurs
        """
        b = Buffer(fd = self.r)
        self.offset = 0

        ## Try to find the next ZipFileHeader. We allow some padding
        ## between archived files:
        ## Is the structure a ZipFileHeader?
        while 1:
            if b.offset >= length_to_test:
                return
            
            try:
                length = self.decode_file(b, length_to_test)
                b = b[length:]
            except RuntimeError, e:
                try:
                    length = self.decode_cd_file(b, length_to_test)
                    b=b[length:]
                except RuntimeError:
                    length = self.decode_ecd_header(b, length_to_test)
                    ## If we found the ecd we can quit:
                    return b.offset+length
                
            except Exception,e:
                print "Error occured after parsing %s bytes (%s)" % (self.offset,e)
                raise

class ZipCarver(Carver.CarverFramework):
    ## For now use regex - later convert to pyflag indexs:
    regexs = {
        'ZipFileHeader': 'PK\x03\x04',
        'EndCentralDirectory': 'PK\x05\x06',
        'CDFileHeader': 'PK\x01\x02'
        }

    def build_maps(self, index_file):
        hits = self.load_index(index_file)
        
        image_fd = open(self.args[0],'r')
        zip_files = {}

        for ecd_offset in hits['EndCentralDirectory']:
            ## Each EndCentralDirectory represents a new Zip file
            r = Carver.Reassembler(None)
            b = Buffer(image_fd)[ecd_offset:]
            ecd = Zip.EndCentralDirectory(b)
            print "End Central Directory at offset %s:" % (ecd_offset,)

            ## Find the CD:
            offset_of_cd = ecd['offset_of_cd'].get_value()

            ## Check if the cd is where we think it should be:
            possibles = []
            for x in hits['CDFileHeader']:
                if x == ecd_offset - ecd['size_of_cd'].get_value():
                    ## No fragmentation in CD:
                    print "No fragmentation in Central Directory at offset %s discovered... good!" % x
                    possibles = [ x,]
                    break

                if x % 512 == offset_of_cd % 512:
                    print "Possible Central Directory Starts at %s" % x
                    possibles.append(x)

            ## FIXME: this needs to be made to estimate the most similar
            ## possibility - we really have very little to go on here -
            ## how can we distinguish between two different CDs that occur
            ## in the same spot? I dont think its very likely in reality
            ## because the CD will be at the end of the zip file which
            ## will be of varying sizes.

            ## We probably should prefer the CD found at image offset
            ## of ecd - ecd['size_of_cd'] which will be the case if
            ## the CD is not fragmented.

            ## For now we go with the first possibility:
            cd_image_offset = possibles[0]

            ## Identify the central directory:
            r.add_point(offset_of_cd, cd_image_offset, "Central_Directory")

            ## We can calculate the offset of ecd here:
            r.add_point(offset_of_cd + ecd['size_of_cd'].get_value(),
                        ecd_offset, "End_Central_Directory")

            ## The file end - this is used to stop the carver:
            r.add_point(offset_of_cd + ecd['size_of_cd'].get_value() + ecd.size(),
                                         ecd_offset + ecd.size(), "EOF")

            ## Read all entries in the CD and try to locate their
            ## corresponding ZipFileHeaders:
            for i in range(ecd['total_entries_in_cd_on_disk'].get_value()):
                b = Buffer(image_fd)[cd_image_offset:]
                cd = Zip.CDFileHeader(b)

                ## Now try to find the ZipFileHeader for this cd entry:
                fh_offset = cd['relative_offset_local_header'].get_value()

                for fh_image_offset in hits['ZipFileHeader']:
                    ## Apply the modulo rule:
                    if fh_image_offset % 512 == fh_offset % 512:
                        print "Possible File header at image offset %s" % fh_image_offset

                        b = Buffer(image_fd)[fh_image_offset:]
                        try:
                            fh = Zip.ZipFileHeader(b)
                        except:
                            print "Oops - no File Header here... continuing"
                            continue

                        ## Is it the file we expect?
                        path = fh['zip_path'].get_value()
                        expected_path = cd['filename'].get_value()

                        ## Check the paths:
                        if path and expected_path and path != expected_path:
                            print "This ZipFileHeader is for %s, while we wanted %s" % (path,expected_path)
                            continue

                        ## Check the expected lengths with the central directory:
                        cd_compr_size = cd['compressed_size'].get_value()
                        cd_uncompr_size = cd['uncompr_size'].get_value()

                        fh_comr_size = fh['compr_size'].get_value()
                        fh_uncomr_size = fh['uncompr_size'].get_value()

                        if cd_compr_size and fh_comr_size and cd_compr_size!=fh_comr_size:
                            print "Compressed size does not match (%s - expected %s)" % (cd_compr_size, fh_comr_size)
                            continue

                        if cd_uncompr_size and fh_uncomr_size and cd_uncompr_size!=fh_uncomr_size:
                            print "Uncompressed size does not match (%s - expected %s)" % (
                                cd_uncompr_size, fh_uncomr_size)
                            continue

                        print "Will use Zip File Header at %s." % (fh_image_offset)

                        ## Identify point:
                        r.add_point(fh_offset, fh_image_offset, "File_%s" % path)

                ## Progress to the next file in the archive:
                cd_image_offset += cd.size()

            r.save_map("%s.map" % ecd_offset)

    def generate_function(self, c):
        """ Generates a series of functions and uses the ZipDiscriminator
        to guide the generation process.

        We alter the carver object as we process it. We return the total
        final error count.
        """
        ## We check each sector in turn until we find ambiguous sectors,
        ## then brute force them using the discriminator:
        d = ZipDiscriminator(c)
        for x in range(0,c.size(), SECTOR_SIZE):
            y_forward, length = c.interpolate(x, True)
            y_reverse, length = c.interpolate(x, False)

            ## Its not possible to interpolate before the start of the
            ## image:
            if y_reverse<0: continue

            ## Is this an ambigous point?
            if y_forward != y_reverse:
                print "Ambiguous point found at offset %s: forward=%s vs reverse=%s..." % (x, y_forward, y_reverse)
                ## Disambiguate the function by adding a new point:
                c.add_point(x, y_reverse, comment = "Forced")

                ## Test the file up to the last point:
                try:
                    d.parse(x + length)
                except Exception,e:
                    print "Errors detected, point removed.(%s)" % e
                    ## Error occured, move the point over by one:
                    c.del_point(x)
                    continue

                print "Match found at offset %s" % x

if __name__=='__main__':
    carver = ZipCarver()
    ## Work out what we need to do:
    carver.parse()
