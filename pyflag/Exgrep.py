# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Name:  $ $Date: 2004/09/05 15:19:05 $
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
""" An extracting Grep implementation

This module will extract files from an image by using their magic.
"""
import re,types
import pyflag.conf
import pyflag.logging as logging
config=pyflag.conf.ConfObject()

## This initialises the cut definition stack:
definitions=[]

cut={}
cut["Extension"]="jpg"
cut["StartRE"]="\\xff\\xd8....(JFIF|Exif)"
cut["MaxLength"]=1500000
cut["Comment"]="JPEG picture file type"
definitions.append(cut)

cut={}
cut["Extension"]="gif"
cut["StartRE"]="GIF8[79]a"
cut["MaxLength"]=50000
cut["Comment"]="GIF picture file type"
definitions.append(cut)

cut={}
cut["Extension"]="png"
cut["StartRE"]="\\x89PNG\\x0d\\x0a\\x1a\\x0a"
cut["EndRE"]="\\x45\\x4e\\x44\\xae\\x42\\x60\\x82"
cut["MaxLength"]=500000
cut["Comment"]="PNG picture file type"
definitions.append(cut)

#cut={}
#cut["Extension"]="tif"
#cut["StartRE"]="\\x49\\x49\\x2a\\x00\\x08"
#cut["MaxLength"]=1000000
#cut["Comment"]="TIF picture file type 1"
#definitions.append(cut)

cut={}
cut["Extension"]="tif"
cut["StartRE"]="\\x4d\\x4d\\x00\\x2a\\x00"
cut["MaxLength"]=1000000
cut["Comment"]="TIF picture file type 2"
definitions.append(cut)

cut={}
cut["Extension"]="doc"
cut["StartRE"]="\\xd0\\xcf\\x11\\xe0"
cut["MaxLength"]=500000
cut["Comment"]="MS Word document"
definitions.append(cut)

cut={}
cut["Extension"]="pdf"
cut["StartRE"]="%PDF-"
cut["EndRE"]=".%%EOF\\x0d"
cut["MaxLength"]=1000000
cut["Comment"]="Portable Document Format"
definitions.append(cut)

cut={}
cut["Extension"]="eps"
cut["StartRE"]="%!PS-Adobe"
cut["EndRE"]="end.%%.trailer"
cut["MaxLength"]=1000000
cut['Comment']='Encapsulated Postscript'
definitions.append(cut)

cut={}
cut["Extension"]="eps"
cut["StartRE"]="%!PS-Adobe"
cut["EndRE"]="%%EOF."
cut["MaxLength"]=1000000
cut['Comment']='Encapsulated Postscript'
definitions.append(cut)

cut={}
cut["Extension"]="ie_hist"
cut["StartRE"]="Client UrlCache"
cut["MaxLength"]=300000
cut["Comment"]="Internet Explorer URL cache"
definitions.append(cut)

cut={}
cut["Extension"]="url"
cut["StartRE"]="URL \\x03\\x00\\x00\\x00"
cut["MaxLength"]=384
cut["Comment"]="Internet Explorer URL cache"
definitions.append(cut)

cut={}
cut["Extension"]="url"
cut["StartRE"]="URL \\x02\\x00\\x00\\x00"
cut["MaxLength"]=256
cut["Comment"]="Internet Explorer URL cache"
definitions.append(cut)

cut={}
cut["Extension"]="mov"
cut["StartRE"]="....free.....mov"
cut["MaxLength"]=1000000
cut["Comment"]="Quicktime MOV format type 1"
definitions.append(cut)

cut={}
cut["Extension"]="mov"
cut["StartRE"]="MOVI"
cut["MaxLength"]=1000000
cut["Comment"]="Quicktime MOV format type 2"
definitions.append(cut)

cut={}
cut["Extension"]="mov"
cut["StartRE"]="....moov"
cut["MaxLength"]=1000000
cut["Comment"]="Quicktime MOV format type 3"
definitions.append(cut)

cut={}
cut["Extension"]="mov"
cut["StartRE"]="....mdat"
cut["MaxLength"]=1000000
cut["Comment"]="Quicktime MOV format type 4"
definitions.append(cut)

cut={}
cut["Extension"]="avi"
cut["StartRE"]="RIFF....AVI"
cut["MaxLength"]=1000000
cut["Comment"]="AVI video format"
definitions.append(cut)

cut={}
cut["Extension"]="wmv"
cut["StartRE"]="\\x30\\x26\\xb2\\x75\\x8e\\x66"
cut["MaxLength"]=1000000
cut["Comment"]="Windows movie file"
definitions.append(cut)

cut={}
cut["Extension"]="zip"
cut['StartRE']= "PK\\x03\\x04"
cut['EndRE']="PK\\x05\\x06.{18}"
cut["MaxLength"]=1000000
cut["Comment"]="Zip file"
definitions.append(cut)

cut={}
cut["Extension"]="pst"
cut['StartRE']="!BDNF"
cut['MaxLength'] = 10000000
cut['Comment'] = "Outlook PST File"
definitions.append(cut)

for i in definitions:
    i["CStartRE"]=re.compile(i["StartRE"])
    try:
        i["CEndRE"]=re.compile(i["EndRE"])
    except: pass

import pyflag.IO as IO

def process_string(string,extension=None):
    """ This is just like process except it operates on a string """
    for cut in definitions:
        offset=0
        if extension and cut['Extension'] not in extension: continue
        while 1:
            match=cut['CStartRE'].search(string,offset)
            if match:
                offset=match.start()
                length=cut['MaxLength']
                ## If there is an end RE, we try to read the entire length in, and then look for the end to we can adjust the length acurately. This is essential for certain file types which do not tolerate garbage at the end of the file, e.g. pdfs.
                if cut.has_key('CEndRE'):
                    end_match=cut['CEndRE'].search(string,offset)
                    if end_match:
                        length=end_match.end()-offset

                yield({'offset':offset,'length':length,'type':cut['Extension']})
                offset+=1
            else:
                break
    
def process(case,subsys,extension=None):
    """ A generator to produce all the recoverable files within the io object identified by identifier

    @arg subsys: Either an IO object to use, or the string name of an io object that will be opened using IO.open().
    @arg extension: A list of extensions we would like to see
    """
    if type(subsys)==types.StringType:
        io=IO.open(case,subsys)
    else:
        io=subsys
        
    blocksize=1024*1024*10
    windowsize=100
    count=0
    bytes_read=0
    window=''
    while(1):
        ## This implements a sliding window of window bytes to ensure
        ## we do not miss a signature that was split across blocksize:
        try:
            data=io.read(blocksize)
            if not len(data): break
        except IOError:
            break
        
        f=window+data
        bytes_read+=len(data)
        logging.log(logging.INFO,"Processed %u Mb" % (bytes_read/1024/1024))
        for cut in definitions:
            if extension and cut['Extension'] not in extension: continue
            pos=0
            while pos<blocksize:
                match=cut['CStartRE'].search(f,pos)
                if match:
                    offset=match.start()+count-len(window)
                    length=cut['MaxLength']
                    ## If there is an end RE, we try to read the entire length in, and then look for the end to we can adjust the length acurately. This is essential for certain file types which do not tolerate garbage at the end of the file, e.g. pdfs.
                    if cut.has_key('CEndRE'):
                        tell=io.tell()
                        io.seek(offset)
                        file_data=io.read(length)
                        io.seek(tell)

                        end_match=cut['CEndRE'].search(file_data,0)
                        if end_match:
                            length=end_match.end()
                  
                    yield({'offset':offset,'length':length,'type':cut['Extension']})
                    pos=match.start()+1
                else:
                    pos=blocksize

        window=f[-windowsize:]
        count+=blocksize
        
    io.close()
