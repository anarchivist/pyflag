
""" This plugin provides reports for viewing of files in special
ways. For example we are able to display properly sanitised html with
matched images etc.
"""
# Michael Cohen <scudette@users.sourceforge.net>
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

import pyflag.Reports as Reports
import pyflag.Registry as Registry
import pyflag.DB as DB
import sys,re,string
import StringIO
import re,os.path,cgi, textwrap
from FlagFramework import query_type,normpath, Curry
import pyflag.FileSystem as FileSystem
import FileFormats.HTML as HTML
import pyflag.Magic as Magic

## FIXME: This needs to be pluggable too
class ViewFile(Reports.report):
    """
    View HTML
    ---------

    This report allows users to view a sanitised version of the inode.

    We filter the inode from potentially malicious javascript and only
    allow certain html tags. This ensures that the investigators
    browser does not connect back to the malicious site or run
    potentially malicious code.

    We try to fill in images from our local cache. This is an
    approximation only and we guess the right image based on the
    filename.
    """
    
    name = "View File"
    family = "Network Forensics"
    hidden = True

    def display(self,query,result):
        result.decoration = 'naked'
        self.case = query['case']

        fsfd = FileSystem.DBFS( self.case)
        if query.has_key('inode_id'):
            fd = fsfd.open(inode_id=query['inode_id'])
            inode = fd.inode
            inode_id = query['inode_id']
        elif query.has_key("sundry_id"):
            fd = FileSystem.File(query['case'], None, "HTTP%s" % query['sundry_id'])
            inode_id = -1
        else:
            fd = fsfd.open(inode=query['inode'])
            inode_id = fd.lookup_id()

        content_type = self.guess_content_type(fd, query, inode_id)
        result.generator.content_type = content_type

        ## Now establish the dispatcher for it
        for k,v in self.dispatcher.items():
            if k.search(content_type):
                return v(self,fd, result)

        return self.default_handler(fd, result)

    def guess_content_type(self, fd, query, inode_id):
        try:
            if query['hint']: content_type=query['hint']
        except KeyError:      
            m = Magic.MagicResolver()
            type, content_type = m.find_inode_magic(self.case, inode_id)

        return content_type
    
    def default_handler(self, fd, ui):
        ui.generator.content_type = "text/plain"

        def default_generator():
            size=0
            ## Cap the maximum text size so we dont kill the browser:
            while size<100000:
                data = fd.read(10000)
                if not data: break

                a = []
                for c in data:
                    if c.isspace() or c.isalnum() \
                       or c in '\r\n!@#$%^&*()_+-=[]\{}|[]\\;\':\",./<>?':
                        a.append(c)

                size += len(data)
                for line in ''.join(a).splitlines():
                    yield textwrap.fill(line)+"\n"
                
        ui.generator.generator = default_generator()

    def image_handler(self,fd, ui):
        def generator():
            while 1:
                data = fd.read(1000000)
                if not data: break

                yield data

        ui.generator.generator = generator()
        
    def html_handler(self,fd, ui):
        """ We sanitise the html here """
        def generator():
            parser = HTML.HTMLParser(tag_class = Curry(HTML.ResolvingHTMLTag,
                                                       inode_id = fd.lookup_id(),
                                                       case = self.case))
            #parser = HTML.HTMLParser(tag_class = HTML.Tag)
            data = fd.read(1000000)
            parser.feed(data)
            parser.close()
            
            yield parser.root.innerHTML()

        ui.generator.generator = generator()
        
    def zip_handler(self, fd, ui):
        ## Show the file listing in the zip file:
        import zipfile
        z = zipfile.ZipFile(fd,'r')
        ## This is a bit of cheating...
        ui.start_table(**{'class':'PyFlagTable'})
        ui.row("File Name", "Modified    ", "Size", **{'class':'hilight'})
        for zinfo in z.filelist:
        	## FIXME: This is evidence local time.
        	## should we bother to convert to case local?
            date = "%d-%02d-%02d %02d:%02d:%02d" % zinfo.date_time
            ui.row(zinfo.filename, date, zinfo.file_size)

    def css_handler(self, fd, ui):
        def generator():
            data = fd.read(100000)
            tag = HTML.ResolvingHTMLTag(inode_id = fd.lookup_id(), case =self.case)
            filtered = tag.css_filter(data)
            yield filtered
            
        ui.generator.generator = generator()
        
    def mpeg3_handler(self, fd, ui):
        ## TODO: run down the ID3 tags here
        
        ## Convert to mp3 at 44100 samples in order to normalise
        ## the input
        def play_file(fd):
            while 1:
                data = fd.read(64*1024)
                if not data: break

                yield data
                
        ui.sound_control("Listen to file", play_file(fd))

    def flv_handler(self, fd, ui):
        
        def play_file(fd):
            while 1:
                data = fd.read(64*1024)
                if not data: break

                yield data
                
        ui.video_control("%s" % fd.inode, play_file(fd))

    dispatcher = { re.compile("text/html"): html_handler,
                   re.compile("image.*"): image_handler,
                   re.compile("application/x-zip"): zip_handler,
                   re.compile("audio/mpeg"): mpeg3_handler,
                   re.compile("application/x-flv"): flv_handler,
                   re.compile("css"): css_handler,
                   }

import pyflag.Magic as Magic
class FLVMagic(Magic.Magic):
    """ Detect Macromedia Flash Files """
    type = "Macromedia Flash Video"
    mime = "application/x-flv"

    regex_rules = [( "FLV", (0,1) )]

    samples = [
        ( 100, "FLV xxxx" )
        ]
