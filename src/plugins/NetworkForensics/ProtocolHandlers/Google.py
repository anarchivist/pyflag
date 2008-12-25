# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
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
""" This module is designed to extract information from google
searches. This is needed now as google image search is ajax based.
"""
import Gmail
from FileFormats.HTML import decode_entity, HTMLParser, url_unquote
import pyflag.DB as DB
import pyflag.pyflaglog as pyflaglog
import re
import pyflag.CacheManager as CacheManager

class GoogleImageScanner(Gmail.GmailScanner):
    """ Detect Google image searches and clean up the html """
    
    class Scan(Gmail.GmailScanner.Scan):
        def boring(self, metadata, data=''):
            self.get_url(metadata)

            try:
                if metadata['host'].startswith("images.google.com"):
                    self.parser = HTMLParser(verbose=0)
                    return False
            except: pass
            
            return True

        def external_process(self, fd):
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for Google image search processing" % self.fd.inode)
            self.process_image_list()
            #print self.parser.root.tree()

        def process_image_list(self):
            ## Pull out all the scripts and match the regex:
            result = ''
            image_text = ''
            text_text = ''
            count = 0
            total_count = 0
            regex = re.compile('dyn.Img(\(.+?\));')
            for script in self.parser.root.search("script"):
                data = script.innerHTML()
                for m in regex.finditer(data):
                    row = eval(m.group(1),{},{})
                    image_text += '''\n<td id="tDataImage%s" nowrap="" width="16%%" valign="bottom" align="center" style="padding-top: 0px;">
                    <a href="%s">
                    <img height="%s" width="%s" src="%s?q=tbn:%s%s" style="border: 1px solid ;"/>
                    </a>
                    </td>\n''' % (total_count, row[0], row[5], row[4], row[14], row[2], row[3])

                    text_text += '''<td id="tDataText%s" width="16%%" valign="top" align="center">
                    <font face="arial,sans-serif" size="-1">
                    %s
                    <br/>
                    %s - %s
                    <br/>
                    <font color="#008000">%s</font>
                    </font>
                    </td>''' % (total_count, row[6], row[9], row[10], row[11])
                    
                    count += 1
                    total_count += 1
                    
                    if count >= 5:
                        result += "<tr>%s</tr>\n<tr>%s</tr>\n" % (image_text, text_text)
                        image_text = ''
                        text_text = ''
                        count = 0

            if image_text:
                result += "<tr>%s</tr>\n<tr>%s</tr>\n" % (image_text, text_text)

            if result:
                ## Prepare the new page
                tag = self.parser.root.find("div", {"id":"ImgContent"})
                if tag:
                    result = "<table>%s</table>" % result
                    tag.add_child(result)

                inode_id = self.ddfs.VFSCreate(self.inode,
                                               "xGimage",
                                               "Gimage")

                ## Update the http and http_parameters table to point
                ## to this new Inode instead:
                dbh = DB.DBO(self.case)
                dbh.update('http_parameters',
                           where = DB.expand("inode_id=%r",self.inode_id),
                           inode_id = inode_id)

                dbh.update('http',
                           where = DB.expand("inode_id=%r",self.inode_id),
                           inode_id = inode_id)

                page = self.parser.root.innerHTML()
                page = page.encode("utf","ignore")
                CacheManager.MANAGER.create_cache_from_data(self.case,
                                                            "%s|xGimage" % self.inode,
                                                            page,
                                                            inode_id=inode_id)
                

## Unit tests:
import pyflag.pyflagsh as pyflagsh
import pyflag.tests as tests

class GoogleImageTests(tests.ScannerTest):
    """ Tests Google Image Scanner """
    test_case = "PyFlagTestCase"
    test_file = 'google_image.pcap'
    subsystem = "Standard"
    fstype = "PCAP Filesystem"

    def test01GmailScanner(self):
        """ Test Google Image Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "GoogleImageScanner",
                                   ])                   ## List of Scanners
