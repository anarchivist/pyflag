# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.85 Date: Fri Dec 28 16:12:30 EST 2007$
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
""" This module will retrieve the email messages from Yahoo mail """
import pyflag.DB as DB
import LiveCom
import pyflag.pyflaglog as pyflaglog
import pyflag.Scanner as Scanner
import re
import FileFormats.HTML as HTML
import pyflag.TableObj as TableObj
import pyflag.FileSystem as FileSystem
import pyflag.FlagFramework as FlagFramework

class YahooMailScan(LiveCom.HotmailScanner):
    """ Detect YahooMail Sessions """

    class Scan(LiveCom.HotmailScanner.Scan):
        service = "Yahoo"
        
        def boring(self, metadata, data=''):
            ## We dont think its boring if our base class does not:
            ## And the data contains '<title>\s+Yahoo! Mail' in the top.
            if not Scanner.StoreAndScanType.boring(self, metadata, data=''):
                m=re.search("<title>\s+Yahoo! Mail\s+-\s+([^< ]+)", data)
                if m:
                    self.username = m.group(1)
                    ## Make a new parser:
                    if not self.parser:
                        self.parser =  HTML.HTMLParser(verbose=0)
                    return False

            return True

        def external_process(self, fd):
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for YahooMail processing" % self.fd.inode)

            self.process_readmessage(fd)
            #if self.process_send_message(fd) or self.process_readmessage(fd):
            #    pass

        def process_send_message(self,fd):
            dbh = DB.DBO(self.case)
            dbh.execute("select `key`,`value` from http_parameters where inode_id = %r", self.fd.inode_id)
            query = dict([(r['key'].lower(),r['value']) for r in dbh])
            result = {'type':'Edit Sent'}
            for field, pattern in [('To','send_to'),
                                   ('From','username'),
                                   ('CC','send_to_cc'),
                                   ('Bcc', 'send_to_bcc'),
                                   ('Subject', 'subject'),
                                   ('Message', 'body')]:
                if query.has_key(pattern):
                    result[field] = query[pattern]

            if len(result.keys())>2:
                ## Fixme: Create VFS node for attachments
                return self.insert_message(result)

            else: return False

        def process_readmessage(self, fd):
            result = {'type': 'Read', 'Message':'' }

            ## Try to find the messageheader
            header = self.parser.root.find("table", {"class":"messageheader"})
            if not header: return
            
            ## Look through all its rows:
            context = None
            for td in header.search("td"):
                if context:
                    for i in td:
                        if type(i)==str:
                            result[context] = HTML.unquote(HTML.decode_entity(i))
                            break
                    context = None

                data = td.innerHTML()
                if data.lower().startswith('from:'):
                    context = 'From'
                elif data.lower().startswith('to:'):
                    context = 'To'
                elif data.lower().startswith('date:'):
                    context = 'Sent'
                elif data.lower().startswith('subject:'):
                    context = 'Subject'

            ## Now the message:
            msgbody = self.parser.root.find('div', {"class":"msgbody"})
            if msgbody:
                result['Message'] = msgbody.innerHTML()
                
            if 'Sent' in result:
                result['Sent'] = TableObj.guess_date(result['Sent'])
            
            if len(result.keys())>3:
                return self.insert_message(result, inode_template = "y%s")            


class YahooMailViewer(LiveCom.LiveMailViewer):
    specifier = 'y'

    def fixup_page(self, root):
        ## Put in some script to turn on visibility (this emulates
        ## what yahoo does).
        tag = root.find("body")

        ## This will not be filtered out because the parser thinks its
        ## just a string
        tag.add_child("""<script>
        document.write('<style>* { visibility: visible; }</style>');
        </script>""")


