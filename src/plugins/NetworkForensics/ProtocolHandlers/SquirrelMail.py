# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Tue Jun 10 13:18:41 EST 2008$
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
""" This is a module to parse squirel mail web mails """
import pyflag.DB as DB
import LiveCom
from FileFormats.HTML import decode_entity, HTMLParser, join_urls, decode
import pyflag.pyflaglog as pyflaglog
import FileFormats.HTML as HTML

class SquirrelMailScan(LiveCom.HotmailScanner):
    """ Detect SquirrelMail Sessions """

    class Scan(LiveCom.HotmailScanner.Scan):
        service = "Squirrel"
        
        def boring(self, metadata, data=''):
            dbh = DB.DBO(self.case)
            dbh.execute("select content_type,url,host from http where inode_id=%r limit 1", self.fd.inode_id)
            row = dbh.fetch()
            ## We dont actually need to scan the file to add it as an
            ## attachment to a previous message
            if row and "download.php" in row['url']:
                self.handle_downloads(row['url'])
                return True

            if (row and "compose.php" in row['url']) or "SquirrelMail" in data[:256]:
                self.parser =  HTMLParser(verbose=0)
                self.url = row['url']
                return False
            
            return True

        def handle_downloads(self, url):
            dbh = DB.DBO(self.case)
            ## What is our session id?
            dbh.execute("select value from http_parameters where inode_id = %r and `key`='SQMSESSID'", self.fd.inode_id)
            row = dbh.fetch()
            if not row: return

            ## See if there are any pending attachments:
            dbh.execute("select inode_id from webmail_attachments where url = %r and isnull(attachment)", url)
            row = dbh.fetch()
            if row:
                print "Found attachement"
                dbh.update("webmail_attachments", where="inode_id = %r" % row['inode_id'],
                           attachement = self.fd.inode_id)
            
        def external_process(self, fd):
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for SquirrelMail processing" % self.fd.inode)

            if self.process_mail_listing() or \
                   self.process_send_message(fd) or self.process_readmessage(fd):
                pass

        def process_mail_listing(self):
            """ Search for a listing in this page """
            current_folder = None
            for td in self.parser.root.search("td"):
                if td.attributes.get('align')=='left' and \
                       "Current Folder" in td.children[0]:
                    current_folder = HTML.decode(td.children[1].innerHTML())
                    break

            if not current_folder: return None

            for table in self.parser.root.search("table"):
                ## I wish they would use css - it would make it easier to identify things:
                if table.attributes.get('cellpadding')=='1' and \
                       table.attributes.get('cellspacing')=='0' and \
                       table.attributes.get('border')=='0' and \
                       table.attributes.get('align')=='center' and \
                       table.attributes.get('bgcolor')=='#ffffcc':
                    b = table.find("b")
                    if b.innerHTML() == "From":
                        ## Ok we are pretty sure this is a listing now:
                        result = {'type':'Listed', 'Message': table,
                                  'From': current_folder}
                            
                        return self.insert_message(result, inode_template = "y%s")

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

            ## Fill in all the other fields:
            context = None
            for td in self.parser.root.search('td'):
                if context:
                    result[context] = decode_entity(td.innerHTML())
                    context = None

                b = td.find('b')
                if not b: continue

                data = b.innerHTML()
                if data.lower().startswith('from:'):
                    context = 'From'
                elif data.lower().startswith('to:'):
                    context = 'To'
                elif data.lower().startswith('date:'):
                    context = 'Sent'
                elif data.lower().startswith('subject:'):
                    context = 'Subject'

            ## Now the message:
            pre = self.parser.root.find('pre')
            if pre:
                result['Message'] += pre.__str__()

            if len(result.keys())>3:
                new_inode_id = self.insert_message(result)            
                dbh = DB.DBO(self.case)

                ## Now do the attachments:
                for a in self.parser.root.search("a"):
                    if "download.php" in a.attributes.get("href",''):
                        url = a.attributes['href']
                        ## Its a relative reference:
                        if not url.startswith('http'):
                            url = join_urls(self.url, decode(url))

                        dbh.insert("webmail_attachments",
                                   inode_id = new_inode_id,
                                   url = url)

## Unit tests:
import pyflag.pyflagsh as pyflagsh
import pyflag.tests as tests

class SquirrelTests(tests.ScannerTest):
    """ Tests SquirrelMail Scanner """
    test_case = "PyFlagTestCase"
    test_file = 'output.pcap'
    subsystem = "Advanced"
    fstype = "PCAP Filesystem"

    def test01GmailScanner(self):
        """ Test SquirrelMail Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "SquirrelMailScan","GmailScanner"
                                   ,"HotmailScanner",
                                   ])                   ## List of Scanners
