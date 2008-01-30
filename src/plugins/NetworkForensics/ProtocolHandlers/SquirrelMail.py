# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
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
""" This is a module to parse squirel mail web mails """
import pyflag.DB as DB
import LiveCom
from FileFormats.HTML import decode_entity, HTMLParser
import pyflag.pyflaglog as pyflaglog

class SquirrelMailScan(LiveCom.HotmailScanner):
    """ Detect SquirrelMail Sessions """

    class Scan(LiveCom.HotmailScanner.Scan):
        service = "Squirrel"
        
        def boring(self, metadata, data=''):
            dbh = DB.DBO(self.case)
            dbh.execute("select content_type,url,host from http where inode_id=%r limit 1", self.fd.inode_id)
            row = dbh.fetch()
            if (row and "compose.php" in row['url']) or "SquirrelMail" in data[:256]:
                self.parser =  HTMLParser(verbose=0)
                return False
            
            return True
                   
        def external_process(self, fd):
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for SquirrelMail processing" % self.fd.inode)

            if self.process_send_message(fd) or self.process_readmessage(fd):
                pass

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
                return self.insert_message(result)            

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
