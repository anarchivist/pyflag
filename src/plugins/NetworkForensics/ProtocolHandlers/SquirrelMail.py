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
            dbh.execute("select content_type,url,host from http where inode=%r limit 1", self.fd.inode)
            row = dbh.fetch()
            if row and "compose.php" in row['url'] or "SquirrelMail" in data:
                self.parser =  HTMLParser(verbose=0)
                return False
            
            return True
                   
        def external_process(self, fd):
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for SquirrelMail processing" % self.fd.inode)

            if self.process_send_message(fd) or self.process_readmessage(fd):
                pass

        def process_send_message(self,fd):
            dbh = DB.DBO(self.case)
            dbh.execute("select `key`,`value` from http_parameters, http where http.inode = %r and http.id = http_parameters.id", self.fd.inode)
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
            for td in self.parser.search(self.parser.root, 'td'):
                if context:
                    result[context] = decode_entity(td['_cdata'])
                    context = None

                b = self.parser.find(td, 'b')
                if not b: continue

                data = b['_cdata']
                if data.lower().startswith('from:'):
                    context = 'From'
                elif data.lower().startswith('to:'):
                    context = 'To'
                elif data.lower().startswith('date:'):
                    context = 'Sent'
                elif data.lower().startswith('subject:'):
                    context = 'Subject'

            ## Now the message:
            pre = self.parser.find(self.parser.root, 'pre')
            if pre:
                result['Message'] += pre['_cdata']
                
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
