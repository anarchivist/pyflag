""" This module is designed to extract information from gmail traffic.

This is similar but slightly different to the module implemented in
LiveCom. This protocol is a little more complicated because messages
are sent back in a json stream via ajax, rather than simple html.
"""
import pyflag.FlagFramework as FlagFramework
from pyflag.TableObj import StringType, TimestampType, InodeIDType, IntegerType, PacketType
from FileFormats.HTML import decode_entity, HTMLParser
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.FileSystem as FileSystem
import re, urllib
import pyflag.pyflaglog as pyflaglog
import LiveCom

def parse_json(string):
    """ This function attempts to parse the json stream returned by the gmail server.

    This is a little tricky because the gmail application itself uses
    javascript to eval it, with a couple of internal functions of its
    own. We try to eval the stream using python too, but there are
    some subtle differences between the javascript syntax and the
    python syntax which we need to massage.

    This should not expose a security vulnerability because we provide
    both local and global dictionaries.
    """
    def _A(x='',*args):
        """ Not really sure what this function is used for, we just
        return our first element
        """
        return x

    ## First we need to tweak the data to avoid some subtle syntax
    ## differnces: Javascript allows empty array elements to be
    ## omitted (as in [1,,,2])
    string = re.sub("(?<=,),","'',",string)

    result = eval(string, {"_A": _A}, {})
    return result

def gmail_unescape(string):
    """ We find gmail strings to be escaped in an unusual way. This
    function reverses it
    """
    string = re.sub(r"\\u(....)",lambda m: chr(int(m.group(1),16)), string)
    string = re.sub(r"\\>",">", string)
    string = re.sub(r"&#([^;]+);",lambda m: chr(int(m.group(1),10)), string)
    string = urllib.unquote(string)

    return string

class GmailScanner(LiveCom.HotmailScanner):
    """ Detect Gmail web mail sessions """

    class Scan(LiveCom.HotmailScanner.Scan):
        parser = None
        javascript = None
        service = "Gmail"

        def boring(self, metadata, data=''):
            dbh = DB.DBO(self.case)
            dbh.execute("select content_type,url,host from http where inode=%r limit 1", self.fd.inode)
            row = dbh.fetch()
            if row and row['host']=='mail.google.com' and \
                   row['url'].startswith("http://mail.google.com/mail/"):
                if row['content_type'].startswith("text/javascript"):
                    self.javascript = ''
                elif row['content_type'].startswith("text/html"):
                    self.parser =  HTMLParser(verbose=0)
                else:
                    return True
                
                return False

            return True

        def process(self, data, metadata=None):
            Scanner.StoreAndScanType.process(self, data, metadata)
            ## Feed our parser some more:
            if not self.boring_status:
                if self.javascript == None:
                    self.parser.feed(data)
                    ## Get all the tokens
                    while self.parser.next_token(True): pass
                else:
                    self.javascript += data
                     
        def external_process(self, fd):
            if self.process_send_message(fd) or self.process_readmessage(fd):
                pyflaglog.log(pyflaglog.DEBUG,"Opening %s for Gmail processing" % self.fd.inode)
            
        def process_send_message(self,fd):
            ## Check to see if this is a POST request (i.e. mail is
            ## sent to the server):
            dbh = DB.DBO(self.case)
            dbh.execute("select `key`,`value` from http_parameters, http where http.inode = %r and http.id = http_parameters.id", self.fd.inode)
            query = dict([(r['key'].lower(),r['value']) for r in dbh])
            result = {'type':'Edit Sent'}
            for field, pattern in [('To','to'),
                                   ('From','from'),
                                   ('CC','cc'),
                                   ('Bcc', 'bcc'),
                                   ('Subject', 'subject'),
                                   ('Message', 'body')]:
                if query.has_key(pattern):
                    result[field] = query[pattern]

            if len(result.keys())>2:
                ## Fixme: Create VFS node for attachments
                return self.insert_message(result)

            else: return False

        def process_readmessage(self,fd):
            """ This one pulls out the read message from the AJAX stream.

            Gmail does not send the message in html, it send it as a
            javascript object. So we need to try to find these objects
            and then decode them.
            """
            ## We are looking for a json stream, its not html at
            ## all. Google encode this stream in two ways:
            
            ## 1) The first statement is while(1); so that a browser
            ## getting it as normal script (and hence running it) will
            ## lock up.

            ## 2) Nowhere in the page there is < character - this
            ## stops a html parser from reading any tags. All <
            ## characters are actually encoded in unicode as \u003c
            if not self.javascript or not self.javascript.startswith("while"):
                return False

            try:
                json = parse_json(self.javascript[self.javascript.find('[[['):])
                result = {'type':'Read'}
                
                for i in json[0]:
                ## This is a message:
                    if i[0]=='ms':
                        message = i[13]
                        result['From'] = gmail_unescape(message[1])
                        result['Subject'] = gmail_unescape(message[5])
                        result['Message'] = gmail_unescape(message[6])

                        return self.insert_message(result)
                        
            except Exception,e:
                print "Unable to parse %s as json stream: %s" % (self.fd.inode , e)
                return False

## Unit tests:
import pyflag.pyflagsh as pyflagsh
import pyflag.tests as tests

class GmailTests(tests.ScannerTest):
    """ Tests Gmail Scanner """
    test_case = "PyFlagTestCase"
    test_file = 'gmail.com.pcap.e01'
    subsystem = "EWF"
    fstype = "PCAP Filesystem"

    def test01GmailScanner(self):
        """ Test Gmail Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "GmailScanner",
                                   ])                   ## List of Scanners
