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
""" This module is designed to extract information from gmail traffic.

This is similar but slightly different to the module implemented in
LiveCom. This protocol is a little more complicated because messages
are sent back in a json stream via ajax, rather than simple html.
"""
import pyflag.FlagFramework as FlagFramework
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, IntegerType, PacketType, guess_date
from FileFormats.HTML import decode_entity, HTMLParser
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.FileSystem as FileSystem
import re, urllib
import pyflag.pyflaglog as pyflaglog
import pyflag.Time as Time
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
    string = string.replace(r"\'","'")
    string = string.replace(r'\"','"')
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
            dbh.execute("select content_type,url,host from http where inode_id=%r limit 1", self.fd.inode_id)
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
            dbh.execute("select `inode_id`,`key`,`value` from http_parameters where inode_id=%r", self.fd.inode_id)
            query = {}
            key_map = {}

            for row in dbh:
                query[row['key'].lower()] = row['value']
                key_map[row['key'].lower()] = row['inode_id']

            result = {'type':'Edit Sent'}
            for field, pattern in [('To','to'),
                                   ('From','from'),
                                   ('CC','cc'),
                                   ('Bcc', 'bcc'),
                                   ('Subject', 'subject'),
                                   ('Message', 'body')]:
                if query.has_key(pattern):
                    result[field] = query[pattern]

            if len(result.keys())<3: return False
            
            ## Fixme: Create VFS node for attachments
            message_id = self.insert_message(result, "webmail")
            
            ## Are there any attachments?
            for k in query.keys():
                if k.startswith("f_"):
                    ## Create an Inode for it:
                    dbh.execute("select mtime from inode where inode_id = %r" , self.fd.inode_id)
                    row = dbh.fetch()

                    new_inode = "thttp_parameters:inode_id:%s:value" % key_map[k]
                    
                    inode_id = self.ddfs.VFSCreate(self.fd.inode,
                                                   new_inode,
                                                   k, mtime = row['mtime'],
                                                   _fast = True)
                    
                    dbh.insert("webmail_attachments",
                               inode_id = message_id,
                               attachment = inode_id)

                    fd = self.ddfs.open(inode = "%s|%s" % (self.fd.inode, new_inode))
                    Scanner.scanfile(self.ddfs, fd, self.factories)

            return message_id

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
                result = {'type':'Read', "Message":''}
            except Exception,e:
                print "Unable to parse %s as json stream: %s" % (self.fd.inode , e)
                return False

            for i in json[0]:
                ## Message index (contains all kinds of meta data)
                if i[0]=='mi':
                    result['From'] = gmail_unescape(i[7])
                    result['Subject'] = gmail_unescape(i[16])
                    #result['Sent'] = guess_date(gmail_unescape(i[15]))
                    result['Sent'] = Time.parse(gmail_unescape(i[15]), case=self.case, evidence_tz=None)
                    for x in i[9]:
                        try:
                            if x[0][0]=='me':
                                result['To'] = gmail_unescape(x[0][1])
                        except (IndexError, ValueError): pass
                        
                ## Message body
                elif i[0]=='mb':
                    result['Message'] += gmail_unescape(i[1])
                ## This is a single combined message:
                elif i[0]=='ms':
                    message = i[13]
                    try: result['From'] = gmail_unescape(i[4])
                    except IndexError: pass
                    try: result['To'] = gmail_unescape(message[1])
                    except IndexError: pass
                    try: result['Subject'] = gmail_unescape(message[5])
                    except IndexError: pass
                    try: result['Message'] = gmail_unescape(message[6])
                    except IndexError: pass

            if len(result.keys()) > 2:
                message_id = self.insert_message(result, "webmail")

##                    try:
##                        attachment = message[7][0][0]
##                        url = gmail_unescape(attachment[8])

##                        ## Make a note of the attachment so we can
##                        ## try to resolve it later.
##                        dbh = DB.DBO(self.case)
##                        dbh.insert("live_message_attachments",
##                                   message_id = message_id,
##                                   url = url)
##                    except IndexError:
##                        pass

                return message_id

class GoogleDocs(LiveCom.HotmailScanner):
    """ A scanner for google docs related pages """
    class Scan(GmailScanner.Scan):
        service = "Google Docs"
        def boring(self, metadata, data=''):
            ## This string identifies this document as worth scanning
            if "var trixApp" in data:
                self.parser =  HTMLParser(verbose=0)
                return False

            return True

        def external_process(self, fd):
            self.parser.close()
            if self.process_view_document():
                pyflaglog.log(pyflaglog.DEBUG,"Opening %s for Google Document processing" % self.fd.inode)

        def process_view_document(self):
            result = {}
            ## Find the actions:
            for script in self.parser.root.search("script"):
                data = script.innerHTML()
                m = re.search('var\s+TX_name\s+=\s+"([^"]+)";', data)
                if m:
                    result['subject'] = m.group(1)

                m = re.search('var\s+TX_username\s+=\s+"([^"]+)";', data)
                if m: result['from'] = m.group(1)

                m = re.search('var\s+TX_emailAddress\s+=\s+"([^"]+)";', data)
                if m: result['to'] = m.group(1)

                m = re.search(r'trixApp.processAction\d+\("([^\n]+)"\);', data,
                              re.S| re.M)

                if m:
                    result['message'] = gmail_unescape(m.group(1))
                    open("/tmp/test.html","w").write(m.group(1))

            if result:
                return self.insert_message(result, "webmail")

class WebmailViewer(FileSystem.StringIOFile):
    """ A VFS Driver to view formatted webmail messages """
    specifier = 'w'
    size = 0
    def read(self, length = None):
        try:
            return FileSystem.StringIOFile.read(self, length)
        except IOError: pass

        id = self.lookup_id()
        dbh = DB.DBO(self.case)
        dbh.execute("select * from webmail_messages where inode_id = %r limit 1" , id)
        row = dbh.fetch()
        if row:
            self.size = len(row['message'])
            return row['message']

        return ''

    def explain(self, query, result):
        self.fd.explain(query, result)
        id = self.lookup_id()
        dbh = DB.DBO(self.case)
        dbh.execute("select * from webmail_messages where inode_id = %r limit 1" , id)
        row = dbh.fetch()
        result.row("Web App", "Analyse %s transaction" % row['service'],
                   **{'class': 'explainrow'})

## Unit tests:
import pyflag.pyflagsh as pyflagsh
import pyflag.tests as tests

class GmailTests(tests.ScannerTest):
    """ Tests Gmail Scanner """
    test_case = "PyFlagTestCase1"
    test_file = 'gmail.com.pcap.e01'
    subsystem = "EWF"
    subsystem = "Advanced"
    fstype = "PCAP Filesystem"

    def test01GmailScanner(self):
        """ Test Gmail Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "GmailScanner", "YahooMailScan",
                                   "SquirrelMailScan", "HotmailScanner"
                                   ])                   ## List of Scanners
