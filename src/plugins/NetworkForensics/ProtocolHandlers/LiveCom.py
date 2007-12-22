""" This module is designed to extract messages from live.com (the new
name for hotmail).

The reason this is needed is that most modern web mail applications
use so much javascript its impossible to make sense of the html
objects directly - they are not simple pages any more. This module
tries to extract certain pieces of information from the html object
specifically oriented towards the live.com/hotmail service.

How this works:

1) We only target inodes with a type of html as well as the regex
'<title>\s+Windows Live' in the top.

InboxLight pages (pages showing a view of the inbox or another mail folder)

2) We obtain the list of folders by doing some dom navigation (find li with class=FolderItemNormal, get the a below it and extract the FolderID, get the span below that and get the name of the mail box. This gives us a mapping between folder id and mailbox name).

3) Extract all the messages using some more DOM stuff:
  - Locate a table with class InboxTable, iterate over its rows
  - for each row, the 5th td is the to field. The mailbox can be found from the a tag there.
  - The subject is the 6th field. Date is the 7th field. Size is the 8th field.

EditMessageLight - This page is what the user receives when they want to edit a new message.

3) Search for a table with class ComposeHeader, iterate over its rows
   - For each row extract the fields from the id attributes:
     - From tr - find an option tag with selected attribute
     - To tr, Cc tr, Bcc tr, Subject tr - find an input tag and extract the value attribute
     - To find the actual context of the message search for script tags, with a regex:
     document.getElementById\(\"fEditArea\"\).innerHTML='([^']+)'
     The result needs to be unescaped suitably.

4) When EditMessageLight is called it has a form which submits into itself. To get the post values look at the http_parameters table for that HTTP object id.
"""
import pyflag.FlagFramework as FlagFramework
from pyflag.TableObj import StringType, TimestampType, InodeType, IntegerType, PacketType
from FileFormats.HTML import decode_entity, HTMLParser
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import re
import pyflag.pyflaglog as pyflaglog

class LiveTables(FlagFramework.EventHandler):
    def create(self, dbh, case):
        dbh.execute(
            """ CREATE table if not exists `live_messages` (
            `id` int not null auto_increment,
            `inode_id` int not null,
            `type` enum('Edit Read','Edit Sent','Read','Listed') default 'Edit Read',
            `From` VARCHAR(250),
            `To` VARCHAR(250),
            `CC` VARCHAR(250),
            `BCC` VARCHAR(250),
            `Subject` VARCHAR(250),
            `Message` Text,
            primary key (`id`))""")

import fnmatch

class HotmailScanner(Scanner.GenScanFactory):
    """ Detects Live.com/Hotmail web mail sessions """
    default = True
    depends = ['TypeScan']

    def multiple_inode_reset(self, inode_glob):
        Scanner.GenScanFactory.multiple_inode_reset(self, inode_glob)
        dbh = DB.DBO(self.case)
        sql = fnmatch.translate(inode_glob)
        dbh.delete("live_messages", where="inode_id in (select inode_id from inode where inode rlike %r)" % sql) 
    
    class Scan(Scanner.StoreAndScanType):
        types = (
            'text/html',
            )
        parser = None

        def boring(self, metadata, data=''):
            ## We dont think its boring if our base class does not:
            ## And the data contains '<title>\s+Windows Live' in the top.
            if not Scanner.StoreAndScanType.boring(self, metadata, data='') and \
                   re.search("<title>\s+Windows Live", data):
                   ## Make a new parser:
                if not self.parser:
                    self.parser =  HTMLParser(verbose=0)
                return False

            return True

        def process(self, data, metadata=None):
            Scanner.StoreAndScanType.process(self, data, metadata)
            ## Feed our parser some more:
            if not self.boring_status:
                self.parser.feed(data)
                ## Get all the tokens
                while self.parser.next_token(True): pass

        def external_process(self, fd):
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for Hotmail processing" % self.fd.inode)

            ## Now we should be able to parse the data out:
            self.process_editread(fd)

        def process_readmessage(self,fd):
            pass

        def process_editread(self, fd):
            ## Find the ComposeHeader table:
            result = {'type':'Edit Read', 'inode_id': self.fd.inode_id}

            tag = self.parser.find(self.parser.root, 'table', **{"class":'ComposeHeader'})
            if not tag:
                #pyflaglog.log(pyflaglog.DEBUG, "Tag ComposeHeader not found in %s" % self.fd.inode)
                return
            
            ## Iterate over its rows:
            for row in self.parser.search(tag, 'tr'):
                try:
                    if row['id'] == 'From':
                        option = self.parser.find(row, 'option', selected='.*')
                        result['From'] = decode_entity(option['value'])
                        
                    elif row['id'] == 'To':
                        option = self.parser.find(row, 'input', type='text')
                        if option:
                            result['To'] = decode_entity(option['value'])
                            
                    elif row['id'] == 'Cc':
                        option = self.parser.find(row, 'input', name='fCc')
                        if option:
                            result['Cc'] = decode_entity(option['value'])

                    elif row['id'] == 'Bcc':
                        option = self.parser.find(row, 'input', name='fBcc')
                        if option:
                            result['Bcc'] = decode_entity(option['value'])
                            
                except KeyError:
                    continue

            ## Extract the subject:
            option = self.parser.find(tag, 'input', type='text', name='fSubject')
            if option:
                result['Subject'] = decode_entity(option['value'])

            ## Now extract the content of the email:
            for s in self.parser.search(self.parser.root,'script'):
                m=re.match("document\.getElementById\(\"fEditArea\"\)\.innerHTML='([^']*)'", s['_cdata'])
                if m:
                    result['Message'] = m.group(1).decode("string_escape")
                    break

            dbh = DB.DBO(self.case)
            dbh.insert('live_messages', **result)

            return True

class LiveComMessages(Reports.report):
    """
    Browse LiveCom/Hotmail messages.
    --------------------------------

    This allows the results from the hotmail message scanner to be viewed.

    """

    name = "Browse Hotmail Messages"
    family = "Network Forensics"

    def display(self, query, result):
        result.table(
            elements = [ TimestampType('Timestamp','http.date'),
                         StringType('From', 'From'),
                         StringType('To', 'To'),
                         StringType('CC', 'CC'),
                         StringType('BCC', 'BCC'),
                         StringType('Subject', 'Subject'),
                         StringType('Message','Message'),
                         ],
            table = 'live_messages,http',
            where = 'http.id=live_messages.id',
            case = query['case']
            )
