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

InboxLight pages (pages showing a view of the inbox or another mail
folder)

2) We obtain the list of folders by doing some dom navigation (find li
with class=FolderItemNormal, get the a below it and extract the
FolderID, get the span below that and get the name of the mail
box. This gives us a mapping between folder id and mailbox name).

3) Extract all the messages using some more DOM stuff:
  - Locate a table with class InboxTable, iterate over its rows

  - for each row, the 5th td is the to field. The mailbox can be found
  from the a tag there.

  - The subject is the 6th field. Date is the 7th field. Size is the
  8th field.

EditMessageLight - This page is what the user receives when they want
to edit a new message.

3) Search for a table with class ComposeHeader, iterate over its rows
   - For each row extract the fields from the id attributes:

     - From tr - find an option tag with selected attribute

     - To tr, Cc tr, Bcc tr, Subject tr - find an input tag and
     extract the value attribute

     - To find the actual context of the message search for script
     tags, with a regex:
     document.getElementById\(\"fEditArea\"\).innerHTML='([^']+)' The
     result needs to be unescaped suitably.

4) When EditMessageLight is called it has a form which submits into
itself. To get the post values look at the http_parameters table for
that HTTP object id.
"""
import pyflag.FlagFramework as FlagFramework
from pyflag.ColumnTypes import StringType, TimestampType, InodeIDType, IntegerType, PacketType
import FileFormats.HTML as HTML
import pyflag.DB as DB
import pyflag.Scanner as Scanner
import pyflag.Reports as Reports
import pyflag.FileSystem as FileSystem
import re,cgi
import pyflag.pyflaglog as pyflaglog
import textwrap
import pyflag.HTMLUI as HTMLUI
import pyflag.Registry as Registry
import pyflag.Graph as Graph

class WebMailTable(FlagFramework.CaseTable):
    """ Table to store Web mail related information """
    name = 'webmail_messages'
    columns = [
        [ InodeIDType, {} ],
        [ InodeIDType, dict(column = 'parent_inode_id')],
        [ StringType, dict(name="Service", column='service')],
        [ StringType, dict(name='Type', column='type')],
        [ StringType, dict(name='From', column='From')],
        [ StringType, dict(name='To', column='To')],
        [ StringType, dict(name='CC', column='CC')],
        [ StringType, dict(name='BCC', column='BCC')],
        [ StringType, dict(name='Subject', column='subject')],
        [ StringType, dict(name='Message', column='message', text=True)],
        [ StringType, dict(name='Identifier', column='message_id')],
        [ TimestampType, dict(name='Sent', column='sent')],
        ]

class WebMailAttachmentTable(FlagFramework.CaseTable):
    """ Table to store web mail attachment references """
    name = "webmail_attachments"
    columns = [
        [ InodeIDType, dict(name = "Message Inode") ],
        [ InodeIDType, dict(name = "Attachment", column="attachment") ],
        [ StringType, dict(name = "URL", column='url')],
        ]

class LiveTables(FlagFramework.EventHandler):
    def create(self, dbh, case):
        ## This table keeps a record of http objects which may be used
        ## to assist with rendering. Often static content on web sites
        ## is cached for a long time in users browsers. This means
        ## that they are not requested by the browser at all and this
        ## causes problems when reconstructing the pages. This table
        ## allows us to maintain our own cache of such objects which
        ## we can download by ourselves when needed.
        dbh.execute("""CREATE table if not exists `http_sundry` (
        `id` int not null auto_increment,
        `url` VARCHAR(500),
        `present` enum('yes', 'no') default 'no',
        primary key (`id`))""")

import fnmatch

class HotmailScanner(Scanner.GenScanFactory):
    """ Detects Live.com/Hotmail web mail sessions """
    default = True
    depends = ['TypeScan', 'HTTPScanner']
    group = 'NetworkScanners'

    def multiple_inode_reset(self, inode_glob):
        Scanner.GenScanFactory.multiple_inode_reset(self, inode_glob)
        dbh = DB.DBO(self.case)
        sql = fnmatch.translate(inode_glob)
        dbh.delete("webmail_messages", where="inode_id in (select inode_id from inode where inode rlike %r)" % sql) 
    
    class Scan(Scanner.StoreAndScanType):
        types = (
            'text/html',
            )
        parser = None
        service = "Hotmail"

        def boring(self, metadata, data=''):
            ## We dont think its boring if our base class does not:
            ## And the data contains '<title>\s+Windows Live' in the top.
            if not Scanner.StoreAndScanType.boring(self, metadata, data) and \
                   re.search("<title>\s+Windows Live", data):
                   ## Make a new parser:
                if not self.parser:
                    self.parser =  HTML.HTMLParser(verbose=0)
                return False

            return True

        def process(self, data, metadata=None):
            Scanner.StoreAndScanType.process(self, data, metadata)
            ## Feed our parser some more:
            if not self.boring_status:
                self.parser.feed(data.decode("utf8","ignore"))
                ## Get all the tokens
                while self.parser.next_token(True): pass

        def external_process(self, fd):
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for Hotmail processing" % self.fd.inode)
            ## Now we should be able to parse the data out:
            self.process_send_message(fd)
            self.process_editread(fd)
            self.process_readmessage(fd)
            self.process_mail_listing()

        def process_mail_listing(self):
            """ This looks for the listing in the mail box """
            table = self.parser.root.find("table",{"class":"ItemListContentTable InboxTable"})
            if not table: return False
            
            result = {'type': 'Listed', 'message': table}

            mail_box = self.parser.root.find("li", {"class":"FolderItemSelected"})
            if mail_box:
                mail_box = mail_box.find("span")
                if mail_box:
                    result['From'] = mail_box.innerHTML()

            title = self.parser.root.find("a",{"class":"uxp_hdr_meLink"})
            if title:
                result['To'] = title.innerHTML()

            return self.insert_message(result, inode_template = "l%s")


        def process_send_message(self,fd):
            ## Check to see if this is a POST request (i.e. mail is
            ## sent to the server):
            dbh = DB.DBO(self.case)
            dbh.execute("select `key`,`value` from http_parameters where inode_id = %r", self.fd.inode_id)
            query = dict([(r['key'].lower(),r['value']) for r in dbh])
            result = {'type':'Edit Sent' }
            for field, pattern in [('To','fto'),
                                   ('From','ffrom'),
                                   ('CC','fcc'),
                                   ('BCC', 'fbcc'),
                                   ('subject', 'fsubject'),
                                   ('message', 'fmessagebody')]:
                if query.has_key(pattern):
                    result[field] = query[pattern]

            if len(result.keys())>2:
                return self.insert_message(result)
            else: return False

        def process_readmessage(self,fd):
            result = {'type': 'Read', 'message':''}
            root = self.parser.root

            tag = root.find('div', {'class':'ReadMsgContainer'})
            if not tag: return

            ## Find the subject:
            sbj = tag.find('td', {'class':'ReadMsgSubject'})
            if sbj: result['subject'] = HTML.decode_entity(sbj.innerHTML())

            ## Fill in all the other fields:
            context = None
            for td in tag.search('td'):
                data = td.innerHTML()
                if context:
                    result[context] = HTML.decode_entity(data)
                    context = None
                
                if data.lower().startswith('from:'):
                    context = 'From'
                elif data.lower().startswith('to:'):
                    context = 'To'
                elif data.lower().startswith('sent:'):
                    context = 'sent'

            ## Now the message:
            ## On newer sites its injected using script:
            for s in root.search('script'):
                m=re.match("document\.getElementById\(\"MsgContainer\"\)\.innerHTML='([^']*)'", s.innerHTML())
                if m:
                    result['message'] += HTML.decode_unicode(m.group(1).decode("string_escape"))
                    break

            return self.insert_message(result)            

        def process_editread(self, fd):
            ## Find the ComposeHeader table:
            result = {'type':'Edit Read'}

            root = self.parser.root
            tag = root.find('table', {"class":'ComposeHeader'})
            if not tag:
                return

            ## Find the From:
            row = tag.find( 'select', dict(name = 'ffrom'))
            if row:
                option = row.find('option', dict(selected='.*'))
                result['From'] = HTML.decode_entity(option['value']) 

            for field, pattern in [('To','fto'),
                                   ('CC','fcc'),
                                   ('BCC', 'fbcc'),
                                   ('subject', 'fsubject')]:
                tmp = tag.find('input', dict(name = pattern))
                if tmp:
                    result[field] = HTML.decode_entity(tmp['value'])
            
            ## Now extract the content of the email:
            result['message'] = ''

            ## Sometimes the message is found in the EditArea div:
            div = root.find('div', dict(id='EditArea'))
            if div:
                result['message'] += div.innerHTML()

            ## On newer sites its injected using script:
            for s in root.search('script'):
                m=re.match("document\.getElementById\(\"fEditArea\"\)\.innerHTML='([^']*)'", s.innerHTML())
                if m:
                    result['message'] += m.group(1).decode("string_escape")
                    break

            return self.insert_message(result)
            
        def insert_message(self, result, inode_template="l%s"):
            dbh = DB.DBO(self.case)

            dbh.execute("select mtime from inode where inode_id = %r" , self.fd.inode_id)
            row = dbh.fetch()

            try:
                new_inode = inode_template % self.fd.inode_id
            except: new_inode = inode_template

            inode_id = self.ddfs.VFSCreate(self.fd.inode,
                                           new_inode,
                                           "Message", mtime = row['mtime'],
                                           _fast = True)

            dbh.insert('webmail_messages', service=self.service,
                       parent_inode_id = self.fd.inode_id,
                       inode_id = inode_id,
                       **result)
            
            return inode_id

class Live20Scanner(HotmailScanner):
    """ Parse Hotmail Web 2.0 Session """

    class Scan(HotmailScanner.Scan):
        data = ''
        types = (
            '.',)

        def boring(self, metadata, data=''):
            if not Scanner.StoreAndScanType.boring(self, metadata, data='') and \
                   re.match("new HM.FppReturnPackage\(", data):
                self.data = ''
                return False

            return True

        def process(self, data, metadata=None):
            Scanner.StoreAndScanType.process(self, data, metadata)            
            if not self.boring_status:
                self.data += data

        def finish(self):
            if self.boring_status: return
            pyflaglog.log(pyflaglog.DEBUG,"Opening %s for Hotmail AJAX processing" % self.fd.inode)        
            m=re.search("HM.InboxUiData\((.+)",self.data)
            if m:
                string = m.group(1)
                def a(*x):
                    try:
                        if x[0][2]:
                            self.process_readmessage(x[0][2])
                    except IndexError: pass

                ## Now parse the data
                eval("a(("+string, {}, {'a':a, 'null':0})

        def process_readmessage(self, message):
            parser =  HTML.HTMLParser(verbose=0)
            parser.feed(message)
            parser.close()

            result = {'type': 'Read', 'Message':''}

            ## Find the subject
            sbj = parser.root.find('td', {'class':'ReadMsgSubject'})
            if sbj: result['Subject'] = HTML.decode_entity(sbj.innerHTML())

            context = None
            for td in parser.root.search('td'):
                data = td.innerHTML()
                if context:
                    result[context] = HTML.decode_entity(data)
                    context = None
                
                if data.lower().startswith('from:'):
                    context = 'From'
                elif data.lower().startswith('to:'):
                    context = 'To'
                elif data.lower().startswith('sent:'):
                    context = 'Sent'

            msg = parser.root.find('div', {'class':'ReadMsgContainer'})
            if msg:
                result['Message'] = msg.innerHTML()


            ## Try to detect the message ID
            tag = parser.root.find('div', {'mid':'.'})
            if tag:
                result['message_id'] = tag['mid']

            return self.insert_message(result, inode_template = 'l%s')

import os.path

class LiveAttachements(FlagFramework.EventHandler):
    def find_uploaded_attachments(self, dbh):
        dbh.execute("select * from http_parameters where `key`='fAttachments'")
        dbh2 = dbh.clone()
        for row in dbh:
            parent_inode_id = row['inode_id']
            ## Find all the attachments
            for line in row['value'].split("\x1b"):
                items = line.split("|")
                filename = items[2][36:]
                m = re.search("([^.]+)", filename)
                if m: filename = m.group(1)
                ## Try to locate the files as they got uploaded
                dbh2.execute("select * from http_parameters where `key`='Subject' and value=%r limit 1",
                             filename)
                row = dbh2.fetch()
                if row:
                    ## Is there an attachment?
                    dbh2.execute("select * from http_parameters where inode_id = %r and `key`='Attachment'",
                                 row['inode_id'])
                    row = dbh2.fetch()
                    if row:
                        attachment = row['indirect']

                        # Find the webmail message for this attachment
                        dbh2.execute("select * from webmail_messages where parent_inode_id = %r",
                                     parent_inode_id)
                        row = dbh2.fetch()
                        if row:
                            ## Check if there already is an entry in attachment table
                            dbh2.execute("select * from webmail_attachments where "
                                         "inode_id = %r and attachment = %r limit 1",
                                         (row['inode_id'], attachment))

                            if not dbh2.fetch():
                                dbh2.insert("webmail_attachments",
                                            inode_id = row['inode_id'],
                                            attachment =attachment)
    
    def periodic(self, dbh, case):
        """ A periodic handler to ensure that attachements are matched
        to their respective messages
        """
        self.find_uploaded_attachments(dbh)
        dbh2 = dbh.clone()
        dbh3 = dbh.clone()
        dbh4 = dbh.clone()
        dbh3.check_index("webmail_messages","message_id")
        ## Iterate over all unique message ids
        dbh.execute("select message_id from webmail_messages group by message_id")
        for row in dbh:
            message_id = row['message_id']
            attachments = []
            ## For each message_id find direct download:
            dbh2.execute('select * from http where url like "%%GetAttachment%%messageId=%s%%"', message_id)
            for row in dbh2:
                inode_id = row['inode_id']
                if inode_id not in attachments:
                    attachments.append(inode_id)

            ## For each message id find possible SafeRedirect urls
            dbh2.execute('select http.inode_id, url from http_parameters join http on '
                         'http.inode_id = http_parameters.inode_id where  `key`="kr" and '
                         'value like "mid=%s%%" and url like "%%SafeRedirect%%"', message_id)
            for row2 in dbh2:
                ## Find out where they redirect to:
                dbh3.execute("select * from http_parameters where inode_id = %r and "
                             "(`key`='hm__qs' or `key`='hm__tg')", row2['inode_id'])
                tg = ''
                qs = ''
                for row3 in dbh3:
                    if row3['key'] == 'hm__tg': tg = row3['value']
                    elif row3['key'] == 'hm__qs': qs = row3['value']

                ## Try to locate the destination of the redirection
                dbh3.execute("select inode_id from http where url like '%s?%s%%'", (tg,qs))
                row3 = dbh3.fetch()
                if row3:
                    attachment = row3['inode_id']
                    if attachment not in attachments:
                        attachments.append(attachment)

            if attachments:
                for attachment in attachments:
                    ## Check all messages with the specific hotmail message id
                    dbh3.execute("select inode_id from webmail_messages where message_id = %r",
                                 message_id)
                    for row3 in dbh3:
                        ## Update the attachment table to contain the redirected URL.
                        dbh4.execute("select * from webmail_attachments where inode_id =%r and attachment=%r",
                                     (row3['inode_id'], attachment))
                        if not dbh4.fetch():
                            dbh4.insert("webmail_attachments",
                                        inode_id = row3['inode_id'],
                                        attachment = attachment)
        
class HTMLStringType(StringType):
    """ A ColumnType which sanitises its input for HTML.
    We also fetch images etc from the db if available.
    """
    def xxxdisplay(self, value, row, result):
        parser = HTML.HTMLParser(tag_class = HTML.SanitizingTag)
        parser.feed(value)
        parser.close()

        return parser.root.innerHTML()

    def render_html(self, value, table_renderer):
        import plugins.TableRenderers.HTMLBundle as HTMLBundle
#        parser = HTML.HTMLParser(tag_class = HTML.SanitizingTag2)
        parser = HTML.HTMLParser(tag_class = HTML.TextTag)
#        parser = HTML.HTMLParser(tag_class = \
#                                 FlagFramework.Curry(HTMLBundle.BundleResolvingHTMLTag,
#                                                     table_renderer = table_renderer,
#                                                     inode_id = '',
#                                                     prefix = "inodes/"
#                                                     ))
        parser.feed(value or '')
        parser.close()

        text = parser.root.innerHTML()

        ## Make sure its wrapped:
        ui = HTMLUI.HTMLUI(initial=True)
        ui.text(text, wrap ='full', font='typewriter')
        return ui.__str__()

    def display(self, value, row, result):
        parser = HTML.HTMLParser(tag_class = HTML.TextTag)
        parser.feed(value or '')
        parser.close()

        value = parser.root.innerHTML()

	result.text(value, wrap='full', font='typewriter')

class AttachmentColumn(InodeIDType):
    """ Displays the attachments related to the webmail message """
    def display(self, value, row, result):
        dbh = DB.DBO(self.case)
        fsfd = FileSystem.DBFS(self.case)
        dbh.execute("select file.inode_id as inode_id, name from file, webmail_attachments where webmail_attachments.inode_id = %r and file.inode_id = webmail_attachments.attachment", value)
        for row in dbh:
            tmp = result.__class__(result)

            try:
                fd = fsfd.open(inode_id=row['inode_id'])
                image = Graph.Thumbnailer(fd,100)
            except IOError:
                pass
            
            if image.height>0:
                tmp.image(image,width=image.width,height=image.height)
            else:
                tmp.image(image,width=image.width)

            link = result.__class__(result)
            name = row['name']
            if len(name) > 20: name = name[:20]+" ..."
            tmp.para(name)
            link.link(tmp, tooltip = row['name'],
                      pane = 'new',
                      target= FlagFramework.query_type(family = "Disk Forensics",
                                                       report = "ViewFile",
                                                       case = self.case,
                                                       mode = 'Summary',
                                                       inode_id = row['inode_id']))
            result.row(link)

class WebMailMessages(Reports.report):
    """
    Browse WebMail messages.
    --------------------------------

    This allows the results from the various webmail scanners to be viewed.

    """

    name = "Browse WebMail Messages"
    family = "Network Forensics"

    def display(self, query, result):
        result.table(
            elements = [ TimestampType('Timestamp','mtime', table='inode'),
                         InodeIDType(case = query['case']),
                         StringType('From', 'From'),
                         StringType('To', 'To'),
                         StringType('CC', 'CC'),
                         StringType('BCC', 'BCC'),
                         StringType('Subject', 'Subject'),
                         HTMLStringType('Message','Message'),
                         #StringType('MessageID', 'message_id'),
                         AttachmentColumn(name='Attachment',case = query['case']),
                         StringType('Type','type'),
                         StringType('Service','service'),
                         ],
            table = 'webmail_messages',
            case = query['case']
            )

import textwrap

## A VFS File driver which formats a row in the db nicely:
class TableViewer(FileSystem.StringIOFile):
    """ A VFS driver to read rows from an SQL table.

    Format is 't%s:%s:%s:%s' % (table_name, column_name, value, column_to_retrieve (optional))

    e.g. twebmail_messages:id:2
    """
    specifier = 't'

    def __init__(self, case, fd, inode):
        parts = inode.split('|')
        ourinode = parts[-1][1:]
        self.size = 0
        self.inode =inode
        self.case = case
        self.column_to_retrieve = None
                
        try:
            self.table, self.id = ourinode.split(':')
            self.value = self.lookup_id()
        except ValueError:
            try:
                self.table, self.id, self.value = ourinode.split(':')
            except ValueError:
                self.table, self.id, self.value, self.column_to_retrieve = ourinode.split(':')

        FileSystem.StringIOFile.__init__(self, case, fd, inode)
        self.force_cache()

    def read(self, length = None):
        try:
            return FileSystem.StringIOFile.read(self, length)
        except IOError: pass

        dbh = DB.DBO(self.case)
        dbh.execute("select * from %s where `%s`=%r", (self.table, self.id, self.value))

        result = '<html><body>'
        dbh = DB.DBO(self.case)
        dbh.execute("select * from %s where `%s`=%r", (self.table, self.id, self.value))
        for row in dbh:
            if self.column_to_retrieve:
                return row[self.column_to_retrieve]

            result += ("<table border=1>\n")
            for k,v in row.items():
                result += "<tr><td>%s</td>" % k
                result += "<td>%s</td></tr>\n" % textwrap.fill(
                    cgi.escape("%s" % v) or "&nbsp;",
                    subsequent_indent = "<br>")
                
            result += "</table></body></html>"
        return result

class LiveMailViewer(FileSystem.StringIOFile):
    """ A VFS Driver to render a realistic view of a Yahoo mail
    message without allowing scripts to run.
    """
    specifier = 'l'

    def __init__(self, case, fd, inode):
        parts = inode.split('|')
        self.id = parts[-1][1:]
        self.case = case
        self.inode = inode
        self.inode_id = self.lookup_id()
        dbh = DB.DBO(self.case)
        dbh.execute("select * from webmail_messages where inode_id=%r", (self.inode_id))
        row = dbh.fetch()
        if not row: raise RuntimeError("No such message %s" % self.id)

        self.parent_inode_id = row['parent_inode_id']
        self.message = row['message'] or ""
        self.size = len(self.message)
        
        FileSystem.StringIOFile.__init__(self, case, fd, inode)
        self.force_cache()
        
    def read(self, length = None):
        try:
            return FileSystem.StringIOFile.read(self, length)
        except IOError: pass

        ## We must always return a byte string for reads (files are
        ## always bytestreams)
        return self.message.encode("utf8")

    def fixup_page(self, root, tag_class):
        ## We have to inject the message into the edit area:
        edit_area = root.find("div", {"class":"EditArea"}) or \
                    root.find("div",{"id":"MsgContainer"}) or \
                    root.find("textarea",{"id":"fMessageBody"})
        if edit_area:
            parser = HTML.HTMLParser(tag_class = tag_class)
            parser.feed(HTML.decode(self.message))
            #parser.feed(self.message)
            parser.close()
            result = parser.root.__str__()
            result = textwrap.fill(result)
            edit_area.prune()
            edit_area.add_child(result)
            edit_area.name = 'div'

    def stats(self, query,result):
        result.start_table(**{'class':'GeneralTable'})
        dbh = DB.DBO(self.case)
        columns = ["service","type","From","To","CC","BCC","sent","subject","message"]
        dbh.execute("select * from webmail_messages where `inode_id`=%r", self.lookup_id())
        row = dbh.fetch()
        
        dbh2 = DB.DBO(self.case)
        dbh2.execute("select * from inode where inode_id = %r", row['inode_id'])
        row2 = dbh2.fetch()
        result.row("Timestamp", row2['mtime'])

        for c in columns:
            if c=='message':
                ## Filter the message out here:
                parser = HTML.HTMLParser(tag_class = \
                                         FlagFramework.Curry(HTML.ResolvingHTMLTag,
                                                             case = self.case,
                                                             inode_id = row['parent_inode_id']))
                #parser = HTML.HTMLParser(tag_class = HTML.TextTag)
                parser.feed(HTML.decode(row[c] or ""))
                parser.close()
                #tmp = result.__class__(result)
                #tmp.text(parser.root.innerHTML(), font='typewriter', wrap='full')
                #row[c] = tmp
                r = parser.root.__str__()
                r = textwrap.fill(r)
                row[c] = r
                
            result.row(c, row[c])

        dbh.execute("select url from http where inode_id = %r", row['parent_inode_id'])
        row = dbh.fetch()
        if row:
            tmp = result.__class__(result)
            tmp.text(row['url'], font='typewriter', wrap='full')
            result.row("URL", tmp)

    def sanitize_page(self, tag_class):
        """ This produces a rendered version of the underlying page """
        ## Get the original HTML File:
        fsfd = FileSystem.DBFS(self.case)
        fd = fsfd.open(inode_id = self.parent_inode_id)
        #data = HTML.decode(fd.read())
        data = fd.read()
        ## FIXME - This is a hack which works because we always send a
        ## curried class down:
        try:
            tag_class.kwargs['inode_id'] = self.parent_inode_id
        except AttributeError: pass
        
        ## Make a parser:
        p = HTML.HTMLParser(tag_class = tag_class)
        p.feed(data)
        p.close()

        ## Allow us to fix the html page
        root = p.root
        self.fixup_page(root, tag_class)

        ## Add the timestamp to the title of the page - so when you
        ## print it out we can identify it:
        s = fsfd.istat(inode_id = self.parent_inode_id)
        title_tag = root.find("title")
        if title_tag:
            title_tag.children = [ "%s %s %s" % (title_tag.innerHTML(),
                                                 s['mtime'], s['inode']) ,]
        
        return root.innerHTML()        

    def html_export(self, tag_class):
        return self.sanitize_page(tag_class)

    def summary(self, query, result):
        page = self.sanitize_page(tag_class = \
                                  FlagFramework.Curry(HTML.ResolvingHTMLTag,
                                                      case = self.case,
                                                      inode_id = self.parent_inode_id))
        def frame_cb(query, result):
            def generator():
                yield page

            result.generator.content_type = 'text/html'
            result.generator.generator = generator()

        def print_cb(query, result):
            def generator():
                yield page
                #yield page.replace("</html","<script>window.print()</script></html")

            result.generator.content_type = 'text/html'
            result.generator.generator = generator()

        result.iframe(callback = frame_cb)
        result.toolbar(cb = print_cb, text="Print", icon="printer.png", pane='new')
        
## PreCanned reports
class AllWebMail(Registry.PreCanned):
    report="Browse WebMail Messages"
    family="Network Forensics"
    args = {"order":0, "direction":1, "filter":"Type != Listed"}
    description = "View all Webmail messages"
    name = "/Network Forensics/Web Applications/Webmail"

## Unit tests:
import pyflag.pyflagsh as pyflagsh
import pyflag.tests as tests

class HotmailTests(tests.ScannerTest):
    """ Tests Hotmail Scanner """
    test_case = "PyFlagTestCase"
    test_file = 'live.com.pcap.e01'
    subsystem = "EWF"
    fstype = "PCAP Filesystem"

    def test01HotmailScanner(self):
        """ Test Hotmail Scanner """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env,
                             command="scan",
                             argv=["*",                   ## Inodes (All)
                                   "HotmailScanner",
                                   ])                   ## List of Scanners

        dbh = DB.DBO(self.test_case)
        dbh.execute("select count(*) as c from webmail_messages")
        row = dbh.fetch()
        self.assert_(row['c'] > 0, "No hotmail messages were found")

if __name__ == '__main__':
    import sys
    import pyflag.conf
    config = pyflag.conf.ConfObject()

    config.parse_options()

    Registry.Init()

    ## Update the current webmail_messages to include message ids
    dbh = DB.DBO(sys.argv[1])
    dbh1 = dbh.clone()
    dbh.execute("select inode_id, parent_inode_id, message_id from webmail_messages")
    for row in dbh:
        if not row['message_id']:
            data = ''
            m=''
            dbh1.execute("select `key`,value from http_parameters where inode_id=%r and `key`='kr' limit 1",
                         row['parent_inode_id'])
            row1 = dbh1.fetch()
            if row1:
                data = row1['value']
                m = re.search('mid=([^&]+)', data)
                
            if not m:
                dbh1.execute("select `key`,value from http_parameters where inode_id=%r and `key`='d' limit 1",
                         row['parent_inode_id'])
                row1 = dbh1.fetch()
                if row1:
                    data = row1['value']
                    m = re.search('\\{\\"([^\\"]+)\\"', data)

            if m:
                dbh1.execute("update webmail_messages set message_id = %r where inode_id = %r",
                             (m.group(1), row['inode_id']))
                
    
    event = LiveAttachements()
    event.periodic(dbh, dbh.case)
