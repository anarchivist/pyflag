""" This plugin provides reports for viewing of files in special
ways. For example we are able to display properly sanitised html with
matched images etc.
"""
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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
import HTMLParser
import StringIO
import re,os.path,cgi, textwrap
from FlagFramework import query_type,normpath

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
    parameters = {'inode':'any'}

    def form(self,query,result):
        result.case_selector()
        result.textfield("Inode to view",'inode')

    def display(self,query,result):
        result.decoration = 'naked'

        dbh = DB.DBO(query['case'])
        try:
            dbh.execute("select mime from type where inode=%r",query['inode'])
            row = dbh.fetch()
            content_type = row['mime']
        except (DB.DBError,TypeError):
            content_type = 'application/octet-stream'

        fsfd = FileSystem.DBFS( query["case"])
        
        fd = fsfd.open(inode=query['inode'])

        ## Now establish the content type
        for k,v in self.dispatcher.items():
            if k.search(content_type):
                return v(self,fd, result)
                
        return self.default_handler(fd, result)

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
            sanitiser = HTMLSanitiser(fd.case, fd.inode)
            while 1:
                data = fd.read(1000000)
                try:
                    if data:
                        sanitiser.feed(data)
                    else:
                        sanitiser.close()
                except HTMLParser.HTMLParseError:
                    pass

                yield sanitiser.read()

                if not data: break

        ui.generator.generator = generator()
        
    def zip_handler(self, fd, ui):
        ## Show the file listing in the zip file:
        import zipfile
        z = zipfile.ZipFile(fd,'r')
        ## This is a bit of cheating...
        ui.start_table(**{'class':'PyFlagTable'})
        ui.row("File Name", "Modified    ", "Size", **{'class':'hilight'})
        for zinfo in z.filelist:
            date = "%d-%02d-%02d %02d:%02d:%02d" % zinfo.date_time
            ui.row(zinfo.filename, date, zinfo.file_size)

    dispatcher = { re.compile("text/html"): html_handler,
                   re.compile("image.*"): image_handler,
                   re.compile("application/x-zip"): zip_handler
                   }

class HTMLSanitiser(HTMLParser.HTMLParser):
    """ This parser is used to sanitise the html and resolve any
    references back into the case if possible.
    """

    ## No other tags will be allowed (especially script tags)
    allowable_tags = [ 'b','i','a','img','em','br','strong', 'blockquote',
                       'tt', 'li', 'ol', 'ul', 'p', 'table', 'td', 'tr',
                       'h1', 'h2', 'h3', 'pre', 'html', 'font', 'body',
                       'code', 'head', 'meta', 'title','style', 'form',
                       'sup', 'input', 'span', 'label', 'option','select',
                       'div','span','nobr','u', 'frameset','frame','iframe',
                       'textarea',]

    allowable_attributes = ['color', 'bgolor', 'width', 'border',
                            'rules', 'cellspacing', 
                            'cellpadding', 'height',
                            'align', 'bgcolor', 'rowspan', 
                            'colspan', 'valign','id', 'class','name', 
                            'compact', 'type', 'start', 'rel',
                            'value', 'checked', 'rows','cols',
                            'framespacing','frameborder',
                            ]

    def __init__(self, case,inode):
        HTMLParser.HTMLParser.__init__(self)
        ## Output will be written to this
        self.output = StringIO.StringIO()
        self.dbh = DB.DBO(case)
        self.inode = inode
        self.case = case
        self.dbh.execute("select url from http where inode=%r", self.inode)
        row=self.dbh.fetch()
        try:
            url = row['url']
            m=re.search("(http|ftp)://([^/]+)/([^?]*)",url)
            self.method = m.group(1)
            self.host = m.group(2)
            self.base_url = os.path.dirname(m.group(3))
            if not self.base_url.startswith("/"):
                self.base_url = "/"+self.base_url

            if self.base_url.endswith("/"):
                self.base_url = self.base_url[:-1]

        except:
            self.method = ''
            self.host = ''
            self.base_url = ''

        self.comment = False
            
    def read(self):
        """ return any data parsed so far """
        self.output.seek(0)
        data = self.output.read()
        self.output.truncate(0)
        return data
    
    def handle_starttag(self, tag, attrs):
        sanitised_attrs = []
        if tag=="script":
            self.output.write("<!--")
            self.comment = True
        elif tag=="object":
            tag = 'img'
            sanitised_attrs.append(("src","images/spacer.png"))
        elif tag not in self.allowable_tags:
            tag = "removed original_tag=%r" % tag


        for name,value in attrs:
            name = name.lower()
            if name in  self.allowable_attributes:
                sanitised_attrs.append((name,value))
            elif name=='href':
                sanitised_attrs.append((name, "javascript: alert(%r)" % value))
            elif name=='src':
                sanitised_attrs.append((name, self.resolve_reference(value)))
            
        tmp = " ".join( [ "%s=%r" % (x[0],x[1]) for x in sanitised_attrs if not x[1]==None ])
        tmp +=" "+ " ".join( [ "%s" % x[0] for x in sanitised_attrs if x[1]==None ])
        self.output.write("<%s %s>" % (tag,tmp))

    def resolve_reference(self, reference):
        """ This tries to find the relevant reference in the database"""
        original_reference = reference

        ## Absolute reference
        if reference.startswith('http'):
            pass
        elif reference.startswith("/"):
            path = normpath("%s" % (reference))
            reference="%s://%s%s" % (self.method, self.host, path)
        else:
            path = normpath("/%s/%s" % (self.base_url,reference))
            reference="%s://%s%s" % (self.method, self.host, path)

        ## Try to make reference more url friendly:
        reference = reference.replace(" ","%20")
        
        self.dbh.execute("select inode from http where url=%r and not isnull(inode) limit 1", reference)
        row = self.dbh.fetch()
        if row and row['inode']:
            return "%s" % query_type(case=self.case, family="Network Forensics",
                                     report="ViewFile", inode=row['inode'])

        print original_reference, reference
        return '#original reference=%s' % original_reference

    def handle_data(self,data):
        if self.comment:
            data=data.replace("<!--","< comment>")
            data=data.replace("-->", "</comment>")
            
        self.output.write(data)

    def handle_endtag(self, tag):
        if tag not in self.allowable_tags:
            new_tag = "removed original_tag=%r" % tag
        else: new_tag=tag
        
        self.output.write("</%s>" % new_tag)
        if tag=="script":
            self.output.write("-->")
            self.comment = False

    def handle_decl(self,decl):
        self.output.write("<!%s>" % decl)

    def handle_comment(self,comment):
        if self.comment:
            pass
#            self.output.write("<comment %s />" % comment)

        else:
            self.output.write("<!--%s-->" % comment)

    def handle_entityref(self,entity):
        self.output.write("&%s;" % entity)

## This is a fix for a bug in HTMLParser's regex:
HTMLParser.locatestarttagend = re.compile(r"""
  <[a-zA-Z][-.a-zA-Z0-9:_]*          # tag name
  (?:\s+                             # whitespace before attribute name
    (?:[a-zA-Z_][-.:a-zA-Z0-9_]*     # attribute name
      (?:\s*=\s*                     # value indicator
        (?:'[^']*'                   # LITA-enclosed value
          |\"[^\"]*\"                # LIT-enclosed value
          |[^'\">\s]+                # bare value
         )?
       )?
     )
   )*
  \s*                                # trailing whitespace
""", re.VERBOSE)
