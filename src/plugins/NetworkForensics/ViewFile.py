""" This plugin provides reports for viewing of files in special
ways. For example we are able to display properly sanitised html with
matched images etc.
"""
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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
import re
from FlagFramework import query_type

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
        dbh = DB.DBO(query['case'])
        dbh.execute("select mime from type where inode=%r",query['inode'])
        row = dbh.fetch()
        content_type = row['mime']

        fsfd = Registry.FILESYSTEMS.fs['DBFS']( query["case"])
        
        fd = fsfd.open(inode=query['inode'])
        result.generator.content_type = content_type

        ## Now establish the content type
        for k,v in self.dispatcher.items():
            if k.search(content_type):
                result.generator.generator=v(self,fd)
                
        if not result.generator.generator:
            result.generator.generator=self.default_handler(fd)

    def default_handler(self, fd):
        while 1:
            data = fd.read(1000000)
            yield data
            
            if not data: break

    def html_handler(self,fd):
        """ We sanitise the html here """
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
    
    dispatcher = { re.compile("text/html"): html_handler }

class HTMLSanitiser(HTMLParser.HTMLParser):
    """ This parser is used to sanitise the html and resolve any
    references back into the case if possible.
    """

    ## No other tags will be allowed (especially script tags)
    allowable_tags = [ 'b','i','a','img','em','br','strong', 'blockquote',
                       'tt', 'li', 'ol', 'ul', 'p', 'table', 'td', 'tr',
                       'h1', 'h2', 'h3', 'pre', 'html', 'font', 'body',
                       'code', 'head', 'meta', 'title','style', 'form',
                       'sup', 'input', 'span', 'label']

    allowable_attributes = ['color', 'bgolor', 'width', 'border',
                            'rules', 'cellspacing', 
                            'cellpadding', 'height',
                            'align', 'bgcolor', 'rowspan', 
                            'colspan', 'valign','id', 'class','style','name', 
                            'compact', 'type', 'start', 'rel',
                            'http-equiv', 'content', 'value', 'checked'
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
        url = row['url']
        m=re.search("(http|ftp)://([^/]+)/([^?]*)",url)
        self.method = m.group(1)
        self.host = m.group(2)
        self.base_url = m.group(3)
        if "/" in self.base_url:
            self.base_url=self.base_url[:self.base_url.rfind("/")]

    def read(self):
        """ return any data parsed so far """
        self.output.seek(0)
        data = self.output.read()
        self.output.truncate(0)
        return data
    
    def handle_starttag(self, tag, attrs):
        if tag not in self.allowable_tags:
            tag = "REMOVED style='display: hidden;' %s" % tag

        sanitised_attrs = []
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
        ## Absolute reference
        if reference.startswith("/"):
            reference="%s://%s%s" % (self.method, self.host,reference)
        else:
            reference="%s://%s/%s/%s" % (self.method, self.host, self.base_url, reference)
        
        self.dbh.execute("select inode from http where url=%r limit 1", reference)
        row = self.dbh.fetch()
        if row:
            return "%s" % query_type(case=self.case, family="Network Forensics",
                                     report="ViewFile", inode=row['inode'])
        
        return '#'
    def handle_data(self,data):
        self.output.write(data)

    def handle_endtag(self, tag):
        if tag not in self.allowable_tags:
            tag = "REMOVED %s" % tag
        
        self.output.write("</%s>" % tag)

    def handle_decl(self,decl):
        self.output.write("<!%s>" % decl)

    def handle_comment(self,comment):
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
