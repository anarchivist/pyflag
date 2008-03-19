""" This table renderer produces a bundle (a tar file or a directory)
of a set of html pages from the table. The bundle can be viewed as a
stand alone product (i.e. all html pages are self referential and
static) - you do not need pyflag to view them, just a web browser.

This is a good way of delivering a report.
"""
import os, os.path, tempfile
import pyflag.UI as UI
import csv, cStringIO
import pyflag.DB as DB
import pyflag.conf
config=pyflag.conf.ConfObject()

class HTMLDirectoryRenderer(UI.TableRenderer):
    exportable = True
    name = "HTML Diretory"

    def form(self, query,result):
        result.heading("Export HTML Files into a directory")
        return True

    def render_tools(self, query, result):
        pass

    def add_file(self, filename, infd):
        """ Adds a file to the directory.

        We read the infd and write it to the specified filename.
        """
        output_file_name = "/tmp/output/%s" % filename
        
        ## Make sure any directories exist:
        directory = os.path.dirname(output_file_name)
        if not os.access(directory, os.F_OK):
            os.makedirs(directory)
        
        outfd = open(output_file_name, 'w')
        while 1:
            data = infd.read(1024*1024)
            if not data: break
            outfd.write(data)

        outfd.close()

    def add_file_from_string(self, filename, string):
        output_file_name = "/tmp/output/%s" % filename
        
        ## Make sure any directories exist:
        directory = os.path.dirname(output_file_name)
        if not os.access(directory, os.F_OK):
            os.makedirs(directory)
        
        outfd = open(output_file_name, 'w')
        outfd.write(string)
        outfd.close()

    def render_page(self, page_number, elements, row_generator):
        """ Returns a single HTML page of data from the row_generator """
        data = '<html><head title="Pyflag Table Export - Page %s"><body>' % page_number

        ## Write the table headers:
        data += "<table border=1><tr><th>" + "</th><th>".join(self.column_names) + "</th></tr>" 

        for row in row_generator:
            data += "<tr>"
            for e in elements:
                data += "<td>%s</td>" % e.render_html(row[e.name], self)
            data += "</tr>\n"

        data += "</table></body></html>"
            
        return data

    def add_constant_files(self):
        """ Adds constant files to the archive like css, images etc """
        for filename in [ "images/spacer.png" ]:
            self.add_file("inodes/" + filename, open("%s/%s" % (config.DATADIR, filename)))

    def render_table(self, query, result):
        g = self.generate_rows(query)
        self.inodes_in_archive = set()
        self.add_constant_files()
        
        hiddens = [ int(x) for x in query.getarray(self.hidden) ]

        self.column_names = []
        elements = []
        for e in range(len(self.elements)):
            if e in hiddens: continue
            self.column_names.append(self.elements[e].name)
            elements.append(self.elements[e])
            
        def generator(query, result):
            page = 1
            self.add_file_from_string("page%s.html" % page,
                                      self.render_page(1, elements, g))

            yield "<h1> Complete </h1>"
            
        result.generator.generator = generator(query,result)

    def generate_rows(self, query):
        """ This implementation gets all the rows, but makes small
        queries to maximise the chance of getting cache hits.
        """
        dbh = DB.DBO(self.case)
        self.sql = self._make_sql(query)
        
        ## This allows pyflag to cache the resultset, needed to speed
        ## paging of slow queries.
        try:    self.limit = int(query.get(self.limit_context,0))
        except: self.limit = 0

        while 1:
            dbh.cached_execute(self.sql,limit = self.limit, length=self.pagesize)
            count = 0
            for row in dbh:
                yield row
                count += 1

            if count==0: break

            self.limit += self.pagesize


    def add_file_to_archive(self, inode_id, directory='inodes/'):
        """ Given an inode_id which is a html file, we sanitise it and add
        its references to the bundle in table_renderer."""
        ## Add the inode to the exported bundle:
        filename = "%s%s" % (directory, inode_id)

        if inode_id in self.inodes_in_archive:
            return filename

        self.inodes_in_archive.add(inode_id)

        fsfd = FileSystem.DBFS(self.case)
        fd = fsfd.open(inode_id = inode_id)

        m = Magic.MagicResolver()

        ## Use the magic in the file:
        type, content_type = m.find_inode_magic(self.case, inode_id)
        if "html" in content_type:
            ## The inode is html - it needs to be sanitised and all
            ## objects referenced from it need to be included in the
            ## output as well:
            parser = HTML.HTMLParser(tag_class = Curry(BundleResolvingHTMLTag,
                                                       inode_id = inode_id,
                                                       table_renderer = self))
            data = fd.read(1024*1024)
            parser.feed(data)
            parser.close()

            self.add_file_from_string(filename, parser.root.innerHTML())
        elif 'css' in content_type:
            data = fd.read(1024*1024)
            tag = BundleResolvingHTMLTag(table_renderer = self,
                                         inode_id = inode_id)
            self.add_file_from_string(filename, tag.css_filter(data))
        else:
            self.add_file(filename, fd)

        return filename

import zipfile

class HTMLBundleRenderer(HTMLDirectoryRenderer):
    name = "HTML Bundle"
    def __init__(self, *args, **kwargs):
        self.outfd = cStringIO.StringIO()
        self.zip = zipfile.ZipFile(self.outfd, "w", zipfile.ZIP_DEFLATED)
        HTMLDirectoryRenderer.__init__(self, *args, **kwargs)

    def add_file(self, filename, infd):
        outfd = tempfile.NamedTemporaryFile()
        while 1:
            data = infd.read(1024*1024)
            if not data: break
            outfd.write(data)

        outfd.flush()
        self.zip.write(outfd.name, filename)
        outfd.close()

    def add_file_from_string(self, filename, string):
        self.zip.writestr(filename, string)
    
    def form(self, query,result):
        result.heading("Export HTML Files into a zip file")
        return True

    def render_table(self, query, result):
        g = self.generate_rows(query)
        self.inodes_in_archive = set()
        self.add_constant_files()
        
        hiddens = [ int(x) for x in query.getarray(self.hidden) ]

        self.column_names = []
        elements = []
        for e in range(len(self.elements)):
            if e in hiddens: continue
            self.column_names.append(self.elements[e].name)
            elements.append(self.elements[e])
            
        def generator(query, result):
            page = 1
            self.add_file_from_string("page%s.html" % page,
                                      self.render_page(1, elements, g))

            self.zip.close()
            self.outfd.seek(0)
            while 1:
                data = self.outfd.read(1024*1024)
                if not data: break

                yield data

        result.generator.generator = generator(query,result)
        result.generator.content_type = "application/x-zip"
        result.generator.headers = [("Content-Disposition","attachment; filename=table.zip"),]
        
## Here we provide the InodeIDType the ability to render html
## correctly:
from pyflag.ColumnTypes import InodeIDType
import pyflag.FileSystem as FileSystem
import pyflag.Magic as Magic
import FileFormats.HTML as HTML
from pyflag.FlagFramework import Curry

class BundleResolvingHTMLTag(HTML.ResolvingHTMLTag):
    def __init__(self, inode_id, table_renderer, name=None, attributes=None):
        self.table_renderer = table_renderer
        HTML.ResolvingHTMLTag.__init__(self, table_renderer.case, inode_id, name, attributes)
        
    def make_reference_to_inode(self, inode_id, hint):
        ## Ensure that the inode itself is included into the bundle:
        filename = self.table_renderer.add_file_to_archive(inode_id)
        m = Magic.MagicResolver()
        type, content_type = m.find_inode_magic(self.case, inode_id)

        return "%s type='%s' " % (inode_id, content_type)

def render_html(self, inode_id, table_renderer):
    filename = table_renderer.add_file_to_archive(inode_id, directory='inodes/')
    
    return "<a href='%s'>%s</a>" % (filename, inode_id)

InodeIDType.render_html = render_html
