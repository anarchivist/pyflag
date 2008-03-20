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
import pyflag.pyflaglog as pyflaglog

class HTMLDirectoryRenderer(UI.TableRenderer):
    exportable = True
    name = "HTML Diretory"

    ## An option to control adding extra files linked from the html
    include_extra_files = False
    message = "Export HTML Files into a directory"
    limit_context = 'start_limit'

    def form(self, query,result):
        result.heading(self.message)
        submitted = query.has_key('start_limit')
        query.default('start_limit',0)
        query.default('end_limit',0)

        result.textfield("Start Row (0)", "start_limit")
        result.textfield("End Row (0 - no limit)", "end_limit")
        result.checkbox("Include extra files","include_extra_files","Include files such as inodes in the exported bundle")

        return submitted

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
        header = '''<html><head>
        <link rel="stylesheet" type="text/css" href="images/pyflag.css" />
        <style>
        html, body {
        overflow: auto;
        }
        </style>
        </head>
        <body>
        <script src="javascript/functions.js" type="text/javascript" language="javascript"></script>
        <div class="PyFlagHeader">
        %(toolbar)s
        </div>
        <div class="PyFlagPage" id="PyFlagPage">
        <table class="PyFlagTable" ><thead><tr>'''

        result = ''
        for e in range(len(elements)):
            n = elements[e].name
            if self.order==e:
                if self.direction=='1':
                    result += "<th>%s<img src='images/increment.png'></th>" % n
                else:
                    result += "<th>%s<img src='images/decrement.png'></th>" % n
            else:
                result += "<th>%s</th>" % n

        result+='''</tr></thead><tbody class="scrollContent">'''

        old_sorted = None
        old_sorted_style = ''

        ## Total number of rows
        self.row_count=0

        for row in row_generator:
            row_elements = []
            tds = ''

            ## Render each row at a time:
            for i in range(len(elements)):
                ## Give the row to the column element to allow it
                ## to translate the output suitably:
                value = row[elements[i].name]
                try:
                    ## Elements are expected to render on cell_ui
                    cell_ui =  elements[i].render_html(value,self)
                except Exception, e:
                    pyflaglog.log(pyflaglog.ERROR, "Unable to render %r: %s" % (value , e))

                ## Render the row styles so that equal values on
                ## the sorted column have the same style
                if i==self.order and value!=old_sorted:
                    old_sorted=value
                    if old_sorted_style=='':
                        old_sorted_style='alternateRow'
                    else:
                        old_sorted_style=''

                ## Render the sorted column with a different style
                if i==self.order:
                    tds+="<td class='sorted-column'>%s</td>" % (cell_ui)
                else:
                    tds+="<td class='table-cell'>%s</td>" % (cell_ui)

            result += "<tr class='%s'> %s </tr>\n" % (old_sorted_style,tds)
            self.row_count += 1
            if self.row_count >= self.pagesize:
                break

        return header % {'toolbar': self.navigation_buttons(page_number)} + \
               result + """</tbody></table>
               </div><script>AdjustHeightToPageSize('PyFlagPage');</script>
               </body></html>"""

    def navigation_buttons(self, page_number):
        if page_number==1:
            result = '<img border="0" src="images/stock_left_gray.png"/>'
        else:
            result = '''<a href="page%s.html">
            <abbr title="Previous Page (%s)">
            <img border="0" src="images/stock_left.png"/>
            </abbr>
            </a>''' % (page_number-1,page_number-1)

        if self.row_count < self.pagesize:
            result += '<img border="0" src="images/stock_right_gray.png"/>'
        else:
            result += '''<a href="page%s.html">
            <abbr title="Next Page (%s)">
            <img border="0" src="images/stock_right.png"/>
            </abbr>
            </a>''' % (page_number+1,page_number+1)

        return result

    def add_constant_files(self):
        """ Adds constant files to the archive like css, images etc """
        for filename, dest in [ ("images/spacer.png", "inodes/images/spacer.png"),
                                ("images/spacer.png", None),
                                ('images/pyflag.css',None,),
                                ('images/decrement.png',None,),
                                ('images/increment.png',None),
                                ('images/stock_left.png',None),
                                ('images/stock_left_gray.png',None),
                                ('images/stock_right.png',None),
                                ('images/stock_right_gray.png',None),
                                ('images/toolbar-bg.gif',None),
                                ('images/browse.png',None),
                                ('javascript/functions.js', None),
                                ]:
            if not dest: dest = filename
            self.add_file(dest, open("%s/%s" % (config.DATADIR, filename)))

    def render_table(self, query, result):
        g = self.generate_rows(query)
        self.inodes_in_archive = set()
        self.add_constant_files()

        self.include_extra_files = query.get('include_extra_files',False)
        
        hiddens = [ int(x) for x in query.getarray(self.hidden) ]

        self.column_names = []
        elements = []
        for e in range(len(self.elements)):
            if e in hiddens: continue
            self.column_names.append(self.elements[e].name)
            elements.append(self.elements[e])
            
        def generator(query, result):
            page = 1

            while 1:
                page_data = self.render_page(page, elements, g)
                if self.row_count ==0: break
                
                self.add_file_from_string("page%s.html" % page,
                                          page_data)
                                          
                yield "Page %s" % page
                page +=1
            
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
        try:    self.end_limit = int(query.get('end_limit',0))
        except: self.end_limit = 0

        total = 0
        while 1:
            dbh.cached_execute(self.sql,limit = self.limit, length=self.pagesize)
            count = 0
            for row in dbh:
                yield row
                count += 1
                total += 1
                if self.end_limit > 0 \
                   and total > self.end_limit: return

            if count==0: break

            self.limit += self.pagesize


    def add_file_to_archive(self, inode_id, directory='inodes/'):
        """ Given an inode_id which is a html file, we sanitise it and add
        its references to the bundle in table_renderer."""

        if not self.include_extra_files:
            return "#"

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

    message = "Export HTML Files into a zip file"

    def render_table(self, query, result):
        g = self.generate_rows(query)
        self.inodes_in_archive = set()
        self.add_constant_files()
        self.include_extra_files = query.get('include_extra_files',False)
        
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
    def __init__(self, inode_id, table_renderer, prefix='', name=None, attributes=None):
        self.table_renderer = table_renderer
        self.prefix = prefix
        HTML.ResolvingHTMLTag.__init__(self, table_renderer.case, inode_id, name, attributes)
        
    def make_reference_to_inode(self, inode_id, hint):
        ## Ensure that the inode itself is included into the bundle:
        filename = self.table_renderer.add_file_to_archive(inode_id)
        m = Magic.MagicResolver()
        type, content_type = m.find_inode_magic(self.case, inode_id)

        return "%s%s type='%s' " % (self.prefix, inode_id, content_type)

def render_html(self, inode_id, table_renderer):
    filename = table_renderer.add_file_to_archive(inode_id, directory='inodes/')

    ## A link to the file's body
    fsfd = FileSystem.DBFS(self.case)
    fd = fsfd.open(inode_id = inode_id)

    result = "<a href='%s'>%s</a>" % (filename, fd.inode)

    ## A link to the html export if available:
    try:
        data = fd.html_export(tag_class = Curry(BundleResolvingHTMLTag,
                                                inode_id = inode_id,
                                                table_renderer = table_renderer))

        filename = "inodes/%s_summary" % inode_id
        table_renderer.add_file_from_string(filename, data)
        result += "<br/><a href='%s'><img src=images/browse.png /></a>" % (filename,)
    except AttributeError:
        raise

    return result

InodeIDType.render_html = render_html
