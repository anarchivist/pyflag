""" This table renderer produces a bundle (a tar file or a directory)
of a set of html pages from the table. The bundle can be viewed as a
stand alone product (i.e. all html pages are self referential and
static) - you do not need pyflag to view them, just a web browser.

This is a good way of delivering a report.
"""
import os, os.path, tempfile, sys, time
import pyflag.UI as UI
import csv, cStringIO
import pyflag.DB as DB
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.pyflaglog as pyflaglog
import pyflag.HTMLUI as HTMLUI
from pyflag.DB import expand

config.add_option("REPORTING_DIR", default=config.RESULTDIR + "/Reports",
                  help = "Directory to emit reports into.")

class HTMLDirectoryRenderer(UI.TableRenderer):
    exportable = True
    name = "HTML Directory"
    distributable = True

    ## An option to control adding extra files linked from the html
    include_extra_files = False
    message = "Export HTML Files into a directory"
    limit_context = 'start_limit'
    page_name = "Page"
    description = "PyFlag Exported Page"
    explain_inodes = False
    
    def form(self, query,result):
        result.heading(self.message)
        query.default('start_limit',0)
        query.default('end_limit',0)

        result.textfield("Filename","filename")
        result.textarea("Description", "description")
        result.textfield("Start Row (0)", "start_limit")
        result.textfield("End Row (0 - no limit)", "end_limit")
        result.checkbox("Include extra files","include_extra_files","Include files such as inodes in the exported bundle")
        result.checkbox("Explain Inodes", "explain_inodes","Explain All inodes")
        return query.has_key("filename")

    def render_tools(self, query, result):
        pass

    def add_file(self, filename, infd):
        """ Adds a file to the directory.

        We read the infd and write it to the specified filename.
        """
        output_file_name = "%s/%s/%s" % (config.REPORTING_DIR, self.case, filename)

        ## Make sure any directories exist:
        directory = os.path.dirname(output_file_name)
        if not os.access(directory, os.F_OK):
            os.makedirs(directory)
        
        outfd = open(output_file_name, 'wb')
        try:
            while 1:
                data = infd.read(1024*1024)
                if not data: break
                outfd.write(data)
        except IOError:
            pass

        outfd.close()

    def add_file_from_string(self, filename, string):
        """ Add a new file to the archive called filename with
        contents of string. Note string is not a unicode object here. """
        #if self.filename_in_archive(filename):
        #    return
        
        output_file_name = "%s/%s/%s" % (config.REPORTING_DIR, self.case, filename)

        ## Make sure any directories exist:
        directory = os.path.dirname(output_file_name)
        if not os.access(directory, os.F_OK):
            os.makedirs(directory)
        
        outfd = open(output_file_name, 'wb')
        outfd.write(string)
        outfd.close()

    header = '''<html><head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <link rel="stylesheet" type="text/css" href="images/pyflag.css" />
    <style>
    body {
    overflow: auto;
    height: 100%%;
    }

    div.PyFlagPage {
    overflow: visible;
    width: 100%%;
    }
    </style>
    <title>%(title)s</title>
    </head>
    <body>
    <div class="PyFlagHeader">
    %(toolbar)s
    </div>
    <div class="PyFlagPage" id="PyFlagPage">
    <table class="PyFlagTable" ><thead><tr>'''

    def render_page(self, page_name, page_number, elements, row_generator):
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

        start_value = None
        end_value = None

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
                    cell_ui = ''

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
                    end_value = value
                    if start_value == None:
                        start_value = value
    
                else:
                    tds+="<td class='table-cell'>%s</td>" % (cell_ui)

            result += "<tr class='%s'> %s </tr>\n" % (old_sorted_style,tds)
            self.row_count += 1
            if self.row_count >= self.pagesize:
                break

        ## Store critical information about the page in the db:
        dbh = DB.DBO(self.case)
        dbh.delete("reporting", where=DB.expand("page_name = %r", page_name))
        dbh.insert("reporting",
                   start_value = start_value,
                   end_value = end_value,
                   page_name = page_name,
                   description = self.description)

        return self.header % {'toolbar': self.navigation_buttons(page_number),
                         'title': self.description or "PyFlag HTML Export",
                         } + \
               result + """</tbody></table>
               </div>
               </body></html>"""

    def navigation_buttons(self, page_number):
        if page_number==1:
            result = '<img border="0" src="images/stock_left_gray.png"/>'
        else:
            result = '''<a href="%s%03u.html">
            <abbr title="Previous Page (%s)">
            <img border="0" src="images/stock_left.png"/>
            </abbr>
            </a>''' % (self.page_name, page_number-1,page_number-1)

        result += "Page %s" % page_number

        if self.row_count < self.pagesize:
            result += '<img border="0" src="images/stock_right_gray.png"/>'
        else:
            result += '''<a href="%s%03u.html">
            <abbr title="Next Page (%s)">
            <img border="0" src="images/stock_right.png"/>
            </abbr>
            </a>''' % (self.page_name, page_number+1,page_number+1)

        return result

    def add_constant_files(self):
        """ Adds constant files to the archive like css, images etc """
        for filename, dest in [ ("images/spacer.png", "inodes/images/spacer.png"),
                                ("images/spacer.png", None),
                                ('images/pyflag.css',None,),
                                ('images/pyflag.css', "inodes/images/pyflag.css",),
                                ('images/next_line.png', None),
                                ('images/decrement.png',None,),
                                ('images/increment.png',None),
                                ('images/stock_left.png',None),
                                ('images/stock_left_gray.png',None),
                                ('images/stock_right.png',None),
                                ('images/stock_right_gray.png',None),
                                ('images/toolbar-bg.gif',None),
                                ('images/question.png',None),
                                ('images/browse.png',None),
                                ('javascript/functions.js', None),
                                ]:
            if not dest: dest = filename
            self.add_file(dest, open("%s/%s" % (config.DATADIR, filename),'rb'))

    def inodes_in_archive(self, inode_id):
        """ returns True if the inode is already present in the
        archive
        """
        filename = "inodes/%s" % (inode_id)
        return self.filename_in_archive(filename)
    
    def filename_in_archive(self, filename):
        filename = "%s/%s/%s" % (config.REPORTING_DIR, self.case, filename)
        try:
            os.stat(filename)
            return True
        except OSError:
            return False
        
    def render_table(self, query, result):
        ## Fill in some provided parameters:
        self.page_name = query['filename']

        self.description = query.get('description','')

        g = self.generate_rows(query)
        self.add_constant_files()

        self.include_extra_files = query.get('include_extra_files',False)
        
        hiddens = [ int(x) for x in query.getarray(self.hidden) ]

        self.column_names = []
        for e in self.elements:
            print "%s.%s " % (e.table, e.name)
        elements = []
        for e in range(len(self.elements)):
            if e in hiddens: continue
            self.column_names.append(self.elements[e].name)
            elements.append(self.elements[e])
            
        def generator(query, result):
            page = 1

            while 1:
                page_name = "%s%03u.html" % (self.page_name, page)
                page_data = self.render_page(page_name, page, elements, g)
                if self.row_count ==0: break
                
                self.add_file_from_string(page_name,
                                          page_data.encode("utf8"))
                                          
                yield "Page %s\n" % page
                page +=1

                ## update the TOC page:
                self.toc()
        
        result.generator.generator = generator(query,result)

    def toc(self):
        result = HTMLUI.HTMLUI(initial = True)
        result.heading("Case %s" % self.case)

        result.start_table(**{'class': 'PyFlagTable'})
        result.raw("<thead><th>Filename</th><th>Description</th><th>From</th><th>To</th></thead>")
        dbh = DB.DBO(self.case)
        dbh.execute("select * from reporting order by page_name")
        for row in dbh:
            if row['start_value'] == 'None': continue
            
            result.row(expand("<a href=%r>%s</a>", (row['page_name'],row['page_name'])),
                       row['description'],
                       row['start_value'],
                       row['end_value'],
                       **{'class':'hoverRow'})
        result.end_table()

        result.raw("<p><p>\n<font size='-5' color=red>Report Produced using PyFlag Ver. %s</font>" % config.VERSION)

        page = u'''<html><head><link media="all" href="images/pyflag.css" type="text/css" rel="stylesheet">
        <title>Table of Content</title>
        <style>
        body {
        overflow: auto;
        height: 100%%;
        }

        div.PyFlagPage {
        overflow: visible;
        width: 100%%;
	}
        </style>
        </head>
        <body>
        <div id="PyFlagPage" class="PyFlagPage">
        %s
        </div>
        </body></html>''' % result

        self.add_file_from_string("toc.html", page.encode("utf8"))

    def generate_rows(self, query):
        """ This implementation gets all the rows, but makes small
        queries to maximise the chance of getting cache hits.
        """
        dbh = DB.DBO(self.case)
        self.sql = self._make_sql(query)
        
        ## This allows pyflag to cache the resultset, needed to speed
        ## paging of slow queries. FIXME - implement
##        try:    self.limit = int(query.get(self.limit_context,0))
        try:    self.limit = int(query.get('start_limit',0))
        except: self.limit = 0
        try:    self.end_limit = int(query.get('end_limit',0))
        except: self.end_limit = 0

        ## Doesnt make sense to finish before we started
        if self.end_limit <= self.limit:
            self.end_limit = sys.maxint

        dbh.execute(self.sql + " limit %s,%s" % (self.limit,self.end_limit-self.limit))
        count = 0
        for row in dbh:
            yield row
            count += 1

            if self.end_limit > 0 \
               and count > self.end_limit: return

    def make_archive_filename(self, inode_id, directory = 'inodes/'):
        ## Add the inode to the exported bundle:
        filename = "%s%s" % (directory, inode_id)

        fsfd = FileSystem.DBFS(self.case)
        fd = fsfd.open(inode_id = inode_id)

        m = Magic.MagicResolver()

        ## Use the magic in the file:
        try:
            type, content_type = m.find_inode_magic(self.case, inode_id)
        except:
            content_type = "plain/text"
            

        for k,v in {"jpeg": ".jpg",
                    "gif": ".gif",
                    "html": ".html",
                    "css":  ".css",
                    "png": ".png"}.items():
            if k in content_type:
                filename += v

        return filename, content_type, fd

    def add_file_to_archive(self, inode_id, directory='inodes/', visited=None):
        """ Given an inode_id which is a html file, we sanitise it and add
        its references to the bundle in table_renderer.

        visited is a dict which will be passed to any other tags we
        will use.  it mapps the inodes we already visited with the key
        and their filename as the value.
        """
        if not self.include_extra_files:
            return "#"
        
        filename, content_type, fd = self.make_archive_filename(inode_id, directory)

        if self.filename_in_archive(filename):
            return filename

        if "html" in content_type:
            ## The inode is html - it needs to be sanitised and all
            ## objects referenced from it need to be included in the
            ## output as well:
            parser = HTML.HTMLParser(tag_class = Curry(BundleResolvingHTMLTag,
                                                       inode_id = inode_id,
                                                       visited = visited,
                                                       table_renderer = self))
            data = fd.read(1024*1024)
            parser.feed(data)
            parser.close()

            ## Add more information to the title of page if needed
            s = fd.stat()
            title_tag = parser.root.find("title")
            if title_tag:
                title_tag.children = [ "%s %s %s %s" % (title_tag.innerHTML(),
                                                        s['mtime'], s['inode'], self.case) ,]
            else:
                head = parser.root.find("head")
                if head:
                    head.add_child("<title>%s %s %s</title>"%  (s['mtime'], s['inode'], self.case))
 
            self.add_file_from_string(filename, parser.root.innerHTML().encode("utf8"))
        elif 'css' in content_type:
            data = fd.read(1024*1024)
            tag = BundleResolvingHTMLTag(table_renderer = self,
                                         visited =visited,
                                         inode_id = inode_id)
            self.add_file_from_string(filename, tag.css_filter(data))
        elif not self.inodes_in_archive(inode_id):
            self.add_file(filename, fd)

        return filename

## This is disabled now because its not distributable.
##import zipfile

##class HTMLBundleRenderer(HTMLDirectoryRenderer):
##    name = "HTML Bundle"
##    ## We can not distribute this across children
##    distributable = False

##    def __init__(self, *args, **kwargs):
##        self.outfd = cStringIO.StringIO()
##        self.zip = zipfile.ZipFile(self.outfd, "w", zipfile.ZIP_DEFLATED)
##        HTMLDirectoryRenderer.__init__(self, *args, **kwargs)

##    def add_file(self, filename, infd):
##        outfd = tempfile.NamedTemporaryFile()
##        while 1:
##            data = infd.read(1024*1024)
##            if not data: break
##            outfd.write(data)

##        outfd.flush()
##        self.zip.write(outfd.name, filename)
##        outfd.close()

##    def add_file_from_string(self, filename, string):
##        self.zip.writestr(filename, string)

##    message = "Export HTML Files into a zip file"

##    def render_table(self, query, result):
##        g = self.generate_rows(query)
##        self.add_constant_files()
##        self.include_extra_files = query.get('include_extra_files',False)
        
##        hiddens = [ int(x) for x in query.getarray(self.hidden) ]

##        self.column_names = []
##        elements = []
##        for e in range(len(self.elements)):
##            if e in hiddens: continue
##            self.column_names.append(self.elements[e].name)
##            elements.append(self.elements[e])
            
##        def generator(query, result):
##            page = 1
##            self.add_file_from_string("%s/%s.html" % (self.page_name,page),
##                                      self.render_page(1, elements, g))

##            self.zip.close()
##            self.outfd.seek(0)
##            while 1:
##                data = self.outfd.read(1024*1024)
##                if not data: break

##                yield data

##        result.generator.generator = generator(query,result)
##        result.generator.content_type = "application/x-zip"
##        result.generator.headers = [("Content-Disposition","attachment; filename=table.zip"),]
        
## Here we provide the InodeIDType the ability to render html
## correctly:
from pyflag.ColumnTypes import InodeIDType
import pyflag.FileSystem as FileSystem
import pyflag.Magic as Magic
import FileFormats.HTML as HTML
from pyflag.FlagFramework import Curry
import os.path

class BundleResolvingHTMLTag(HTML.ResolvingHTMLTag):
    """
    A Tag which followed all its links and saves them to disk.
    
    visited is expected to be a dict initialised at the top level page,
    we use it to store all urls we have recursed through to prevent
    circular references.
    """
    def __init__(self, inode_id, table_renderer, prefix='', visited=None,
                 name=None, attributes=None, charset=None):
        self.table_renderer = table_renderer
        self.prefix = prefix
        self.visited = visited
        HTML.ResolvingHTMLTag.__init__(self, table_renderer.case, inode_id,
                                       name, attributes, charset=charset)
        
    def make_reference_to_inode(self, inode_id, hint):
        ## Ensure that the inode itself is included into the bundle:
        try:
            filename = self.visited[inode_id]
        except KeyError:
            self.visited[inode_id] = "images/spacer.png "
            filename = self.table_renderer.add_file_to_archive(inode_id,
                                                               visited = self.visited)
            filename = os.path.basename(filename)
            self.visited[inode_id] = filename

        return "%s%s " % (self.prefix, filename, )

import pyflag.Farm as Farm
import pyflag.pyflaglog as pyflaglog

class Export(Farm.Task):
    """ A Distributable table for exporting an inode into HTML """
    def run(self, case, inode_id, *args):
        pyflaglog.log(pyflaglog.DEBUG, "Exporting inode_id %s" % inode_id)
        table_renderer = HTMLDirectoryRenderer(case=case, include_extra_files=True)
        self.export(case, inode_id, table_renderer)

    def export(self, case, inode_id, table_renderer):
        filename = table_renderer.add_file_to_archive(inode_id, directory='inodes/',
                                                      visited = {})

        ## A link to the file's body
        fsfd = FileSystem.DBFS(case)
        fd = fsfd.open(inode_id = inode_id)

        ## A link to the html export if available:
        try:
            filename = "inodes/%s_summary.html" % inode_id
            ## Add the summary page if needed
            if not table_renderer.filename_in_archive(filename):
                tag = Curry(BundleResolvingHTMLTag,
                            inode_id = inode_id,
                            visited = {},
                            table_renderer = table_renderer)
                data = fd.html_export(tag_class = tag)
                table_renderer.add_file_from_string(filename, data.encode("utf8"))
        except AttributeError,e:
            print e
            pass

        ## Now explain this file:
        import pyflag.HTMLUI as HTMLUI
        result = HTMLUI.HTMLUI(initial = True)
        result.heading("How to derive inode %s" % fd.inode)
        
        filename = "inodes/%s_explain.html" % inode_id
        
        result.decoration='naked'
        fd.explain(None, result)
        
        table_renderer.add_file_from_string(filename, result.display())

def render_html(self, inode_id, table_renderer):
    dbh = DB.DBO()
    case = table_renderer.case
    dbh.insert("jobs",
               command = "Export",
               arg1 = case,
               arg2 = inode_id,
               cookie = int(time.time())
               )

    filename, content_type, fd = table_renderer.make_archive_filename(inode_id)
    result = "<a href='%s'>%s</a><br />" % (filename, fd.inode)
    
    try:
        filename = "inodes/%s_summary.html" % inode_id
        fd.html_export
        result += "<a href='%s'><img src=images/browse.png /></a>" % (filename,)
    except AttributeError: pass

    #if table_renderer.explain_inodes:
    ## Add a link to the explaination page:
    filename = "inodes/%s_explain.html" % inode_id
    result+="<a href='%s'><img src=images/question.png /></a>" %(filename,)

    ## Check if there are annotations for this
    dbh = DB.DBO(case)
    dbh.execute("select * from annotate where inode_id=%r", inode_id)
    for row in dbh:
        result += "<br>%s" % row['note']

    return result

## Inodes get special handling:
InodeIDType.render_html = render_html

import pyflag.FlagFramework as FlagFramework

## We need a table to maintain the top level page (TOC):
class ReportingTables(FlagFramework.EventHandler):
    """ A handler to create reporting specific tables """
    def create(self, case_dbh, case):
        case_dbh.execute("""CREATE TABLE reporting(
        `page_name` VARCHAR(250),
        `description` TEXT,
        `start_value` VARCHAR(250),
        `end_value` VARCHAR(250))""")

