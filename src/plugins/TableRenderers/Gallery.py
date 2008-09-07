""" This TableRenderer simply produces a gallery of thumbnails of each
inode in the table
"""

import HTMLBundle
from pyflag.ColumnTypes import InodeIDType
import pyflag.DB as DB
import pyflag.FileSystem as FileSystem
import pyflag.Graph as Graph
import posixpath

class GalleryRenderer(HTMLBundle.HTMLDirectoryRenderer):
    name = "Gallery Export"
    message = "Create a gallery from all files in a table"

    def render_cell(self, inode_id):
        """ Renders a single inode_id """
        filename, ct, fd = self.make_archive_filename(inode_id, directory = "thumbnails/")
        image = Graph.Thumbnailer(fd, 200)

        inode_filename,ct, fd = self.make_archive_filename(inode_id)
        
        self.add_file_from_string(filename, image.display())
        path, inode, inode_id = FileSystem.DBFS(self.case).lookup(inode_id = inode_id)
        ## Make sure we export the inode
        dbh = DB.DBO()
        dbh.insert("jobs",
                   command = "Export",
                   arg1 = self.case,
                   arg2 = inode_id,
                   )

        return "<abbr title='%s'><a href='%s'><img src='%s' /></a><br/>"\
               "<a href='inodes/%s_explain.html' ><img src=images/question.png /></a>"\
               "%s</abbr>" % (\
                              path, inode_filename, filename, inode_id, fd.inode)
        
    def render_row(self, values):
        result = "<tr>"
        for v in values:
            result += "<td>%s</td>" % self.render_cell( v)
            
        return result + "</tr>\n"

    def render_page(self, page_name, page_number, elements, row_generator):
        ## We must have an InodeID in there
        inode = None
        
        for e in elements:
            if isinstance(e, InodeIDType):
                inode = e
                break

        ## Should not happen
        if not inode:
            raise RuntimeError("You must have Inodes in your table")

        start_value = None
        end_value = None
        
        self.row_count = 0
        tmp = []
        result = '<table>'
        for row in row_generator:
            value = row[inode.name]
            cell_ui = value
            tmp.append(cell_ui.__str__()) 

            end_value = row[elements[self.order].name]
            if not start_value:
                start_value = end_value

            if len(tmp) >= 5:
                result += self.render_row(tmp)

                tmp = []
                self.row_count +=1

                if self.row_count > 5:
                    break

        result += self.render_row( tmp)

        dbh = DB.DBO(self.case)
        dbh.delete("reporting", where=DB.expand("page_name = %r", page_name))
        dbh.insert("reporting",
                   start_value = start_value,
                   end_value = end_value,
                   page_name = page_name,
                   description = self.description)

        return self.header % {'toolbar': self.navigation_buttons(page_number),
                              'title': self.description or "PyFlag Gallery Export",
                              } + \
                              result + """</tbody></table>
                              </div>
                              </body></html>"""
