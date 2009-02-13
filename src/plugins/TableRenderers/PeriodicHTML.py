# ******************************************************
# Copyright 2009: Commonwealth of Australia.
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
""" This table renderer is used to set up periodically updated
reports. As new data is loaded into the case, the reports get updated
to reflect the new data. This allows PyFlag to operate in a kind of
batch mode with new data loaded, and automatically producing rendered
reports.
"""

import HTMLBundle
import cPickle
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework
import pyflag.pyflaglog as pyflaglog

class PeriodicRenderer(HTMLBundle.HTMLDirectoryRenderer):
    name = "Periodic HTML Exporter"
    message = "Set up periodic incremental exporting to a Directory"

    def render_table(self, query,result):
        print "Rendering table"

        ## Fill in some provided parameters:
        self.page_name = query['filename']
        self.description = query.get('description','')
        self.include_extra_files = query.get('include_extra_files',False)
        
        ## We do not allow ordering of the result set because it can
        ## cause very slow queries:
        query.clear("order")

        self.query = query

        ## We save off the renderer
        renderer = cPickle.dumps(self)
        dbh = DB.DBO(self.case)
        dbh.insert("reporting_jobs", renderer=renderer)

        result.heading("Setting up periodic export")
        result.para("Periodic export set up.")
        return 

    def calculate_table_stats(self):
        """ Calculate the tables affected by query and their current state.

        We return a dict of keys = tables names, values = number of
        rows in each table. This should give us a good indication of
        the current state of the tables.
        """
        result = {}
        dbh = DB.DBO(self.case)
        sql = self._make_sql(self.query, ordering=False)
        dbh.execute("explain %s", sql)
        tables = [ row['table'] for row in dbh if row['table'] ]
        for t in tables:
            dbh.execute("select count(*) as total from %s", t)
            row = dbh.fetch()
            result[t] = row['total']

        return result

    def real_render_table(self):
        ## Ok we need to figure out which pages need updating - we
        ## assume that data is only added to the tables not removed.
        self.limit = 0
        dbh = DB.DBO(self.case)
        dbh.execute("select count(*) as total from reporting where "
                    " page_name like '%s%%'", self.page_name)
        total = dbh.fetch()['total']

        ## Now work out the limit of the last page - we redo the last
        ## page because it may be more complete now.
        dbh.execute("select * from reporting where "
                    " page_name like '%s%%' order by `limit` desc limit 1",
                    self.page_name)
        row = dbh.fetch()
        if row:
            self.query.set("start_limit", row['limit'])
            ## The initial page
            page = total
        else:
            self.query.set("start_limit",0)
            page = 1

        print "Doing page %s from %s" % (page, self.query['start_limit'])
        self.parse_limits(self.query)
        g = self.generate_rows(self.query, ordering=False)
        self.add_constant_files()

        hiddens = [ int(x) for x in self.query.getarray(self.hidden) ]

        self.column_names = []
        for e in self.elements:
            print "%s.%s " % (e.table, e.name)
        elements = []
        for e in range(len(self.elements)):
            if e in hiddens: continue
            self.column_names.append(self.elements[e].name)
            elements.append(self.elements[e])

        while 1:
            page_name = "%s%03u.html" % (self.page_name, page)
            page_data = self.render_page(page_name, page, elements, g)
            if self.row_count ==0: break

            self.add_file_from_string(page_name,
                                      page_data.encode("utf8"))

            print "Page %s\n" % page
            page +=1

        ## update the TOC page:
        self.toc()

class PeriodicExporter(FlagFramework.EventHandler):
    """ Update the exported tables periodically """
    def periodic(self, dbh, case):
        try:
            pdbh = DB.DBO()
        except:
            return

        pdbh.execute("select value from meta where property='flag_db'")
        for row in pdbh:
            try:
                case = row['value']
                dbh = DB.DBO(case)
                dbh2 = DB.DBO(case)
                try:
                    dbh.execute('select id, tables, renderer from reporting_jobs')
                except:
                    event = HTMLBundle.ReportingTables()
                    event.create(dbh, case)
                    continue
                
                for row in dbh:
                    try:
                        tables = cPickle.loads(row['tables'])
                    except Exception,e:
                        tables = None
                    
                    renderer = cPickle.loads(row['renderer'])
                    new_table = renderer.calculate_table_stats()
                    if tables != new_table:
                        pyflaglog.log(pyflaglog.DEBUG, "Re-exporting HTML Table %s" % renderer.page_name)
                        renderer.real_render_table()
                        dbh2.execute("update reporting_jobs set tables = %r where id=%r",
                                     cPickle.dumps(new_table), row['id'])
            except Exception,e:
                print e
                pass
            
import pyflag.tests
import pyflag.pyflagsh as pyflagsh

class PeriodicExportTest(pyflag.tests.ScannerTest):
    """ Test that periodically exporting a HTML directory works """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.5.e01"
    subsystem = 'EWF'
    offset = "16128s"

    def setUp(self):
        dbh = DB.DBO(self.test_case)
        dbh.execute("delete from reporting_jobs")

    def test01TypeScan(self):
        """ Check the type scanner works """
        env = pyflagsh.environment(case=self.test_case)
#        pyflagsh.shell_execv(env=env, command="scan",
#                             argv=["*",'TypeScan'])

        pyflagsh.shell_execv(env=env, command="export",
                             argv=["Images","PeriodicRenderer",
                                   "TypeCaseTable.Thumbnail",
                                   "TypeCaseTable.Type","InodeTable.Size",
                                   #'filter=Type contains JPEG',
                                   ])
        ## Simulate a periodic run:
        p = PeriodicExporter()
        p.periodic(None, None)

        ## Try again
        p.periodic(None, None)
        
