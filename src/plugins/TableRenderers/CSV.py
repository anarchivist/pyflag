""" This table renderer takes care of exporting to CSV """

import pyflag.UI as UI
import csv, cStringIO
import pyflag.DB as DB

class CSVRenderer(UI.TableRenderer):
    exportable = True
    name = "Comma Seperated Values (CSV)"

    def form(self, query, result):
        result.heading("Export to CSV")
        submitted = query.has_key('start_limit')

        query.default('start_limit',0)
        query.default('end_limit',0)
        
        result.textfield("Start Row (0)", "start_limit")
        result.textfield("End Row (0 - no limit)", "end_limit")

        return submitted
        
    def render_tools(self, query,result):
        pass

    def render_table(self, query, result):
        g = self.generate_rows(query)

        ## Make the table headers with suitable order by links:
        hiddens = [ int(x) for x in query.getarray(self.hidden) ]

        self.column_names = []
        elements = []
        for e in range(len(self.elements)):
            if e in hiddens: continue
            self.column_names.append(self.elements[e].name)
            elements.append(self.elements[e])
            
        def generator(query, result):
            yield "#Pyflag Table widget output\n#Query was %s.\n" % query
            try:
                yield "# Filter: %s\n" % query[self.filter]
            except KeyError: pass

            yield "#Fields: %s\n" % ",".join(self.column_names)
            data = cStringIO.StringIO()
            csv_writer = csv.DictWriter(data,self.column_names,
                                        dialect = 'excel')

            for row in g:
                result = dict( [ (e.name , row[e.name]) for e in elements ] )
                csv_writer.writerow(result)
                data.seek(0)
                yield data.read()

                data.truncate(0)
            
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
