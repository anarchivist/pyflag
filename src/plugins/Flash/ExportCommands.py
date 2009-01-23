""" These commands allow us to create reports from pyflash """

import pyflag.pyflagsh as pyflagsh
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry
import pyflag.TEXTUI as TEXTUI

class export(pyflagsh.command):
    """ Export a custom report """
    long_opts = ['filter=']
    
    def help(self):
        return "export filename [ column ... ] [ options ].  Exports the table constructed by columns into the filename provided. Columns must be specified in fully qualified form (table.column name) and options must be specified in standard form too (key=value)."

    def execute(self):
        ## Derive an element list
        elements = []
        for t in self.args[1:]:
            yield t
            if '.' in t:
                class_name , column_name = t.split(".")
                cls = Registry.CASE_TABLES.dispatch(class_name)()
                elements.append(cls.bind_column(self.environment._CASE, column_name))
            elif "=" in t:
                key,value = t.split("=",1)
                print t
                self.opts.set(key, value)

        exporter = Registry.TABLE_RENDERERS.dispatch("HTMLDirectoryRenderer")
        exporter = exporter(elements=elements,
                            case=self.environment._CASE)

        ## Set the filename
        self.opts.set('filename', self.args[0])
        self.opts.set('include_extra_files',1)
        self.opts.set('explain_inodes',1)

        print self.opts
        
        g = exporter.generate_rows(self.opts)
        print self.opts
        
        ## Render it
        ui = TEXTUI.TEXTUI(query=self.opts)
        exporter.render(self.opts, ui)
        for i in ui.generator.generator:
            print i
        print ui
        #return ui.generator
        
    def complete(self, text, state):
        args = self.args
        if len(args)<2: return

        if '.' in text:
            ## complete the column name
            table, column = text.split(".")
            tbl = Registry.CASE_TABLES.dispatch(table)()
            if tbl:
                columns = [ c.name for c in tbl.instantiate_columns() if c.name.startswith(column)]
                return "%s.%s" % (table,columns[state])
        else:
            tables = [ t for t in Registry.CASE_TABLES.class_names if t.startswith(text)]
            return tables[state]

import pyflag.tests
import pyflag.pyflagsh as pyflagsh

class HTMLExportTest(pyflag.tests.ScannerTest):
    """ Test that exporting a HTML directory works """
    test_case = "PyFlagTestCase"
    test_file = "pyflag_stdimage_0.5.e01"
    subsystem = 'EWF'
    offset = "16128s"

    def test01TypeScan(self):
        """ Check the type scanner works """
        env = pyflagsh.environment(case=self.test_case)
        pyflagsh.shell_execv(env=env, command="scan",
                             argv=["*",'TypeScan'])

        env['filter'] = "Type contains html"
        pyflagsh.shell_execv(env=env, command="export",
                             argv=["Images","TypeCaseTable.Thumbnail",
                                   "TypeCaseTable.Type","InodeTable.Size",
                                   'filter=Type contains html'])
