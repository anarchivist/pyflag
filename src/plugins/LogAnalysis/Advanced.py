""" This is an advanced log analysis module - We add column types one
at the time and configure them
"""
import pyflag.LogFile as LogFile
import pyflag.pyflaglog as pyflaglog
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework
from pyflag.FlagFramework import query_type, Curry, show_help
import re
import pyflag.Registry as Registry
import pyflag.conf
config = pyflag.conf.ConfObject()
import inspect
import pyflag.TableObj as TableObj

## These are names which can not be set by the user
HIDDEN_NAMES = ['self', 'link', 'callback', 'link_pane']

class AdvancedLog(LogFile.Log):
    """ An advanced log parser for generic line oriented log files """
    name = "Advanced"

    def get_fields(self):
        ## For now the file is read one line at the time:
        for row in self.read_record():
            result = {}

            ## Parse the line
            for f in self.fields:
                consumed, name, sql = f.log_parse(row)
                row = row[consumed:]
                if name:
                    result[name] = sql

            yield result

    def parse(self, query, datafile=None):
        """ Recreate the Preset from the query string """
        self.fields = []
        
        if not datafile:
            self.datafile = query.getarray('datafile')

        for i in range(0,50):
            k = "field_types%u" % i
            try:
                v = query[k]
                if v == "New Column": continue
            except KeyError:
                continue

            column_class = Registry.COLUMN_TYPES.dispatch(v)

            ## Fill in all the args:
            (args, varargs, varkw, defaults) = inspect.getargspec(column_class.__init__)
            d = len(args) - len(defaults)
            tmp = {}
            for j in range(len(args)):
                k = args[j]
                fieldname = "field_param_%s_%s" % (i,k)
                try:
                    tmp[k] = query[fieldname]
                except KeyError:
                    pass

            ## Instantiate the field:
            self.fields.append(column_class(**tmp))

        ## Call our base class
        LogFile.Log.parse(self,query,datafile)

    def render_dialog(self, columntype, number, query, result):
        """ Renders a dialog to configure the column type based on its
        interospected values
        """
        ## First find the class:
        column_class = Registry.COLUMN_TYPES.dispatch(columntype)

        right = result.__class__(result)
        (args, varargs, varkw, defaults) = inspect.getargspec(column_class.__init__)
        d = len(args) - len(defaults)
        for i in range(len(args)):
            k = args[i]
            if k in HIDDEN_NAMES: continue

            fieldname = "field_param_%s_%s" % (number,k)
            if i > d and defaults[i-d]:
                result.defaults[fieldname] = defaults[i-d]
                
            right.textfield(k, fieldname)

        left = result.__class__(result)
        left.row(columntype)
        left.popup(Curry(show_help, cls=column_class),
                   "Help on %s" % columntype,
                   icon = "help.png")

        result.row(left, right, valign='top')
 
    def __init__(self,case = None):
        LogFile.Log.__init__(self, case)
        
        columntypes = [ c.__name__ for c in Registry.COLUMN_TYPES.classes if not c.hidden ]
        columntypes.sort()
        self.columntypes = [ "New Column", ] + columntypes

    def form(self, query, result):
        def add_columns(query,result):
            max_number = 0
            result.start_table()
            for i in range(0,50):
                k = "field_types%u" % i
                try:
                    v = query[k]
                    if v == "New Column": continue
                except KeyError:
                    continue
                
                max_number = max(i, max_number)
                self.render_dialog(v, i, query, result)
                
            result.end_table()

            ## Do a small test:
            try:
                self.parse(query)
            except Exception,e:
                result.text("Error: %s" % e, style='red')
                result.text(" ", style='normal')

            result.ruler()
            result.heading("Sample lines from log file")
            result.start_table()
            count =0
            for line in self.read_record():
                result.row(line)
                count +=1
                if count>3:
                    break
            result.end_table()

            try:
                self.display_test_log(result)
            except Exception,e:
                result.text("Error: %s" % e, style='red')
                result.text(" ", style='normal')

            result.ruler()
            result.heading("Select Column Type")
            result.const_selector('',"field_types%s" % (max_number+1),
                                  self.columntypes, self.columntypes , autosubmit=True)

        def test(query,result):
            self.parse(query)
            result.text("The following is the result of importing the first few lines from the log file into the database.\nPlease check that the importation was successfull before continuing.")
            self.display_test_log(result)
            return True

        result.wizard(
            names = [ "Step 1: Select Log File",
                      "Step 2: Add Columns",
                      "Step 3: Save Preset",
                      "Step : Test",
                      "Step 4: End"],
            callbacks = [ LogFile.get_file,
                          add_columns,
                          test,
                          FlagFramework.Curry(LogFile.save_preset, log=self),
                          LogFile.end
                          ],
            )

class PadType(TableObj.ColumnType):
    def __init__(self, regex='.'):
        TableObj.ColumnType.__init__(self, name="-", column="-")
        self.re = re.compile(regex)
        self.ignore = True
        
    def insert(self, value):
        pass

    def log_parse(self, row):
        m = self.re.match(row)
        
        if m:
            return m.end(), None, None

        return None, None, None
    
## Unit tests - a simple syslog parser:
import time

## Unit tests for Simple log file:
class AdvancedLogTest(LogFile.LogDriverTester):
    """ Advanced Log driver Tests """
    test_case = "PyFlag Test Case"
    test_table = "TestTable"
    test_file = "messages.gz"
    log_preset = "AdvancedSyslog"

    def test01CreatePreset(self):
        """ Test that Advanced Presets can be created """
        dbh = DB.DBO(self.test_case)
        log = AdvancedLog(case=self.test_case)
        query = query_type(datafile = self.test_file, log_preset=self.log_preset,
                           field_param_1_name="Timestamp",
                           field_param_1_column="time",
                           field_param_1_format="%b %d %H:%M:%S",
                           field_param_1_override_year="2007",
                           field_types1="TimestampType",

                           field_types2="StringType",
                           field_param_2_name = "Host",
                           field_param_2_column = 'host',

                           field_types3="StringType",
                           field_param_3_name ="Service",
                           field_param_3_column = "service",

                           field_types4="PadType",
                           field_param_4_regex = "(\[[^\]]+\])?",

                           field_types5="StringType",
                           field_param_5_name = "Message",
                           field_param_5_column = 'messages',
                           field_param_5_regex = '.*',
                           )
        
        log.parse(query)
        log.store(self.log_preset)
        
    def test02LoadFile(self):
        """ Test that Advanced Log files can be loaded """
        dbh = DB.DBO(self.test_case)
        log = LogFile.load_preset(self.test_case, self.log_preset, [self.test_file])
        t = time.time()
        ## Load the data:
        for a in log.load(self.test_table):
            pass

        print "Took %s seconds to load log" % (time.time()-t)
            
        ## Check that all rows were uploaded:
        dbh.execute("select count(*) as c from %s_log", self.test_table)
        row = dbh.fetch()
        self.assertEqual(row['c'], 3424)
