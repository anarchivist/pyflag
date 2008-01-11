""" This module implement a log driver for loading a windows event log """
import pyflag.LogFile as LogFile
import plugins.LogAnalysis.Simple as Simple
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
from pyflag.ColumnTypes import TimestampType, IntegerType, StringType, IPType
import pyflag.Reports as Reports
import pyflag.conf
config=pyflag.conf.ConfObject()
import re
import FileFormats.EVTLog as EVTLog
import pyflag.IO as IO
from format import *

class EventLogLog(Simple.SimpleLog):
    """ Log parser for Windows Event log files """
    name = "Event Logs"

    def get_fields(self):
        if self.datafile==None:
            raise IOError("Datafile is not set!!!")

        print "Datafile %s" % (self.datafile,)
        
        for file in self.datafile:
            ## open the file as a url:
            fd = IO.open_URL(file)
            dbh = DB.DBO()
            buffer = Buffer(fd=fd)
            header = EVTLog.Header(buffer)
            buffer = buffer[header.size():]
             
            while 1:
                try:
                    event = EVTLog.Event(buffer)

                    source = event['Source'].get_value()
                    machine = event['Machine'].get_value()
                    
                    ## Find the filename for this source:
                    dbh.execute("select filename from EventMessageSources where source=%r", source)
                    row=dbh.fetch()
                    if row:
                        dbh.execute("select message from EventMessages where filename=%r and message_id=%r", (row['filename'], event['EventID'].get_value()))
                        row = dbh.fetch()
                        if row:
                            message=EVTLog.format_message(row['message'],event['Strings'])
                        ## Message not found
                        else:
                            message="Unable to find message format string (Maybe file was not loaded with --mode=dll?). Parameters are: %s" % event['Strings']
                        
                    ## Filename not found for this source:
                    else: message="Unable to locate file for source %s. Maybe you need to run EventLogTool with the --reg flag on the SYSTEM registry hive? Parameters are: %s " % (source,event['Strings'])


                    buffer=buffer[event.size():]
                    result = dict(
                        _time= "from_unixtime('%s')" % event['TimeGenerated'].get_value(),
                        message= message,
                        event = event['EventID'].get_value(),
                        Source = event['Source'].get_value(),
                        record = event['RecordNumber'].get_value(),
                        )
                    try:
                        result['arg1'] = event['Strings'][0].get_value()
                    except: pass

                    try:
                        result['arg2'] = event['Strings'][1].get_value()
                    except: pass

                    try:
                        result['arg3'] = event['Strings'][2].get_value()
                    except: pass
                    
                    yield result
                    
                except IOError:
                    break
                
    def parse(self, query, datafile='datafile'):
        Simple.SimpleLog.parse(self,query, datafile)
        self.fields = [ IntegerType(name='Record', column='record'),
                        TimestampType(name='Timestamp', column='time'),
                        StringType(name='message', column='message'),
                        IntegerType(name='EventID', column='event'),
                        StringType(name='Source', column="Source"),
                        StringType(name='arg1', column='arg1'),
                        StringType(name='arg2', column='arg2'),
                        StringType(name='arg3', column='arg3'),
                        ]

    def form(self, query, result):
        def test(query,result):
            self.parse(query)
            result.text("The following is the result of importing the first few lines from the log file into the database.\nPlease check that the importation was successfull before continuing.")
            self.display_test_log(result)
            return True

        result.wizard(
            names = (
            "Step 1: Select Log File",
            "Step 2: View test result",
            "Step 3: Save Preset",
            "Step 4: End",
            ),
            callbacks = (
            LogFile.get_file,
            test,
            FlagFramework.Curry(LogFile.save_preset, log=self),
            LogFile.end,
            ))

### Some unit tests for EventLog loader:
import time
from pyflag.FlagFramework import query_type
import pyflag.pyflagsh as pyflagsh

class EventLogTest(LogFile.LogDriverTester):
    """ EventLog Log file processing """
    test_case = "PyFlagTestCase"
    test_table = "TestTable"
    test_file = "SysEvent.evt"
    log_preset = "EventLogTest"

    def test01CreatePreset(self):
        """ Test that EventLog Presets can be created """
        dbh = DB.DBO(self.test_case)
        log = EventLogLog(case=self.test_case)
        query = query_type(datafile = self.test_file, log_preset=self.log_preset)
        log.parse(query)
        log.store(self.log_preset)
        
    def test02LoadFile(self):
        """ Test that Event Log files can be loaded """
        dbh = DB.DBO(self.test_case)
        log = LogFile.load_preset(self.test_case, self.log_preset, [self.test_file])
        t = time.time()
        ## Load the data:
        for a in log.load(self.test_table):
            pass

        print "Took %s seconds to load log" % (time.time()-t)
            
        ## Check that all rows were uploaded:
        dbh.execute("select count(*) as c from `%s_log`", self.test_table)
        row = dbh.fetch()
        self.assertEqual(row['c'], 626)
