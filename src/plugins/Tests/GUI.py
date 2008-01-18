""" This module tests the GUI automatically.

We basically run through all the GUI options and render in memory. We
look for exceptions etc, but will not be able to detect if the actual
HTML rendering is correct.
"""
import pyflag.DB as DB
import pyflag.tests
import pyflag.HTMLUI as HTMLUI
import pyflag.Registry as Registry
import pyflag.FlagFramework as FlagFramework

class GUITester(pyflag.tests.ScannerTest):
    """ GUI Tests """
    test_case = "PyFlagTestCase"
    test_file = "stdcapture_0.3.pcap"
    subsystem = 'Advanced'
    fstype = 'PCAP Filesystem'
    
    def test00preLoadCase(self):
        pass

    def gui_test(self, query):
        ## Check to see if the columns can be ordered correctly:
        for order in range(0,4):
            result = HTMLUI.HTMLUI(query=query, initial=True)
            report_cls = Registry.REPORTS.dispatch(query['family'], query['report'])
            report = report_cls(None, ui=result)
            query.set("order",order)
            report.display(query, result)

    def test01types(self):
        query = FlagFramework.query_type(family='Disk Forensics', report='Browse Types',
                                         case=self.test_case)
        self.gui_test(query)

        query = FlagFramework.query_type(family='Network Forensics', report='Browse HTTP Requests',
                                         case=self.test_case)
        self.gui_test(query)

    def test02ColumnTypes(self):
        self.CaseTableTests('inode')
        self.CaseTableTests('http')
        self.CaseTableTests('connection_details')
        
    def CaseTableTests(self, tablename):
        ## Apply each column's test filters:
        t = Registry.CASE_TABLES.dispatch(tablename)()
        result = HTMLUI.HTMLUI(initial=True)
        dbh=DB.DBO(self.test_case)
        ## For each column run all its test cases:
        elements = [ c for c in t.bind_columns(self.test_case) ]
        for c in elements:
            for operator, arg, e in c.tests:
                try:
                    ## Get the SQL:
                    filter_str = "'%s' %s '%s'" % (c.name, operator, arg)
                    sql = result._make_sql(elements = elements, filter_elements = elements,
                                           table = t.name, 
                                           filter=filter_str)
                    print "%s: Testing %s: %s" % (tablename,
                                                  c.__class__,
                                                  filter_str)
                    
                    dbh.execute(sql)
                except Exception:
                    if not e: raise
                    continue
                
                if e:
                    raise Exception("Expected an exception but did not receive one on filter string %s. SQL was %s" %( filter_str,sql))
