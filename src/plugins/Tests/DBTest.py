""" These are tests for the DB handling. Unfortunately they can not appear in the DB.py module itself due to dependancy problems.
"""
import pyflag.conf
config = pyflag.conf.ConfObject()
import DB
## Unit Tests
import pyflag.tests as tests
import pyflag.pyflaglog as pyflaglog
import threading, time

class DBOTest(tests.ScannerTest):
    """ Database Class Tests """
    test_case = "PyFlagTestCase"
    test_file = None
    
    def test01validinstall(self):
        """ Test to make sure we can locate the pyflag default database """
        dbh = DB.DBO()
        dbh.execute("show tables")
        tables = [ row.values()[0] for row in dbh ]
        self.assert_( 'meta' in tables)

    def test02TemporaryTables(self):
        """ Test to make sure DBO temporary tables get cleaned up after handle gc """
        dbh = DB.DBO(self.test_case)
        tablename = dbh.get_temp()
        dbh.execute("create table %s(field1 text)", tablename)
        dbh.execute("select * from %s", tablename)
        result = [ row['field1'] for row in dbh ]
        self.assertEqual(result, [])

        dbh2 = DB.DBO(self.test_case)
        tablename2 = dbh2.get_temp()
        self.assert_(tablename2 != tablename)

        del dbh
        def ExceptionTest():
            dbh = DB.DBO(self.test_case)
            dbh.execute("select * from %s", tablename)

        self.assertRaises(DB.DBError, ExceptionTest)

    def createTestTable(self, dbh):
        tablename = dbh.get_temp()
        dbh.execute("create table %s(field1 int)", tablename)

        for i in range(0,10):
            dbh.insert(tablename, field1=i)

        return tablename

    def test03ServerSideReconnect(self):
        """ Test to ensure that dbhs reconnect after an aborted server side connection """
        dbh = DB.DBO(self.test_case)
        tablename = self.createTestTable(dbh)

        dbh.execute("select * from %s", tablename)
        result = [ row['field1'] for row in dbh if row['field1'] < 5 ]
        self.assertEqual(result, range(0,5))

    def test04SlowQueryAbort(self):
        """ Test to make sure slow queries are aborted """
        dbh = DB.DBO(None)

        #Make the timeout 1 second for testing
        dbh.cursor.timeout = 1

        dbh.execute("select sleep(20) as sleep")
        result = dbh.fetch()['sleep']
        self.assertEqual(result, 1)
        dbh.cursor.timeout = 0

    def test05MassInsert(self):
        """ Test the mass insert mechanism """
        dbh = DB.DBO(self.test_case)
        tablename = dbh.get_temp()
        dbh.execute("create table %s(field1 int)", tablename)

        dbh.mass_insert_start(tablename)
        ## Escaped variables:
        dbh.mass_insert(field1 = 1)

        ## Non-escaped insert
        dbh.mass_insert(_field1 = "1+1")

        dbh.mass_insert_commit()
        dbh.execute("select * from %s" , tablename)

        result = [ row['field1'] for row in dbh ]
        self.assertEqual(result, [1,2])

    def test06CachedExecute(self):
        """ Test that query caching works properly """
        dbh=DB.DBO(self.test_case)
        tablename = self.createTestTable(dbh)

        ## Do a cached select:
        dbh.cached_execute("select * from %s" % tablename)
        result = [ row['field1'] for row in dbh ]
        self.assertEqual(result, range(0,10))

        ## Make sure we came from the cache:
        cached_sql = dbh.cursor._last_executed
        self.assert_('cache_' in cached_sql)

        ## Update the underlying table:
        dbh.insert(tablename, field1=1)

        ## query the cache again:
        dbh.cached_execute("select * from %s" % tablename)
        result2 = [ row['field1'] for row in dbh ]

        self.assertEqual(result2, result + [1,])

        ## Make sure we have a different cache entry
        self.assert_(cached_sql != dbh.cursor._last_executed)

    def test07CaseExecuteRace(self):
        """ Test for race conditions in cache creation """
        results = []
        dbh = DB.DBO(self.test_case)
        dbh.execute("delete from meta where property = 'test row'")
        dbh.insert("meta", property="test row", value=1, _fast=True)
        dbh.invalidate("meta")
        
        def execute_long_query(results):
            dbh = DB.DBO(self.test_case)
            dbh.cached_execute("select value from meta where property='test row' and sleep(2)=0")
            ## If we get here we are ok:
            row = dbh.fetch()
            self.assertEqual(row['value'],'1')
            results.append(row['value'])
            
        t=threading.Thread(target=execute_long_query, args=(results,))
        t.start()
        time.sleep(0.2)
        ## This executes the same query in the current thread a little
        ## later (it should still be running in the other thread).
        execute_long_query(results)

        time.sleep(1)
        ## Wait for both threads to finish
        self.assertEqual(results,['1','1'])

    def test08Reconnect(self):
        """ Test that we can reconnect if the mysql server dies """
        dbh = DB.DBO(self.test_case)
        ## Disconnect now:
        dbh.cursor.close()
        ## Remove us from the cache too:
        dbh.DBH.expire(".")
        ## Now try to execute a query - it should reconnect transparently:
        dbh.execute("select 1")
        row = dbh.fetch()

        self.assertEqual(row['1'], 1)

    def test09Unicode(self):
        """ Test that we can insert and retrieve unicode characters """
        dbh = DB.DBO(self.test_case)
        tests = [ u'this is a \u0d61 char\'acter ' ,]
        for v in tests:
            dbh.delete("meta", where="property='TestString'", _fast=True)
            dbh.insert("meta", property= "TestString", value=v,
            _fast=True)
            dbh.execute("select * from meta where property='TestString' limit 1")
            row = dbh.fetch()
            self.assertEqual(row['value'],v, "Expected %s, got %s" % (v,row['value']))

def print_stats():
    dbh = DB.DBO("mysql")
    dbh.execute("show processlist")
    connections = {}
    for row in dbh:
        try:
            connections[row['db']]+=1
        except:
            connections[row['db']] =1
            
    print "Usage statistics for DB"
    for time, key, pool in DB.DBO.DBH.creation_times:
        print "%s - I have %s handles, the database has %s handles" % (key,pool.qsize(), connections[key])

if config.LOG_LEVEL >= pyflaglog.VERBOSE_DEBUG:
    import atexit
    atexit.register(print_stats)
