# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG  $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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

""" This module contains db related functions """
import MySQLdb
import MySQLdb.cursors
import _mysql
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.pyflaglog as pyflaglog
import time,types
import threading
from Queue import Queue, Full, Empty
from MySQLdb.constants import FIELD_TYPE
import threading

db_connections=0

## This is the dispatcher for db converters
conv = {
    FIELD_TYPE.LONG: long,
    FIELD_TYPE.INT24: long,
    FIELD_TYPE.LONGLONG: long,
    FIELD_TYPE.TINY: int
    }

def escape(string):
    return MySQLdb.escape_string(string)

class DBError(Exception):
    """ Generic Database Exception """
    pass

class DBExpander:
    """ A utility class for interpolating into the query string.

    This class implements the correct interpolation so that %s is not escaped and %r is escaped in the mysql interpolation.

    @Note: We cant use the MySQLdb native interpolation because it has a brain dead way of interpolating - it always escapes _ALL_ parameters and always adds quotes around anything. So for example:

    >>> MySQLdb.execute('select blah from %s where id=%r',table,id)

    Does not work as it should, since the table name is always enclosed in quotes which is incorrect.
    """
    def __init__(self,string):
        self.string = str(string)

    def __str__(self):
        return self.string

    def __repr__(self):
        return "'%s'"% escape(self.string)

class PyFlagCursor(MySQLdb.cursors.SSDictCursor):
    """ This cursor combines client side and server side result storage.

    We store a limited cache of rows client side, and fetch rows from
    the server when needed.
    """
    ignore_warnings = False
    
    def __init__(self, connection):
        MySQLdb.cursors.SSDictCursor.__init__(self, connection)
        self.py_row_cache = []
        ## Maximum size of client cache
        self.py_cache_size = 10
        self._last_executed = None

        ## By default queries are allowed to take a long time
        self.timeout = 3600

    def kill_connection(self, what=''):
        dbh = DBO()
        try:
            dbh.execute("kill %s %s" % (what,self.connection.thread_id()))
        except:
            pass

    def execute(self,string):
        self.py_row_cache = []
        self.py_cache_size = 10
        self._last_executed = string

        def cancel():
            pyflaglog.log(pyflaglog.WARNINGS, "Killing query in thread %s because it took too long" % self.connection.thread_id())
            self.kill_connection('query')
            
        t = threading.Timer(self.timeout, cancel)
        t.start()
        try:
            MySQLdb.cursors.SSDictCursor.execute(self,string)
        finally:
            t.cancel()
            t.join()
            pass

    def fetchone(self):
        """ Updates the row cache if needed otherwise returns a single
        row from it.
        """
        self._check_executed()
        if len(self.py_row_cache)==0:
            self.py_row_cache = list(self._fetch_row(self.py_cache_size))

        try:
            result = self.py_row_cache.pop(0)
            self.rownumber = self.rownumber + 1
            return result
        except IndexError:
            return None

    def close(self):
        self.connection = None

    def _warning_check(self):
        """ We need to override this because for some cases it issues
        a SHOW WARNINGS query. Which will raise an 'out of sync
        error' when we operate in SS. This is a most sane approach -
        when warnings are detected, we simply try to drain the
        resultsets and then read the warnings.
        """
        if self.ignore_warnings: return
        
        ## We have warnings to show
        if self._warnings:
            last_executed = self._last_executed

            results = list(self._fetch_row(1000))
            if len(results)<1000:
                self.execute("SHOW WARNINGS")
                while 1:
                    a=self.fetchone()
                    if not a: break
                    pyflaglog.log(pyflaglog.DEBUG,"Mysql warnings: query %r: %s" % (last_executed[:500],a))
                else:
                    pyflaglog.log(pyflaglog.DEBUG,"Mysql issued warnings but we are unable to drain result queue")

            ## If we have strict SQL we abort on warnings:
            if config.STRICTSQL:
                raise DBError(a)

            self.py_row_cache.extend(results)

class Pool(Queue):
    """ Pyflag needs to maintain multiple simulataneous connections to
    the database sometimes.  To avoid having to reconnect on each
    occasion, we keep a pool of connection objects. This allows
    connections to be placed back in the pool after DBO destruction
    for reuse by other DBOs.
    
    Note that since we use the Queue class we are thread safe
    here. I.e. we guarantee that the same connection will never be
    shared by two different threads.

    Note that connections are not placed back on the queue until all
    references to them are GCed. This means that we still need to be
    relatively concervative in creating new DBOs and prefer to reuse
    existing ones whenever possible (of course we need to create new
    ones if the connection state is important (e.g. iterating through
    a resultset while doing some different db activity).
    """
    def __init__(self, case, poolsize=0):
        self.case=case
        self.indexes = {}
        Queue.__init__(self, poolsize)

    def get(self, block=1):
        """Get an object from the pool or a new one if empty."""
        try:
            result=self.empty() and self.connect() or Queue.get(self, block)
            return result
        except Empty:
            return self.connect()

    def connect(self):
        """ Connect specified case and return a new connection handle """
        global db_connections
        db_connections +=1
        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "New Connection to DB. We now have %s in total" % (db_connections, ))
        
        case=self.case
        try:
            #Try to connect over TCP
            if config.STRICTSQL:
                dbh = MySQLdb.Connect(user = config.DBUSER,
                                      passwd = config.DBPASSWD,
                                      db = case,
                                      host=config.DBHOST,
                                      port=config.DBPORT,
                                      cursorclass=PyFlagCursor,
                                      sql_mode="STRICT_ALL_TABLES",
                                      conv = conv,
                                      use_unicode = False,
                                      #charset='latin1'
                                      )
            else:
                dbh = MySQLdb.Connect(user = config.DBUSER,
                                      passwd = config.DBPASSWD,
                                      db = case,
                                      host=config.DBHOST,
                                      port=config.DBPORT,
                                      cursorclass=PyFlagCursor,
                                      conv = conv,
                                      use_unicode = False,
                                      #charset = 'latin1'
                                      )
                
            mysql_bin_string = "%s -f -u %r -p%r -h%s -P%s" % (config.MYSQL_BIN,config.DBUSER,config.DBPASSWD,config.DBHOST,config.DBPORT)
        except Exception,e:
            print e
            ## or maybe over the socket?
            ##  The following is used for debugging to ensure we dont
            ##  have any SQL errors:
            if config.STRICTSQL:
                dbh = MySQLdb.Connect(user = config.DBUSER,
                                      passwd = config.DBPASSWD,
                                      db = case,
                                      unix_socket = config.DBUNIXSOCKET,
                                      sql_mode="STRICT_ALL_TABLES",
                                      cursorclass=PyFlagCursor,
                                      conv = conv,
                                      use_unicode = False,
                                      #charset='latin1'
                                      )
            else:
                dbh = MySQLdb.Connect(user = config.DBUSER,
                                      passwd = config.DBPASSWD,
                                      db = case,
                                      unix_socket = config.DBUNIXSOCKET,
                                      cursorclass=PyFlagCursor,
                                      conv = conv,
                                      use_unicode = False,
                                      #charset='latin1'
                                      )

            mysql_bin_string = "%s -f -u %r -p%r -S%s" % (config.MYSQL_BIN,config.DBUSER,config.DBPASSWD,config.DBUNIXSOCKET)

        return (dbh,mysql_bin_string)

## This store stores information about indexes
import Store
DBIndex_Cache=Store.Store()

global DBH
DBH={}

class DBO:
    """ Class controlling access to DB handles

    We implement a pool of connection threads. This gives us both worlds - the advantage of reusing connection handles without running the risk of exhausting them, as well as the ability to issue multiple simultaneous queries from different threads.

    @cvar DBH: A dict containing cached database connection objects
    @cvar lock: an array of unique locks that each thread must hold before executing new SQL
    @ivar temp_tables: A variable that keeps track of temporary tables so they may be dropped when this object gets gc'ed
    """
    temp_tables = []
    
    def __init__(self,case=None):
        """ Constructor for DB access. Note that this object implements database connection caching and so should be instantiated whenever needed. If case is None, the handler returned is for the default flag DB

        @arg case: Case database to connect to. May be None in which case it connects to the default flag database
        """
        if not case:
            case = config.FLAGDB

        try:
            self.dbh,self.mysql_bin_string=DBH[case].get()
        except KeyError:
            DBH[case] = Pool(case)
            self.dbh,self.mysql_bin_string=DBH[case].get()
            
        self.temp_tables = []
        self.case = case
        self.cursor = self.dbh.cursor()
                
    def clone(self):
        """ Returns a new database object for the same case database """
        return self.__class__(self.case)

    def execute(self,query_str,params=None):
        """  SQL execution method.
               This functions executes the SQL in this object's cursor context. the query must be given as a string with with %s or %r escape characters, and the correct number of strings in the params list.

               @note: Just as a reminder - using %r will escape the corresponding string in a manner that is adequate for mysql, it will also automatically insert quotes around the string. On the other hand using %s will not escape the strings.
               
               >>> a.execute('select * from %s where id=%r' , ('table','person'))
                       
               @arg query_str: A format string with only %r and %s format sequences
               @arg params: A list of strings which will be formatted into query_str. If there is only one format string and the programmer is truely lazy, a string is ok. """

        if params==None:
            string = query_str
        else:
            try:
                ## We only do this if the params are truely iteratable
                params.__getattribute__('__iter__')

                ## Hopefully this does not bear a huge performance overhead???
                params = tuple([ DBExpander(i) for i in params])
            except AttributeError,e:
                params=(DBExpander(params),)

            string= query_str % params
        try:
            ## The following decode is required to go around MySQLdb's
            ## stupid unicode crap - this has just recently been
            ## introduced:
            self.cursor.execute(string.decode('latin1'))
        #If anything went wrong we raise it as a DBError
        except Exception,e:
            str = "%s" % e
            if 'Commands out of sync' in str or 'server has gone away' in str or 'Lost connection' in str:
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG,
                            "Got DB Error: %s, %s" % (str,self.dbh))

                ## We terminate the current connection and reconnect
                ## to the DB
                self.cursor.kill_connection()
                del self.dbh
                
                global db_connections
                db_connections -=1

                self.dbh,self.mysql_bin_string=DBH[self.case].connect()
                self.cursor = self.dbh.cursor()

                ## Redo the query with the new connection - if we fail
                ## again, we just raise - otherwise we risk running
                ## into recursion issues:
                return self.cursor.execute(string.decode('latin1'))
                
            elif not str.startswith('Records'):
                raise DBError,e

    def cached_execute(self, sql, limit=0, length=50):
        """ Execute the query_str with params inside the pyflag Cache system.

        PyFlag often needs to execute the same query with different
        limit clauses - for example when paging a table in the
        GUI. Since MySQL applies the limits after perfomring the
        query, and the MySQL query cache is applied on the results,
        MySQL ends up redoing the same query for each page. If the
        query is expensive this could significantly delay paging.

        This function implements a cache in the db for especially
        complex queries.
        """
        ## Expire the cache if needed
        self.execute("select * from sql_cache where timestamp < date_sub(now(), interval %r minute)", config.DBCACHE_AGE)
        tables = [ row['id'] for row in self]
        for table_id in tables:
            self.execute("delete from sql_cache where id = %r" , table_id)
            self.execute("drop table if exists cache_%s" , table_id)

        ## Try to find the query in the cache. We need a cache which
        ## covers the range we are interested in:
        self.execute("""select * from sql_cache where query = %r and `limit` <= %r and `limit` + `length` >= %r""", (sql, limit, limit + length))
        row = self.fetch()
        
        if row:            
            ## Return the query:
            self.execute("update sql_cache set timestamp=now() where id=%r ",
                         row['id'])

            cache_limit = row['limit']
            return self.execute("select * from cache_%s limit %s,%s",
                                (row['id'], limit - cache_limit, length))

        ## Query is not in cache - create a new cache entry: FIXME -
        ## this could race.  We create the cache centered on the
        ## required range - this allows quick paging forward and
        ## backwards.
        lower_limit = max(limit - config.DBCACHE_LENGTH/2,0)

        ## Determine which tables are involved:
        self.execute("explain %s", sql)
        tables = [ row['table'] for row in self ]
        if not tables or tables[0]==None:
            return self.execute(sql)

        self.insert('sql_cache',
                    query = sql, _timestamp='now()',
                    tables = ",%s," % ','.join(tables),
                    limit = lower_limit,
                    length = config.DBCACHE_LENGTH,
                    _fast = True
                    )

        ## Create the new table
        id = self.autoincrement()
        
        self.execute("create table cache_%s %s limit %s,%s",
                     (id,sql, lower_limit, config.DBCACHE_LENGTH))
        
        return self.execute("select * from cache_%s limit %s,%s",
                            (id,limit - lower_limit,length))

        ## Did we take too long? If we didnt take very long, we lose
        ## the table and mark the query as uncachable for a
        ## while. (basically its quicker to just do the query than to
        ## cache it).

        ## Return the cursor back:

    def commit(self):
        self.cursor.connection.commit()

    def __iter__(self):
        return self

    def invalidate(self,table):
        """ Invalidate all copies of the cache which relate to this table """
        self.execute("select id from sql_cache where tables like '%%,%s,%%'",table)
        ids = [row['id'] for row in self]
        for id in ids:
            self.execute("drop table if exists cache_%s", id)
            self.execute("delete from sql_cache where id=%r", id)

    def _calculate_set(self, **fields):
        """ Calculates the required set clause from the fields provided """
        tmp = []
        sql = []
        for k,v in fields.items():
            if k.startswith("_"):
                sql.append('`%s`=%s')
                k=k[1:]
            else:
                sql.append('`%s`=%r')
                
            tmp.extend([k,v])
            
        return (','.join(sql), tmp)

    def update(self, table, where='1', _fast=False, **fields):
        sql , args = self._calculate_set(**fields)
        sql = "update %s set " + sql + " where %s "
        ## We are about to invalidate the table:
        if not _fast:
            self.invalidate(table)
        self.execute(sql, [table,] + args + [where,])

    def drop(self, table):
        self.invalidate(table)
        self.execute("drop table if exists %s", table)

    def delete(self, table, where):
        sql = "delete from %s where %s"
        ## We are about to invalidate the table:
        self.invalidate(table)
        self.execute(sql, (table, where))        

    def insert(self, table, _fast=False, **fields):
        """ A helper function to make inserting a little more
        readable. This is especially good for lots of fields.

        Special case: Normally fields are automatically escaped using
        %r, but if the field starts with _, it will be inserted using
        %s and _ removed.

        Note that since the introduction of the cached_execute
        functionality it is mandatory to use the insert, mass_insert
        or update methods to ensure the cache is properly invalidated
        rather than use raw SQL.
        """
        sql , args = self._calculate_set(**fields)
        sql = "insert into %s set " + sql
        ## We are about to invalidate the table:
        if not _fast:
            self.invalidate(table)
        self.execute(sql, [table,]+args)
                    
    def mass_insert_start(self, table, _fast=False):
        self.mass_insert_cache = {}
        self.mass_insert_table = table
        self.mass_insert_row_count = 0
        self.mass_insert_fast = _fast
    
    def mass_insert(self, **columns):
        """ Starts a mass insert operation. When done adding rows, call commit_mass_insert to finalise the insert.
        """
        for k,v in columns.items():
            ## _field means to pass the field 
            if k.startswith('_'):
                k=k[1:]
            else:
                v="'%s'" % escape(v.__str__())
                
            try:
                self.mass_insert_cache[k][self.mass_insert_row_count]=v
            except:
                self.mass_insert_cache[k]={ self.mass_insert_row_count: v}

        self.mass_insert_row_count+=1
        if self.mass_insert_row_count > 100:
            self.mass_insert_commit()
            self.mass_insert_start(self.mass_insert_table, _fast=self.mass_insert_fast)

    def mass_insert_commit(self):
        try:
            keys = self.mass_insert_cache.keys()
        except AttributeError:
            ## We called commit without start
            return

        if len(keys)==0: return
        
        args = []
        values = []
        for i in range(self.mass_insert_row_count):
            for k in keys:
                try:
                    args.append(self.mass_insert_cache[k][i])
                except KeyError:
                    args.append('NULL')

            values.append(",".join(["%s"] * len(keys)))

        sql = "insert ignore into `%s` (%s) values (%s)" % (self.mass_insert_table,
                                                   ','.join(["`%s`" % c for c in keys]),
                                                   "),(".join(values))
        if not self.mass_insert_fast:
            self.invalidate(self.mass_insert_table)
            
        self.execute(sql,args)

        ## Ensure the cache is now empty:
        self.mass_insert_start(self.mass_insert_table,
                               _fast=self.mass_insert_fast)

    def autoincrement(self):
        """ Returns the value of the last autoincremented key """
        return self.cursor.connection.insert_id()

    def next(self):
        """ The db object supports an iterator so that callers can simply iterate over the result set.

        Each iteration returns a hash as obtained from fetch. """
        result = self.fetch()
        if not result: raise StopIteration

        return result

    def fetch(self):
        """ Returns the next cursor row as a dictionary.

        It is encouraged to use this function over cursor.fetchone to ensure that if columns get reordered in the future code does not break. The result of this function is a dictionary with keys being the column names and values being the values """
        return self.cursor.fetchone()
    
    def check_index(self, table, key, length=None):
        """ This checks the database to ensure that the said table has an index on said key.

        If an index is missing, we create it here, so we always ensure an index exists once we return. """
        ## We implement a local cache to ensure that we dont hit the
        ## DB all the time:
        cache_key = "%s:%s" % (table,key)
        try:
            ## These should be the fields with the indexes on them:
            fields = DBIndex_Cache.get(cache_key)
        except KeyError:
            self.execute("show index from `%s`",table)
            fields = [ row['Key_name'] for row in self]
            DBIndex_Cache.put(fields, key=cache_key)

        ## Now fields is an array stored in the Store - we can append
        ## to it directly because we also hold a reference here and it
        ## will affect the next value gotten from the Store:
        if key not in fields:
            if length:
                sql="(`%s`(%s))" % (key,length)
            else:
                sql="(`%s`)" % (key) 

            pyflaglog.log(pyflaglog.DEBUG,"Oops... No index found in table %s on field %s - Generating index, this may take a while" %(table,key))
            ## Index not found, we make it here:
            self.execute("Alter table `%s` add index%s",(table,sql))

            ## Add to cache:
            fields.append(key)
        
    def get_meta(self, property, table='meta',**args):
        """ Returns the value for the given property in meta table selected database

        Only returns first value """
        self.execute("select value from `%s` where property=%r",
                     (table,property))
        row = self.fetch()

        if row != None:
            return row['value']

        return None

    def set_meta(self, property,value, table='meta',force_create=False, **args):
        """ Sets the value in meta table
        """
        prevvalue = self.get_meta(property, table, **args)
        if (prevvalue != None) and (not force_create):
            self.execute("update `%s` set property=%r,value=%r where property=%r",
                         (table, property,value, property))
        else:
            self.execute("insert into `%s` set property=%r,value=%r", (table, property,value))

    def MakeSQLSafe(self,string):
        """ Returns a version of string, which is SQL safe.

        String will be converted to a form which is suitable to be used as the name of a table for example.
        """
        import re
        return re.sub('[^a-zA-Z0-9]','_',string)

    def get_temp(self):
        """ Gets a unique name for a table.

        This can be used to create temporary tables - since flag is multi-threaded, normal mysql temporary tables remain within the same thread. Use this function to get names for temporary tables which can be shared between all threads.

        Note that each DBO object maintains a list of temporary tables, and drops those when gc'd so users of this class do not need to clean temporary tables up.

        The result from this function is guaranteed to not exist - so a create temporary table (or even a create table) call should work.
        """
        thread_name = threading.currentThread().getName()
        thread_name = thread_name.replace('-','_')
        count = 1

        while 1:
            test_name = "temp%s_%u" % (thread_name,count)
            ## Check if the table already exists:
            self.execute('show table status like %r',test_name)
            rs = self.cursor.fetchone()
            if not rs:
                self.temp_tables.append(test_name)
                return test_name

            count+=1

    def __del__(self):
        """ Destructor that gets called when this object is gced """
        try:
            self.cursor.ignore_warnings = True
            for i in self.temp_tables:
                self.drop(i)

            ## Ensure that our mass insert case is comitted in case
            ## users forgot to flush it:
            self.mass_insert_commit()
            self.cursor.ignore_warnings = False

            DBH[self.case].put((self.dbh, self.mysql_bin_string))
        except (TypeError,AssertionError):
            pass

    def MySQLHarness(self,client):
        """ A function to abstact the harness pipes for all programs emitting SQL.

        @arg client: A string of the command to shell out to.
        @arg dbh: The database handle to use.
        """
        if not client.startswith('/'):
            client = "%s/%s" % (config.FLAG_BIN, client)
            
        pyflaglog.log(pyflaglog.DEBUG, "Will shell out to run %s " % client)

        import os
        p_mysql=os.popen("%s -D%s" % (self.mysql_bin_string,self.case),'w')
        p_client=os.popen(client,'r')
        while 1:
            data= p_client.read(1000)
            if not data: break
            p_mysql.write(data)

        if not p_client.close():
            pass
    #        raise IOError("Client program exited with a non-zero exit code")
        if not p_mysql.close():
            pass
    #        raise IOError("MySQL client exited with an error")

## Unit Tests
import unittest

class DBOTest(unittest.TestCase):
    def test01validinstall(self):
        """ Test to make sure we can locate the pyflag default database """
        dbh = DBO(None)
        dbh.execute("show tables")
        tables = [ row.values()[0] for row in dbh ]
        self.assert_( 'meta' in tables)

    def test02TemporaryTables(self):
        """ Test to make sure DBO temporary tables get cleaned up after handle gc """
        dbh = DBO(None)
        tablename = dbh.get_temp()
        dbh.execute("create table %s(field1 text)", tablename)
        dbh.execute("select * from %s", tablename)
        result = [ row['field1'] for row in dbh ]
        self.assertEqual(result, [])

        dbh2 = DBO(None)
        tablename2 = dbh2.get_temp()
        self.assert_(tablename2 != tablename)

        del dbh
        def ExceptionTest():
            dbh = DBO(None)
            dbh.execute("select * from %s", tablename)

        self.assertRaises(DBError, ExceptionTest)

    def createTestTable(self, dbh):
        tablename = dbh.get_temp()
        dbh.execute("create table %s(field1 int)", tablename)

        for i in range(0,10):
            dbh.insert(tablename, field1=i)

        return tablename

    def test03ServerSideReconnect(self):
        """ Test to ensure that dbhs reconnect after an aborted server side connection """
        dbh = DBO(None)
        tablename = self.createTestTable(dbh)

        dbh.execute("select * from %s", tablename)
        result = [ row['field1'] for row in dbh if row['field1'] < 5 ]
        self.assertEqual(result, range(0,5))

    def test04SlowQueryAbort(self):
        """ Test to make sure slow queries are aborted """
        dbh = DBO(None)

        #Make the timeout 1 second for testing
        dbh.cursor.timeout = 1

        dbh.execute("select sleep(2) as sleep")
        result = dbh.fetch()['sleep']
        self.assertEqual(result, 1)

    def test05MassInsert(self):
        """ Test the mass insert mechanism """
        dbh = DBO(None)
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
        dbh=DBO()
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

if __name__=='__main__':
    suite = unittest.makeSuite(DBOTest)
    unittest.TextTestRunner(verbosity=2).run(suite)
