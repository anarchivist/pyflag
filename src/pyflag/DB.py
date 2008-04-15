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
#  Version: FLAG  $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
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
config = pyflag.conf.ConfObject()

import pyflag.pyflaglog as pyflaglog
import time,types
from Queue import Queue, Full, Empty
from MySQLdb.constants import FIELD_TYPE
import threading

## This store stores information about indexes
import Store
DBIndex_Cache=Store.Store()

db_connections=0

## Declare the configuration parameters we need here:
config.add_option("FLAGDB", default='pyflag',
                help="Default pyflag database name")

config.add_option("FLAG_BIN", default='/usr/bin/mysql',
                help="Location of the mysql client")

config.add_option("DBUSER", default='root',
                help="Username to connect to db with")

config.add_option("DBPASSWD", default=None,
                help="Password to connect to the database")

config.add_option("STRICTSQL", default=False, action='store_true',
                metavar = "true/false",
                help="database warnings are fatal")

config.add_option("DBHOST", default='localhost',
                help="database host to connect to")

config.add_option("DBPORT", default=3306, type='int',
                help="database port to connect to")

config.add_option("DBUNIXSOCKET", default="/var/run/mysqld/mysqld.sock",
                help="path to mysql socket")

config.add_option("MYSQL_BIN", default="/usr/bin/mysql",
                help="path to mysql socket")

config.add_option("DBCACHE_AGE", default=60, type='int',
                help="The length of time table searches remain cached")

config.add_option("DBCACHE_LENGTH", default=1024, type='int',
                help="Number of rows to cache for table searches")

config.add_option("MASS_INSERT_THRESHOLD", default=300, type='int',
                  help="Number of rows where the mass insert buffer will be flushed.")

config.add_option("TABLE_QUERY_TIMEOUT", default=60, type='int',
                  help="The table widget will timeout queries after this many seconds")


## This is the dispatcher for db converters
conv = {
    FIELD_TYPE.LONG: long,
    FIELD_TYPE.INT24: long,
    FIELD_TYPE.LONGLONG: long,
    FIELD_TYPE.TINY: int,
    FIELD_TYPE.SHORT: int,
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
    logged = True
    
    def __init__(self, connection):
        MySQLdb.cursors.SSDictCursor.__init__(self, connection)
        self.py_row_cache = []
        ## Maximum size of client cache
        self.py_cache_size = 10
        self._last_executed = None

        ## By default queries are allowed to take a long time
        self.timeout = 0

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

        if self.timeout:
            t = threading.Timer(self.timeout, cancel)
            t.start()
            try:
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, string)
                MySQLdb.cursors.SSDictCursor.execute(self,string)
            finally:
                t.cancel()
                t.join()
                pass
        else:
            if self.logged:
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, string)
            MySQLdb.cursors.SSDictCursor.execute(self,string)

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

    The pool maintains a cache of case parameters, which we get from
    the meta table. If these change, The cache needs to be expired.
    """
    def __init__(self, case, poolsize=0):
        self.case=case
        self.indexes = {}
        self._parameters = {}
        Queue.__init__(self, poolsize)

    def parameter(self, string):
        try:
            return self._parameters[string]
        except KeyError:
            dbh, tmp = self.get()
            c=dbh.cursor()

            c.execute("select value from meta where property = %r limit 1" % string)
            row = c.fetchone()
            try:
                return row['value']
            except:
                return None

    def parameter_flush(self):
        """ Expire the parameter cache """
        self._parameters = {}

    def put(self, dbh):
        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Returning dbh to pool %s" % self.case)
        Queue.put(self,dbh)

    def get(self, block=1):
        """Get an object from the pool or a new one if empty."""
        try:
            try:
                result=self.empty() and self.connect() or Queue.get(self, block)

                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Getting dbh from pool %s" % self.case)
            except Empty:
                result = self.connect()

##            ## Ensure the tz is adjusted appropriately:
##            tz=pool.parameter("TZ")
##            if result.tz != tz:
##                print "Adjusting TZ to %s" % tz
##                c=result.cursor()
##                c.execute("set time_zone = %r" % tz)
##                self.dbh.tz = tz

            return result
        except Exception,e:
            raise DBError("Unable to connect - does the DB Exist?: %s" % e)

    def connect(self):
        """ Connect specified case and return a new connection handle """
        global db_connections
        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "New Connection to DB %s. We now have %s in total" % (self.case,
                                                                                                     db_connections, ))
        
        args = dict(user = config.DBUSER,
                    db = self.case,
                    host=config.DBHOST,
                    port=config.DBPORT,
                    cursorclass=PyFlagCursor,
                    conv = conv,
                    use_unicode = False,
                    #charset='latin1'
                    )

        if config.DBPASSWD:
            args['passwd'] = config.DBPASSWD

        if config.STRICTSQL:
            args['sql_mode'] = "STRICT_ALL_TABLES"
            
        try:
            #Try to connect over TCP
            dbh = MySQLdb.Connect(**args)

            mysql_bin_string = "%s -f -u %r -p%r -h%s -P%s" % (config.MYSQL_BIN,config.DBUSER,config.DBPASSWD,config.DBHOST,config.DBPORT)
        except Exception,e:
            ## or maybe over the socket?
            ##  The following is used for debugging to ensure we dont
            ##  have any SQL errors:
            args['unix_socket'] = config.DBUNIXSOCKET
            del args['host']
            del args['port']

            dbh = MySQLdb.Connect(**args)
            mysql_bin_string = "%s -f -u %r -p%r -S%s" % (config.MYSQL_BIN,config.DBUSER,config.DBPASSWD,config.DBUNIXSOCKET)

        db_connections +=1
        c=dbh.cursor()
        c.execute("set autocommit=1")

        ## Make sure we record the TZ:
        dbh.tz = None
        return (dbh,mysql_bin_string)

class DBO:
    """ Class controlling access to DB handles

    We implement a pool of connection threads. This gives us both worlds - the advantage of reusing connection handles without running the risk of exhausting them, as well as the ability to issue multiple simultaneous queries from different threads.

    @cvar DBH: A store containing cached database connection objects
    @cvar lock: an array of unique locks that each thread must hold before executing new SQL
    @ivar temp_tables: A variable that keeps track of temporary tables so they may be dropped when this object gets gc'ed
    """
    temp_tables = []
    transaction = False
    ## This stores references to the pools
    DBH = Store.Store(max_size=10)

    def get_dbh(self, case):
        try:
            pool = self.DBH.get(case)
        except KeyError:
            pool = Pool(case)
            self.DBH.put(pool, key=case)
        
        self.dbh,self.mysql_bin_string=pool.get()
        ## Check if we need to adjust the timezone:
            
    def __init__(self,case=None):
        """ Constructor for DB access. Note that this object implements database connection caching and so should be instantiated whenever needed. If case is None, the handler returned is for the default flag DB

        @arg case: Case database to connect to. May be None in which case it connects to the default flag database
        """
        if not case:
            case = config.FLAGDB

        self.get_dbh(case)
        self.temp_tables = []
        self.case = case
        self.cursor = self.dbh.cursor()
        self.tranaction = False

    def start_transaction(self):
        self.execute("start transaction")
        self.tranaction = True

    def end_transaction(self):
        self.execute("commit")
        self.tranaction = False
        
    def clone(self):
        """ Returns a new database object for the same case database """
        return self.__class__(self.case)

    def execute(self,query_str, *params):
        """  SQL execution method.
               This functions executes the SQL in this object's cursor context. the query must be given as a string with with %s or %r escape characters, and the correct number of strings in the params list.

               @note: Just as a reminder - using %r will escape the corresponding string in a manner that is adequate for mysql, it will also automatically insert quotes around the string. On the other hand using %s will not escape the strings.
               
               >>> a.execute('select * from %s where id=%r' , ('table','person'))
                       
               @arg query_str: A format string with only %r and %s format sequences
               @arg params: A list of strings which will be formatted into query_str. If there is only one format string and the programmer is truely lazy, a string is ok. """
        try:
            params[0].__iter__
            params = params[0]
        except (AttributeError,IndexError):
            pass
            
        ## Hopefully this does not bear a huge performance overhead???
        params = tuple( DBExpander(i) for i in params )
        if len(params)>0:
            string = query_str % params
        else: string = query_str
        try:
            ## The following decode is required to go around MySQLdb's
            ## stupid unicode crap - this has just recently been
            ## introduced:
            self.cursor.execute(string.decode('latin1'))
        #If anything went wrong we raise it as a DBError
        except Exception,e:
            str = "%s" % e
            if     'cursor closed' in str or \
                   'Commands out of sync' in str or \
                   'server has gone away' in str or \
                   'Lost connection' in str:
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG,
                            "Got DB Error: %s" % (str))

                ## We terminate the current connection and reconnect
                ## to the DB
                pyflaglog.log(pyflaglog.DEBUG, "Killing connection because %s. Last query was %s" % (e,self.cursor._last_executed))
                                
                self.cursor.kill_connection()
                del self.dbh
                
                global db_connections
                db_connections -=1
                self.get_dbh(self.case)
                self.dbh.ignore_warnings = self.cursor.ignore_warnings
                
                self.cursor = self.dbh.cursor()

                ## Redo the query with the new connection - if we fail
                ## again, we just raise - otherwise we risk running
                ## into recursion issues:
                return self.cursor.execute(string.decode('latin1'))
                
            elif not str.startswith('Records'):
                raise DBError(e)

    def expire_cache(self):
        """ Expires the cache if needed """
        ## Expire the cache if needed
        self.start_transaction()
        try:
            self.execute("select * from sql_cache where timestamp < date_sub(now(), interval %r minute) for update", config.DBCACHE_AGE)
            ## Make a copy to maintain the cursor
            tables = [ row['id'] for row in self]
            for table_id in tables:
                self.execute("delete from sql_cache where id = %r" , table_id)
                self.execute("delete from sql_cache_tables where sql_id = %r" , table_id)
                self.execute("drop table if exists `cache_%s`" , table_id)
                
        finally:
            self.end_transaction()

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

        Note that races are controlled here by using a tranactional
        table to achieve row level locks.
        """
        self.expire_cache()
        self.start_transaction()
        ## Try to find the query in the cache. We need a cache which
        ## covers the range we are interested in: This will lock the
        ## row while we generate its underlying cache table:
        try:            
            self.execute("""select * from sql_cache where query = %r and `limit` <= %r and `limit` + `length` >= %r limit 1 for update""", (sql, limit, limit + length))
            row = self.fetch()
                
            if row and row['locked']:
                self.end_transaction()
                while 1:
                    self.execute("select locked from sql_cache where id=%r limit 1", row['id'])
                    row2 = self.fetch()
                    if row2 and row2['locked']==0: break
                    time.sleep(1)

            if row:            
                ## Return the query:
                self.execute("update sql_cache set timestamp=now() where id=%r ",
                             row['id'])

                cache_limit = row['limit']

                ## If we fail to return the table (probably because the
                ## cache table disappeared) we simply continue on to make
                ## a new one:
                try:
                    ## We need to commit the transaction before the
                    ## select because we dont want to drain the cursor
                    ## right now (More SS Crap):
                    self.end_transaction()
                    return self.execute("select * from cache_%s limit %s,%s",
                                        (row['id'], limit - cache_limit, length))
                except DBError,e:
                    print e
                    pass

            ## Query is not in cache - create a new cache entry: We create
            ## the cache centered on the required range - this allows
            ## quick paging forward and backwards.
            lower_limit = max(limit - config.DBCACHE_LENGTH/2,0)

            ## Determine which tables are involved:
            self.execute("explain %s", sql)
            tables = [ row['table'] for row in self ]
            
            if not tables or tables[0]==None:
                ## Release the lock on the row
                self.end_transaction()
                self.execute(sql)
                return 

            for t in tables:
                if t == None:
                    self.end_transaction()
                    self.execute(sql)
                    return

            self.insert('sql_cache',
                        query = sql, _timestamp='now()',
                        #tables = ",%s," % ','.join(tables),
                        limit = lower_limit,
                        length = config.DBCACHE_LENGTH,
                        locked = 1,
                        _fast = True
                        )

            ## Create the new table
            id = self.autoincrement()
            
            ## Store the tables in the sql_cache_tables:
            for t in tables:
                self.insert('sql_cache_tables',
                            sql_id = id,
                            table_name = t,
                            _fast = True)

            ## This is needed to flush the SS buffer (we do not want to go
            ## out of sync here..)
            self.fetch()

            ## This could take a little while on a loaded db:
            try:
                self.execute("create table cache_%s %s limit %s,%s",
                             (id,sql, lower_limit, config.DBCACHE_LENGTH))
                self.execute("update sql_cache set locked=0 where id=%r" , id)
            except Exception,e:
                print e
                ## Oops the table already exists (should not happen)
                self.execute("drop table `cache_%s`",id )
                self.execute("create table `cache_%s` %s limit %s,%s",
                             (id,sql, lower_limit, config.DBCACHE_LENGTH))
                self.execute("update sql_cache set locked=0 where id=%r" , id)
        except Exception,e:
            self.end_transaction()
            raise e

        ## This is a race which occurs sometimes????
        try:
            return self.execute("select * from cache_%s limit %s,%s",
                                (id,limit - lower_limit,length))
        except:
            return self.execute("%s limit %s,%s" %
                                (sql,lower_limit,length))

    def __iter__(self):
        return self

    def invalidate(self,table):
        """ Invalidate all copies of the cache which relate to this table """
        self.execute("start transaction")
        try:
            try:
                self.execute("select sql_id from sql_cache_tables where `table_name`=%r", table)
            except Exception, e:
                print e
                pass
            ids = [row['sql_id'] for row in self]
            for id in ids:
                self.execute("drop table if exists cache_%s", id)
                self.execute("delete from sql_cache where id=%r", id)
                self.execute("delete from sql_cache_tables where sql_id=%r", id)
        finally:
            self.end_transaction()

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
        self.execute("drop table if exists `%s`", table)

    def delete(self, table, where='0', _fast=False):
        sql = "delete from %s where %s"
        ## We are about to invalidate the table:
        if not _fast:
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
        sql = "insert into `%s` set " + sql
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
        if self.mass_insert_row_count > config.MASS_INSERT_THRESHOLD:
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
            
        self.execute(sql,*args)

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
        cache_key = "%s/%s" % (self.case,table)
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

            pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Oops... No index found in table %s on field %s - Generating index, this may take a while" %(table,key))
            ## Index not found, we make it here:
            self.execute("Alter table `%s` add index%s",(table,sql))

            ## Add to cache:
            fields.append(key)
        
    def get_meta(self, property, table='meta',**args):
        """ Returns the value for the given property in meta table selected database

        Only returns first value """
        self.execute("select value from `%s` where property=%r limit 1",
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
            self.invalidate(table)
            self.execute("update `%s` set property=%r,value=%r where property=%r",
                         (table, property,value, property))
        else:
            self.invalidate(table)
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
            test_name = "%s_%s%s" % (thread_name, int(time.mktime(time.gmtime())),count)
            ## Check if the table already exists:
            self.execute('show table status like %r',test_name)
            rs = [ r for r in self ]
            if not rs:
                self.temp_tables.append(test_name)
                return test_name
            
            count+=1

    def __del__(self):
        """ Destructor that gets called when this object is gced """
        try:
            try:
                self.cursor.ignore_warnings = True
                for i in self.temp_tables:
                    self.drop(i)
            except: pass

            if self.transaction:
                self.end_transaction()

            ## Ensure that our mass insert case is comitted in case
            ## users forgot to flush it:
            self.mass_insert_commit()
            self.cursor.ignore_warnings = False

            ##key = "%s/%s" % (self.case, threading.currentThread().getName())
            key = "%s" % (self.case)
            if self.DBH:
                pool = self.DBH.get(key)
                pool.put((self.dbh, self.mysql_bin_string))
                
        except (TypeError,AssertionError,AttributeError, KeyError),e:
            #print "dbh desctrucr: %s " % e
            pass
        except Exception,e:
            import FlagFramework
            
            print FlagFramework.get_bt_string(e)


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

