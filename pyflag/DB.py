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
#  Version: FLAG  $Name:  $ $Date: 2004/10/26 00:02:58 $
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
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.logging as logging
import time,types
import threading

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
        return "'%s'"% MySQLdb.escape_string(self.string)

class DBO:
    """ Singlton class controlling access to DB handles

    We need to be careful here since the mysql library is not multi-threaded (This comment is no longer true, but we still maintain locks just in case we are running single threaded libraries). We must ensure that every thread obtains a unique lock on the connection object prior to issuing exec calls.
    @cvar DBH: A dict containing cached database connection objects
    @cvar lock: the unique lock that each thread must hold before executing new SQL
    @ivar temp_tables: A variable that keeps track of temporary tables so they may be dropped when this object gets gc'ed
    """
    DBH = {}
    temp_tables = []
    
    def __init__(self,case):
        """ Constructor for DB access. Note that this object implements database connection caching and so should be instantiated whenever needed. If case is None, the handler returned is for the default flag DB

        @arg case: Case database to connect to. May be None in which case it connects to the default flag database
        """
        ## Locking is done per object - not per class.
        self.lock = threading.Lock()
        if not case:
            case = config.FLAGDB
        
        if not DBO.DBH.has_key(case):
            ## are we using the embedded server? This is experimental embedded server stuff - commented out until embedded server stabilizes a bit. (MC)
##            try:
##                MySQLdb.server_init(args=['python','--datadir=/tmp/mysql/','--log=/tmp/mysql.log'])
##            except Exception,e:
##                pass
##            
##            DBO.DBH[case] = MySQLdb.Connect(db=case)
            try:
                #Try to connect over TCP
                DBO.DBH[case] = MySQLdb.Connect(user = config.USER, passwd = config.PASSWD,db = case, host=config.HOST, port=config.PORT)
                DBO.mysql_bin_string = "%s -f -u %r -p%r -h%s -P%s" % (config.MYSQL_BIN,config.USER,config.PASSWD,config.HOST,config.PORT)
            except Exception,e:
                #or maybe over the socket?
                DBO.DBH[case] = MySQLdb.Connect(user = config.USER, passwd = config.PASSWD,db = case, unix_socket = config.UNIX_SOCKET)
                DBO.mysql_bin_string = "%s -f -u %r -p%r -S%s" % (config.MYSQL_BIN,config.USER,config.PASSWD,config.UNIX_SOCKET)

        self.cursor = DBO.DBH[case].cursor()
        self.temp_tables = []
        self.case=case

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

        if not params:
            string = query_str
        else:
            try:
                ## We only do this if the params are truely iteratable
                params.__getattribute__('__iter__')
            ## Hopefully this does not bear a huge performance overhead???
                params = tuple([ DBExpander(i) for i in params])
            except AttributeError:
                params=(DBExpander(params),)

            string= query_str % params
        #Try to obtain the lock:
        self.lock.acquire()
        try:
            try:
                self.cursor.execute(string,None)
            #We must release the lock even if we throw an exception
            finally:
                self.lock.release()
        #If anything went wrong we raise it as a DBError
        except Exception,e:
            str = "%s" % e
            if not str.startswith('Records'):
                raise DBError,e


    def commit(self):
        self.cursor.connection.commit()

    def __iter__(self):
        return self

    def next(self):
        """ The db object supports an iterator so that callers can simply iterate over the result set.

        Each iteration returns a hash as obtained from fetch. """
        result = self.fetch()
        if not result: raise StopIteration

        return result

    def fetch(self):
        """ Returns the next cursor row as a dictionary.

        It is encouraged to use this function over cursor.fetchone to ensure that if columns get reordered in the future code does not break. The result of this function is a dictionary with keys being the column names and values being the values """
        results = {}
        #acquire the lock for getting a row back
        self.lock.acquire()
        try:
            temp = self.cursor.fetchone()
            temp2=[]
            if temp:
                for i in temp:
                    try:
                        temp2.append(i.tostring())
                    except AttributeError:
                        temp2.append(i)
                        pass
                temp = temp2
                
        finally:
            self.lock.release()
            
        if not temp: return None
        
        column = 0
        for d in self.cursor.description:
            if results.has_key(d[0]): raise DBError, "Duplicate names in query heading"
            results[d[0]] = temp[column]
            column += 1

        return results

    def check_index(self, table, key, length=None):
        """ This checks the database to ensure that the said table has an index on said key.

        If an index is missing, we create it here, so we always ensure an index exists once we return. """
        self.execute("show index from `%s`",table)
        for row in self:
            if row['Key_name'] == key:
                ## We found an index we are looking for
                return

        if length:
            sql="(`%s`(%s))" % (key,length)
        else:
            sql="(`%s`)" % (key) 
        
        logging.log(logging.DEBUG,"Oops... No index found in table %s on field %s - Generating index, this may take a while" %(table,key))
        ## Index not found, we make it here:
        self.execute("Alter table `%s` add index%s",(table,sql))
        
    def get_meta(self, property):
        """ Returns the value for the given property in meta table selected database

        Only returns first value """
        self.execute("select value from meta where property=%r", property)
        row = self.fetch()
        if row:
            return row['value']
        return None

    def set_meta(self, property,value):
        """ Sets the value in meta table
        """
        self.execute("insert into meta set property=%r,value=%r", (property,value))
        return None

    def MakeSQLSafe(self,string):
        """ Returns a version of string, which is SQL safe.

        String will be converted to a form which is suitable to be used as the name of a table for example.
        """
        import re
        return re.sub('[^a-zA-Z0-9]','_',string)

    def get_temp(self):
        """ Gets a unique name for a table.

        This can be used to create temporary tables - since flag is multi-threaded, temporary tables remain within the same thread. Use this function to get names for temporary tables.

        Note that each DBO object maintains a list of temporary tables, and drops those when gc'd so users of this class do not need to clean temporary tables up.

        The result from this function is guaranteed to exist - so a create temporary table (or even a create table) call should work.
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
        for i in self.temp_tables:
            self.execute('drop table if exists %s',i)
            

    def MySQLHarness(self,client):
        """ A function to abstact the harness pipes for all programs emitting SQL.

        @arg client: A string of the command to shell out to.
        @arg dbh: The database handle to use.
        """
        if not client.startswith(config.FLAG_BIN):
            client = "%s/%s" % (config.FLAG_BIN, client)
            
        print "Will shell out to run %s " % client

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
