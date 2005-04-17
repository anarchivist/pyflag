# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.76 Date: Sun Apr 17 21:48:37 EST 2005$
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

""" Module for handling Log Files """
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.logging as logging
import pickle
import plugins.LogAnalysis.Whois as Whois

class Log:
    """ This base class abstracts Loading of log files.

    Log files are loaded through the use of log file drivers. These
    drivers extend this class, possibly providing new methods for form
    and field, and potentially even read_record.
    """
    datafile = ()
    num_fields = 0
    def __init__(self,variable,query):
        """ Load the log file.

        @arg variable: Name of query variable that carries the name of the file. Note that this may be an array for users to specify a number of files.
        @arg query: The query object.
        """
        self.datafile = query.getarray(variable)
        if self.datafile==():
            raise KeyError("No variable %s" % variable)
        self.query = query

        self.num_fields = 0
        ## If this object was called with an unknown number of fields we work it out. Note that we may not have all the consecutive fields defined:
        for k in query.keys():
            if k.startswith('field'):
                number=int(k[len('field'):])
                if number>self.num_fields:
                    self.num_fields=number
                    
        self.num_fields+=1

        self.set_fields()
        self.set_types()
        self.set_indexes()
    
    def read_record(self, ignore_comment = True):
        """ Generates records.

        This can handle multiple files as provided in the constructor.
        """
        for file in self.datafile:
            fd=open(file,'r')
            for line in fd:
                if line.startswith('#') and ignore_comment:
                    continue
                else:
                    yield line

    def set_fields(self):
        """ set the field names from the query, order is important """
        self.fields=[]
        for i in range(0,self.num_fields):
            try:
                assert(len(self.query['field%u'%i])>0)
                self.fields.append(self.query['field%u'%i])
            except (KeyError,AssertionError):
                self.query['field%u' % i ] = 'ignore'
                self.fields.append('ignore')

    def set_types(self):
        """ set the field types from the query, order is important """
        self.types=[]
        for i in range(0,self.num_fields):
            try:
                self.types.append(self.query['type%u'%i])
            except KeyError:
                self.query['type%u' % i ] = 'varchar(250)'
                self.types.append('varchar(250)')

    def set_indexes(self):
        """ which fields require indexes """
        self.indexes=[]
        for i in range(0,self.num_fields):
            if self.query.has_key('index%u'%i):
                self.indexes.append(True)
            else:
                self.indexes.append(False)

    def load(self,dbh,tablename, rows = None):
        """ Loads the specified number of rows into the database.

        @arg dbh: A database handle to use
        @arg table_name: A table name to use
        @arg rows: number of rows to upload - if None , we upload them all
        @return: A generator that represents the current progress indication.
        """
        ## First we create the table:
        cols = []
        insert_sql = []
        field_indexes = []
        count=0
        for i in range(len(self.fields)):
            if self.fields[i]!='' and self.fields[i] != 'ignore':
                field_indexes.append(i)
                type = types[self.types[i]]()
                cols.append("`%s` %s" % (self.fields[i], type.type ))
                insert_sql.append(type.sql_in)

        dbh.execute("CREATE TABLE IF NOT EXISTS %s (id int auto_increment,%s,key(id))" % (tablename,",".join(cols)))
        ## prepare the insert string
        insert_str = "INSERT INTO "+tablename+" values(Null,"+','.join(insert_sql)+")"

        for fields in self.get_fields():
            count += 1
            fields = [ fields[i] for i in range(len(fields)) if i in field_indexes ]
            try:
                ## We insert into the table those fields that are not ignored:
                dbh.execute(insert_str, fields )
            except DB.DBError,e:
                logging.log(logging.WARNINGS,"Warning: %s" % e)
            except TypeError:
                logging.log(logging.WARNINGS,"Unable to load line into table SQL: %s Data: %s" % (insert_str,fields))
                continue

            yield "Uploaded %s rows" % count

            if rows and count > rows:
                break
            
        ## Now create indexes on the required fields
        for field_number in range(len(self.fields)):
            index = types[self.types[field_number]].index
            if self.indexes[field_number] and index:
                ## interpolate the column name into the index declaration
                index = index % self.fields[field_number]
                dbh.execute("Alter table %s add index(%s)" % (tablename,index))
                yield "Created index on %s " % index
                
        ## Add the IP addresses to the whois table if required:
        dbh.execute("create table if not exists `whois` (`IP` INT UNSIGNED NOT NULL ,`country` VARCHAR( 4 ) NOT NULL ,`NetName` VARCHAR( 50 ) NOT NULL ,`whois_id` INT NOT NULL ,PRIMARY KEY ( `IP` )) COMMENT = 'A local case specific collection of whois information'")
        for field_number in range(len(self.fields)):
            if self.types[field_number] == 'IP Address':
                dbh2=dbh.clone()
                #Handle for the pyflag db
                dbh_pyflag = DB.DBO(None)
                yield "Doing Whois lookup of column %s" % self.fields[field_number]
                
                dbh.execute("select `%s` as IP from %s group by `%s`", (
                    self.fields[field_number],
                    tablename,
                    self.fields[field_number]))
                for row in dbh:
                    whois_id = Whois.lookup_whois(row['IP'])
                    dbh_pyflag.execute("select * from whois where id=%r",(whois_id))
                    row2=dbh_pyflag.fetch()
                    try:
                        dbh2.execute("insert into whois set IP=%r,country=%r,NetName=%r,whois_id=%r",(
                            row['IP'],
                            row2['country'],
                            row2['netname'],
                            whois_id))
                    except DB.DBError:
                        pass
                                
                    
    def pickle(self):
        """ Pickles this object

        Note that Log objects are asked to pickle themselves. However
        the base class uses a generic pickler. If you need to do
        something really special for pickling or unpickling, you may
        override this method.
        """
        ## Clear stuff that is not relevant
        self.datafile = None
        self.query = None
        return pickle.dumps(self)

    def draw_type_selector(self,result):
        """ Draws an interactive GUI allowing users to specify field names, types and choice of indexes """
        result.start_table()
        result.ruler()
        tmp = result.__class__(result)
        tmp.heading("Step 4:")
        result.row(tmp,"Assign field names and Types to each field")
        result.ruler()
        result.end_table()

        ## This part creates a GUI allowing users to assign names,
        ## types and indexes to columns
        result.start_table(border=1,bgcolor='lightgray')
        count = 0
        self.num_fields=0
        for fields in self.get_fields():
            count +=1                
            result.row(*fields)
            ## Find the largest number of columns in the data
            if len(fields)>self.num_fields:
                self.num_fields=len(fields)
            if count>3: break

        ## If we have more columns we set their names,types and
        ## indexes from the users data.
        self.num_fields=len(fields)
        self.set_fields()
        self.set_types()
        self.set_indexes()

        field = []
        type = []
        index = []
        ## Now we create the input elements:
        for i in range(len(self.fields)):
            field_ui = result.__class__(result)
            type_ui = result.__class__(result)
            index_ui =  result.__class__(result)
            
            field_ui.textfield('','field%u' % i)
            type_selector(type_ui,"type%u" % i)
            index_ui.checkbox('Add Index?','index%u'%i,'yes')
            field.append(field_ui)
            type.append(type_ui)
            index.append(index_ui)

        result.row(*field)
        result.row(*type)
        result.row(*index)
                
#plugins = {"Simple": SimpleLog,"CSV": CSVLog, "IIS Log":IISLog}

def get_loader(name,datafile):
    """ lookup and unpickle log object from the database, return loader object

    We also initialise the object to the datafile list of filenames to use.
    """
    dbh = DB.DBO(config.FLAGDB)
    log=pickle.loads(dbh.get_meta('log_preset_%s' % name))
    log.datafile = datafile
    return log
    
def store_loader(log, name):
    """ pickle and save given loader into the database """
    dbh = DB.DBO(config.FLAGDB)
    dbh.execute('INSERT INTO meta set property="log_preset", value=%r' % name)
    print "%s" % log.fields
    dbh.execute('INSERT INTO meta set property="log_preset_%s", value=%r' % (name,log.pickle()))

class Type:
    """ This class represents translations between the way a column is stored in the database and the way it is displayed.

    This is used by the log driver to store the data in the most efficient format in the database.
    @cvar type: The database type this column should be created with.
    """
    type = None
    sql_in="%r"
    sql_out = "`%s`"
    index = "%s"
    
class VarType(Type):
    type = "varchar(250)"

class IntType(Type):
    type = "int"

class DateTimeType(Type):
    type = "datetime"

class TextType(Type):
    type = "text"
    index=None

class IPType(Type):
    """ IP addresses should be stored in the database as ints, but displayed in dot notation """
    type = "int unsigned"
    sql_in= "INET_ATON(%r)"
    sql_out= "INET_NTOA(`%s`)"
    
types = {
    'varchar(250)': VarType,
    'int': IntType,
    'datetime': DateTimeType,
    'text': TextType,
    'IP Address': IPType
    }

def type_selector(result, name):
    result.const_selector('',name, types.keys(), types.keys())
