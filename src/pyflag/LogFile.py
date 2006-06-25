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
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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

def get_file(query,result):
    result.row("Select a sample log file for the previewer",stretch=False)
    tmp = result.__class__(result)
    tmp.filebox(target='datafile')
    result.row("Enter name of log file:",tmp)
    if query.has_key('datafile'):
        return True
    else:
        result.text("Please input a log file name\n",color='red')
        return False

def save_preset(query,result, log=None):
    result.textfield("name for preset:",'log_preset')
    if query.has_key('log_preset'):
        log.parse(query)
        log.store(query['log_preset'])
        query['finished']='yes'
        return True
    else:
        result.text("Please type a name for the preset.\n",color='red')
        return False

class Log:
    """ This base class abstracts Loading of log files.

    Log files are loaded through the use of log file drivers. These
    drivers extend this class, possibly providing new methods for form
    and field, and potentially even read_record.
    """
    def parse(self, query, datafile="datafile"):
        """ Parse all options from query and update ourselves.

        This may be done several times during the life of an
        object. We need to ensure that we completely refresh all data
        which is unique to our instance.
        """
        
    def __init__(self, case=None):
        self.dbh = DB.DBO(case)
        
    def form(self,query,result):
        """ This method will be called when the user wants to configure a new instance of us. IE a new preset """

    def reset(self, query):
        """ This is called to reset the log tables this log driver has created """

    def display_test_log(self,result,query):
        # try to load and display as a final test
        temp_table = self.dbh.get_temp()

        for a in self.load(temp_table,rows= 3):
            pass

        self.dbh.execute("select * from %s limit 1",temp_table)
        columns =[]
        names = []
        for d in self.dbh.cursor.description:
            names.append(d[0])
            try:
                type = self.types[self.fields.index(d[0])]
                columns.append(types[type].sql_out % "`%s`" % d[0])
            except ValueError:
                columns.append(d[0])

        result.ruler()
        tmp_final = result.__class__(result)
        tmp_final.table(columns=columns,names=names,links=[], table=temp_table, case=self.dbh.case, simple=True)
        result.row(tmp_final,bgcolor='lightgray',colspan=5)
    
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

    def load(self,tablename, rows = None):
        """ Loads the specified number of rows into the database.

        @arg table_name: A table name to use
        @arg rows: number of rows to upload - if None , we upload them all
        @return: A generator that represents the current progress indication.
        """
        ## First we create the table:
        cols = []
        insert_sql = []
        field_indexes = []
        row_cache = []
        cached_count = 0
        count=0
        
        for i in range(len(self.fields)):
            if self.fields[i]!='' and self.fields[i] != 'ignore':
                field_indexes.append(i)
                type = types[self.types[i]]()
                cols.append("`%s` %s" % (self.fields[i], type.type ))
                insert_sql.append(type.sql_in)

        self.dbh.execute("CREATE TABLE IF NOT EXISTS %s (id int auto_increment,%s,key(id))" % (tablename,",".join(cols)))
        
        ## prepare the insert string
        insert_str = "(Null,"+','.join(insert_sql)+")"
        #insert_str = ','.join(insert_sql)+")"
        
        for fields in self.get_fields():
            count += 1
            fields = [ fields[i] for i in range(len(fields)) if i in field_indexes ]
            try:
                self.dbh.execute("INSERT INTO "+tablename+" values " + insert_str, fields)
            except DB.DBError,e:
                logging.log(logging.WARNINGS,"DB Error: %s" % e)
            except TypeError,e:
                logging.log(logging.WARNINGS,"Unable to load line into table SQL: %s Data: %s Error: %s" % (insert_str,fields,e))
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
                self.dbh.execute("Alter table %s add index(`%s`)" % (tablename,index))
                yield "Created index on %s " % index
                
        ## Add the IP addresses to the whois table if required:
        self.dbh.execute("create table if not exists `whois` (`IP` INT UNSIGNED NOT NULL ,`country` VARCHAR( 4 ) NOT NULL ,`NetName` VARCHAR( 50 ) NOT NULL ,`whois_id` INT NOT NULL ,PRIMARY KEY ( `IP` )) COMMENT = 'A local case specific collection of whois information'")

        for field_number in range(len(self.fields)):
            if self.types[field_number] == 'IP Address':
                ## FIXME: Resolving whois lookups is too
                ## expensive. This needs to be moved to a different
                ## report!!!. For now it disabled
                continue
                dbh2=self.dbh.clone()
                #Handle for the pyflag db
                dbh_pyflag = DB.DBO(None)
                yield "Doing Whois lookup of column %s" % self.fields[field_number]
                
                self.dbh.execute("select `%s` as IP from %s group by `%s`", (
                    self.fields[field_number],
                    tablename,
                    self.fields[field_number]))
                for row in self.dbh:
                    whois_id = Whois.lookup_whois(row['IP'])
                    dbh_pyflag.execute("select * from whois where id=%r limit 1",(whois_id))
                    row2=dbh_pyflag.fetch()
                    try:
                        dbh2.execute("insert into whois set IP=%r,country=%r,NetName=%r,whois_id=%r",(
                            row['IP'],
                            row2['country'],
                            row2['netname'],
                            whois_id))
                    except DB.DBError:
                        pass

    def store(self, name):
        """ Stores the configured driver in the db.

        Note that Log objects are asked to pickle themselves. However
        the base class uses a generic pickler. If you need to do
        something really special for pickling or unpickling, you may
        override this method.
        """
        ## Clear stuff that is not relevant
        self.datafile = None
        tmp=self.dbh
        self.dbh=None
        data=pickle.dumps(self)
        self.dbh=tmp
        self.dbh.set_meta("log_preset", name,force_create=True)
        self.dbh.set_meta("log_preset_%s" % name, data)

    def display(self,query,result):
        """ This method is called to display the contents of the log
        file after it has been loaded
        """

def get_loader(dbh,name,datafile):
    """ lookup and unpickle log object from the database, return loader object

    We also initialise the object to the datafile list of filenames to use.
    """
    pydbh = DB.DBO(None)
    log=pickle.loads(pydbh.get_meta('log_preset_%s' % name))
    log.datafile = datafile
    log.dbh = dbh
    return log
    
class Type:
    """ This class represents translations between the way a column is stored in the database and the way it is displayed.

    This is used by the log driver to store the data in the most efficient format in the database.
    @cvar type: The database type this column should be created with.
    """
    type = None
    sql_in="%r"
    sql_out = "%s"
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
    sql_out= "INET_NTOA(%s)"
    
types = {
    'varchar(250)': VarType,
    'int': IntType,
    'datetime': DateTimeType,
    'text': TextType,
    'IP Address': IPType
    }

def render_whois_info(string,result=None):
    return Whois.identify_network(string)
