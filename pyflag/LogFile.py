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
#  Version: FLAG $Name:  $ $Date: 2004/10/15 23:48:19 $
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
import re
import cPickle

delimiters = {'Space':' ', 'Comma':',', 'Colon':':', 'Semi-Colon':';', 'Hyphen':'-'}

class prefilter:
    """ This class defines all the prefilters that are appropriate for importing log files.
    
    Prefilters are of the prototype:
    
    string prefilter(string)
    
    Method names must start with \"PF\", this will allow the class to pick its methods by itself. The use of a short, 1 line docstring is mandatory, since this is how the class will describe the prefilter to the user.
    
    @ivar  filters: A dict mapping the filter methods to their docstring descriptions.
    @ivar  res: A dict managing lists of (compiled RE's,target strings). This way REs only need to be compiled once.
    """
    
    filters = {}
    res = {}
    
    def __init__(self):
        for a in dir(self):
            if a.startswith('PF'):
                self.filters[a] = (prefilter.__dict__[a],prefilter.__dict__[a].__doc__)

    def transform(self, transform_list,string):
        """ Transforms a string according to a list of transformation.

        @arg transform_list: List of transformations obtained from prepare()
        @arg string: string to transform
        @return: A transformed string """
        for re_expression,target in transform_list:
            string = re_expression.sub(target,string)

        return string


    def prepare(self,re_strings,list):
        """ prepares a string and pushes it onto a list.

        This function can handle perl-like s/.../../ operations in a naive manner. There may be multiple lines of these expressions, in which case- the res will be compiled one line at the time and inserted into the list. Note that the s parsing is simplistic and assumes that the delimiter is after the first letter of the expression which must be an 's'. We assume that the delimiter can not be escaped. If you need to escape the delimiter - use another delimiter.

        @arg re_strings: A possibly multi-lined string of the style: s/.../.../
        @arg list: The list we push the (re,sub_string) onto.
        """
        for i in re_strings.splitlines():
            i = i.strip()
            if not i: continue
            if i[0] != 's': raise REError, "Regular expressions must start with s"
            delimiter = i[1]
            tmp = i.split(delimiter)
            try:
                if tmp[3]:
                    tmp[1] = "(?"+tmp[3]+")" + tmp[1]
            except KeyError:
                pass
            
            list.append((re.compile(tmp[1]),tmp[2]))

    def PFDateFormatChange(self,string):
        """ DD/MM/YYYY->YYYY/MM/DD """
        if not self.res.has_key('PFDateFormatChange'):
            tmp = []
            self.prepare(r" s#(\d\d)\/([^\/]+)\/(\d\d\d\d)#\3/\2/\1# ",tmp)
            self.res['PFDateFormatChange'] = tmp
            
        transform_list = self.res['PFDateFormatChange']
        return self.transform(transform_list,string)

    def PFDateFormatChange2(self,string):
        """ YYYY-MM-DD HH:MM:SS->YYYY/MM/DD:HH:MM:SS """
        if not self.res.has_key('PFDateFormatChange2'):
            tmp=[]
            self.prepare(r"s|(\d\d\d\d)-(\d\d)-(\d\d) (\d\d:\d\d:\d\d)|\1/\2/\3:\4|" , tmp)
            self.res['PFDateFormatChange2'] = tmp

        transform_list = self.res['PFDateFormatChange2']
        return self.transform(transform_list,string)

    def PFDateConvert(self,string):
        """ Month name to numbers """
        if not self.res.has_key('PFDateConvert'):
            tmp = []
            self.prepare(""" s/Jan(uary)?/1/i 
            s/Feb(uary)?/2/i
            s/Mar(ch)?/3/i
            s/Apr(il)?/4/i
            s/May/5/i
            s/Jun(e)?/6/i
            s/Jul(y)?/7/i
            s/Aug(ust)?/8/i
            s/Sep(tember)?/9/i
            s/Oct(ober)?/10/i
            s/Nov(ember)?/11/i
            s/Dec(ember)?/12/i
            """,tmp)
            self.res['PFDateConvert'] = tmp

        transform_list = self.res['PFDateConvert']
        return self.transform(transform_list,string)

    def PFRemoveChars(self,string):
        """ Remove [\'\"] chars """
        if not self.res.has_key('PFRemoveChars'):
             tmp = []
             self.prepare(r" s/[\[\"\'\]]/ /",tmp)
             self.res['PFRemoveChars'] = tmp

        return self.transform(self.res['PFRemoveChars'],string)

class Log:
    """ This base class abstracts Loading of log files """
    datafile = ()
    num_fields = 0
    def __init__(self,variable,query):
        """ Load the log file.

        @arg variable: Name of query variable that carries the name of the file. Note that this may be an array for files to specify a number of files.
        @arg query: The query object.
        """
        self.datafile = query.getarray(variable)
        if self.datafile==():
            raise KeyError("No variable %s" % variable)
        self.fields = []
        self.types = []
        self.indexes = []
        self.query = query

        ## If this object was called with a known number of fields:
        try:
            self.num_fields = int(query['number_of_fields'])
            self.set_fields()
            self.set_types()
            self.set_indexes()
        except KeyError:
            pass
        
    _fd = None
    
    def read_record(self):
        """ Generates records """
        if not self._fd:
            _fd=open(self.datafile[0],'r')
        # Each invocation of this generator should start reading the
        # log file from the beginning.
        _fd.seek(0)
        ## TODO: Seamlessly handle multiple log files by catching when
        ## one finishes and the next begins.
        for line in _fd:
            yield line

    def set_fields(self):
        """ set the field names from the query, order is important """
        for i in range(len(self.fields),self.num_fields):
            try:
                self.fields.append(self.query['field%u'%i])
            except KeyError:
                self.query['field%u' % i ] = 'ignore'
                self.fields.append('ignore')

    def set_types(self):
        """ set the field types from the query, order is important """
        for i in range(len(self.types),self.num_fields):
            try:
                self.types.append(self.query['type%u'%i])
            except KeyError:
                self.query['type%u' % i ] = 'varchar(250)'
                self.types.append('varchar(250)')

    def set_indexes(self):
        """ which fields require indexes """
        for i in range(len(self.indexes),self.num_fields):
            if self.query.has_key('index%u'%i):
                self.indexes.append(True)
            else:
                self.indexes.append(False)

    def load(self,dbh,tablename, rows = None):
        """ Loads the specified number of rows into the database.

        @arg dbh: A database handle to use
        @arg table_name: A table name to use
        @arg rows: number of rows to upload - if None , we upload them all
        """
        ## First we create the table:
        cols = []
        insert_sql = []
        field_indexes = []
        count=0
        print self.fields,self.types
        for i in range(len(self.fields)):
            if self.fields[i]!='' and self.fields[i] != 'ignore':
                field_indexes.append(i)
                type = types[self.types[i]]()
                cols.append("%s %s" % (self.fields[i], type.type ))
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
                logging.log(2,"Warning: %s" % e)

            if rows and count > rows:
                break

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
        self._fd=None
        return cPickle.dumps(self)

class SimpleLog(Log):
    """ A log processor to perform simple delimiter dissection
    """
    def __init__(self,variable,query):
        Log.__init__(self,variable,query)
        self.prefilters = query.getarray('prefilter')

        try:
            self.delimiter=query['delimiter']
        except KeyError:
            self.delimiter=' '
            query['delimiter']=self.delimiter
    
    def prefilter_record(self,string):
        """ Prefilters the record (string) and returns a new string which is the filtered record.
        """
        p = prefilter()
        for i in self.prefilters:
            #Call the relevant methods on the prefilter object:
            string = p.filters[i][0](p,string)
        return string

    def get_fields(self):
        """ A generator that returns all the columns in a log file.

        @returns: A generator that generates arrays of cells
        """
        for row in self.read_record():
            row = self.prefilter_record(row)
            yield row.split(self.delimiter)

    def form(self,query,result):
        """ This draws the form required to fulfill all the parameters """
        result.const_selector("Simple Field Separator:",'delimiter',delimiters.values(), delimiters.keys())
        if not query.has_key('delimiter'):
            query['delimiter'] = ' '

        result.end_table()
        result.row("Unprocessed text from file",colspan=5)
        sample = []
        count =0
        for line in self.read_record():
            sample.append(line)
            count +=1
            if count>3:
                break
            
        result.row('\n'.join(sample),bgcolor='lightgray')
        result.end_table()

        result.start_table()
        result.ruler()
        tmp = result.__class__(result)
        tmp.heading("Step 3:")
        result.row(tmp,"Select pre-filter(s) to use on the data")
        result.ruler()
        
        pre_selector(result)
        result.end_table()
        result.start_table()
        ## Show the filtered sample:
        result.row("Prefiltered data:",align="left")
        sample=[ self.prefilter_record(record) for record in sample ]
        result.row('\n'.join(sample),bgcolor='lightgray')
        result.end_table()

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
        for fields in self.get_fields():
            count +=1
            ## If we have more columns we set their names,types and
            ## indexes from the users data.
            if len(fields)>self.num_fields:
                self.num_fields=len(fields)
                self.set_fields()
                self.set_types()
                self.set_indexes()
                
            result.row(*fields)
            if count>3: break

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
        del result.defaults['number_of_fields']
        result.hidden("number_of_fields",self.num_fields)

class CSVLog(Log):
    """ Log parser designed to handle comma seperated filess """
    
        
plugins = {"Simple": SimpleLog,"CSV": CSVLog}

def get_loader(name,datafile):
    """ lookup and unpickle log object from the database, return loader object

    We also initialise the object to the datafile list of filenames to use.
    """
    dbh = DB.DBO(config.FLAGDB)
    log=cPickle.loads(dbh.get_meta('log_preset_%s' % name))
    log.datafile = datafile
    return log
    
def store_loader(log, name):
    """ pickle and save given loader into the database """
    dbh = DB.DBO(config.FLAGDB)
    dbh.execute('INSERT INTO meta set property="log_preset", value=%r' % name)
    dbh.execute('INSERT INTO meta set property="log_preset_%s", value=%r' % (name,log.pickle()))

def pre_selector(result):
    f = prefilter().filters
    x = []
    y = []
    for i in f.keys():
        x.append(i)
        y.append(f[i][1])
        
    result.const_selector("pre-filter(s) to use on the data:",'prefilter',x,y,size=4,multiple="multiple")

class Type:
    """ This class represents translations between the way a column is stored in the database and the way it is displayed.

    This is used by the log driver to store the data in the most efficient format in the database.
    @cvar type: The database type this column should be created with.
    """
    type = None
    sql_in="%r"
    sql_out = "`%s`"
    
class VarType(Type):
    type = "varchar(250)"

class IntType(Type):
    type = "int"

class DateTimeType(Type):
    type = "datetime"

class TextType(Type):
    type = "text"

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
