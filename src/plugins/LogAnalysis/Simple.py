""" This module implements a simple logfile driver """
# Michael Cohen <scudette@users.sourceforge.net>
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
import pyflag.LogFile as LogFile
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework
from pyflag.FlagFramework import query_type
import re
import pyflag.Registry as Registry

delimiters = {'Space':' ', 'Comma':',', 'Colon':':', 'Semi-Colon':';', 'Hyphen':'-'}

def pre_selector(result):
    f = prefilter().filters
    x = []
    y = []
    for i in f.keys():
        x.append(i)
        y.append(f[i][1])
        
    result.const_selector("pre-filter(s) to use on the data:",'prefilter',x,y,size=4,multiple="multiple")

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

    def PFDateFormatChange(self,string):
        """ DDMMYYYY->YYYYMMDD """
        if not self.res.has_key('PFDateFormatChange3'):
            tmp = []
            self.prepare(r" s#(\d\d)(\d\d)(\d\d\d\d)#\3/\2/\1# ",tmp)
            self.res['PFDateFormatChange3'] = tmp
            
        transform_list = self.res['PFDateFormatChange3']
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

    def PFDateFormatChange3(self, string):
        """MM DD HH:mm:SS YYYY ->  YYYY/MM/DD:HH:MM:SS"""
        if not self.res.has_key('PFDateFormatChange3'):
            tmp=[]
            self.prepare(r"s|(\d{,2}) +(\d{,2}) +(\d\d:\d\d:\d\d) +(\d{4})|\4/\1/\2:\3|" , tmp)
            self.res['PFDateFormatChange3'] = tmp

        transform_list = self.res['PFDateFormatChange3']
        return self.transform(transform_list,string)

    def PFRemoveChars(self,string):
        """ Remove [\'\"] chars """
        if not self.res.has_key('PFRemoveChars'):
             tmp = []
             self.prepare(r" s/[\[\"\'\]]/ /",tmp)
             self.res['PFRemoveChars'] = tmp

        return self.transform(self.res['PFRemoveChars'],string)

class SimpleLog(LogFile.Log):
    """ A log processor to perform simple delimiter dissection. 
    """
    name = "Simple"
    
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

    def parse(self, query, datafile='datafile'):
        """ This function parses the query string into the appropriate fields array """
        LogFile.Log.parse(self,query, datafile)
        
        self.datafile = query.getarray(datafile)
        self.prefilters = query.getarray('prefilter')

        num_fields = 0
        ## Count the fields presented:
        for k in query.keys():
            if k.startswith('field'):
                number=int(k[len('field'):])
                if number>num_fields:
                    num_fields=number
                    
        num_fields+=1
        print "Found %s fields" % num_fields
        ## Initialise the fields array:
        self.fields = [ None ] * num_fields
        self.num_fields = num_fields

        ## Now parse them:
        for i in range(0,num_fields):
            try:
                field_cls = Registry.COLUMN_TYPES.dispatch(query['type%u' % i])
                ## This is what the field will be called:
                name = query['field%u' % i]
                self.fields[i] = field_cls(name=name, column=name)

                ## Do we need to index it?
                if query.has_key('index%u' % i):
                    self.fields[i].index = True
                    
            except Exception,e:
                pass
  
        try:
            self.delimiter=query['delimiter']
        except KeyError:
            self.delimiter=delimiters.values()[0]
            query['delimiter']=self.delimiter
                    
    def form(self,query,result):
        """ This draws the form required to fulfill all the parameters for this report
        """
        def configure_filters(query, result):            
            self.parse(query)
            result.start_table()
            result.row("Unprocessed text from file")
            sample = []
            count =0
            for line in self.read_record():
                sample.append(line)
                count +=1
                if count>3:
                    break

            [result.row(s,bgcolor='lightgray') for s in sample]
            result.end_table()

            result.start_table()
            result.ruler()
            tmp = result.__class__(result)
            tmp.heading("Step:")
            result.row(tmp,  " Select pre-filter(s) to use on the data")
            result.ruler()

            pre_selector(result)
            result.end_table()
            result.start_table()
            ## Show the filtered sample:
            result.row("Prefiltered data:",align="left")
            sample=[ self.prefilter_record(record) for record in sample ]
            [result.row(s,bgcolor='lightgray') for s in sample]
            result.end_table()

        def configure_seperators(query,result):
            self.parse(query)
            result.start_table(hstretch=False)
            result.const_selector("Simple Field Separator:",'delimiter',delimiters.values(), delimiters.keys(), autosubmit=True)

            result.end_table()

            self.draw_type_selector(result)

        def test(query,result):
            self.parse(query)
            result.text("The following is the result of importing the first few lines from the log file into the database.\nPlease check that the importation was successfull before continuing.")
            self.display_test_log(result)
            return True

        result.wizard(
            names = [ "Step 1: Select Log File",
                      "Step 2: Configure preprocessors",
                      "Step 3: Configure Columns",
                      "Step 4: View test result",
                      "Step 5: Save Preset",
                      "Step 6: End"],
            callbacks = [LogFile.get_file,
                         configure_filters,
                         configure_seperators,
                         test,
                         FlagFramework.Curry(LogFile.save_preset, log=self),
                         LogFile.end
                         ],
            
            )
    
    def draw_type_selector(self,result):
        """ Draws an interactive GUI allowing users to specify field names, types and choice of indexes """
        result.start_table()
        result.ruler()
        tmp = result.__class__(result)
        tmp.heading("Step:")
        result.row(tmp,"Assign field names and Types to each field")
        result.ruler()
        result.end_table()

        ## This part creates a GUI allowing users to assign names,
        ## types and indexes to columns
        result.start_table(border=1,bgcolor='lightgray')
        count = 0

        for fields in self.get_fields():
            count +=1                
            result.row(*fields)
            ## Find the largest number of columns in the data
            if len(fields)>self.num_fields:
                self.num_fields=len(fields)
            if count>3: break

        ## If we have more columns we set their names,types and
        ## indexes from the users data.

        field = []
        type = []
        index = []
        ## Now we create the input elements:
        for i in range(self.num_fields):
            field_ui = result.__class__(result)
            type_ui = result.__class__(result)
            index_ui =  result.__class__(result)
            
            field_ui.textfield('','field%u' % i)
            type_ui.const_selector('',"type%u" % i, Registry.COLUMN_TYPES.class_names, Registry.COLUMN_TYPES.class_names)
            index_ui.checkbox('Add Index?','index%u'%i,'yes')
            field.append(field_ui)
            type.append(type_ui)
            index.append(index_ui)

        result.row(*field)
        result.row(*type)
        result.row(*index)
