""" This module implements a Log driver for IIS logs """
import pyflag.LogFile as LogFile
import plugins.LogAnalysis.Simple as Simple
import pyflag.DB as DB

class IISLog(Simple.SimpleLog):
    """ Log parser for IIS (W3C Extended) log files """
    name = "IIS Log"
    
    def __init__(self, variable, query):
        # set these params, then we can just use SimpleLog's get_fields
        self.delimiter = ' '
        self.prefilters = ['PFDateFormatChange2']
        # run Log constructor, unset var so we dont do the extra stuff
        LogFile.Log.__init__(self,variable,query)

        # now for the IIS magic, the code below sets up the
        # fields, types, and indexes arrays req'd by load
        # replaces the need for the form in SimpleLog

        # Find the fields line:
        count=0
        for row in self.read_record(ignore_comment = False):
            count+=1
            if row.startswith('#Fields: '):
                dbh=DB.DBO(None)
                self.fields = [ dbh.MakeSQLSafe(i) for i in row.split()[1:] ]
                # Coallesc the date and time field together:
                try:
                    i = self.fields.index('date')
                    del self.fields[i]
                except ValueError:
                    pass

                break

            ## couldnt we find the field header?
            if count>15:
                raise Reports.ReportError("Error parsing IIS log file (I can't find a #Fields header line.) Maybe you may be able to use the simple log driver for this log?")
        
        # try to guess types based on known field-names, not perfect...
        # automatically index the non-varchar fields, leave the rest
        self.types=[]
        self.indexes=[]
        for field in self.fields:
            if field == 'time':
                self.types.append('datetime')
                self.indexes.append(True)
            elif '-ip' in field:
                self.types.append('IP Address')
                self.indexes.append(True)
            elif '-status' in field:
                self.types.append('int')
                self.indexes.append(True)
            elif '-bytes' in field:
                self.types.append('int')
                self.indexes.append(True)
            else:
                self.types.append('varchar(250)')
                self.indexes.append(False)
            
    def form(self, query, result):
        result.para('NOTICE: This loader attempts to load IIS log files completely automatically by determining field names and types from the header comments, if this loader fails, please use the "Simple" loader')
