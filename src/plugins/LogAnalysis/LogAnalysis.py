# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# David Collett <daveco@users.sourceforge.net>
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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

""" Module for analysing Log files """
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.LogFile as LogFile
import pyflag.DB as DB
import pyflag.conf
config=pyflag.conf.ConfObject()
import re
import plugins.LogAnalysis.Whois as Whois
import pyflag.Registry as Registry

description = "Log Analysis"
order = 35

def display_test_log(dbh,log,result,query):
    # try to load and display as a final test
    temp_table = dbh.get_temp()
    
    for a in log.load(dbh,temp_table,rows= 3):
        pass

    dbh.execute("select * from %s limit 1",temp_table)
    columns =[]
    names = []
    for d in dbh.cursor.description:
        names.append(d[0])
        try:
            type = log.types[log.fields.index(d[0])]
            columns.append(LogFile.types[type].sql_out % "`%s`" % d[0])
        except ValueError:
            columns.append(d[0])

    result.ruler()
    tmp_final = result.__class__(result)
    tmp_final.table(columns=columns,names=names,links=[], table=temp_table, case=query['case'], simple=True)
    result.row(tmp_final,bgcolor='lightgray',colspan=5)

def render_whois_info(string,result=None):
    return Whois.identify_network(string)

class ListLogFile(Reports.report):
    """ Lists the content of the log file using the table UI object """
    parameters = {"logtable":"casetable"}
    name="List log file contents"
    family = "Log Analysis"
    description="This report simply lists the log entries in a searchable/groupable table"

    def form(self,query,result):
        result.case_selector()
        result.meta_selector(query['case'],'Select Log Table','logtable')

    def display(self,query,result):
        result.heading("Log File in Table %s" % query['logtable'])            
        dbh = self.DBO(query['case'])
        dbh.execute("select value from meta where property = 'log_preset_%s'",(query['logtable']))
        row=dbh.fetch()
        try:
            log = LogFile.get_loader(row['value'],None)
        except KeyError:
            raise Reports.ReportError("Unable to load the preset %s for table %s " % (row['value'],query['logtable']))

        if 'IP Address' in log.types and not query.has_key('group_by'):
            new_query=query.clone()
            if query.has_key('whois'):
                del new_query['whois']
                result.toolbar(link=new_query, text='Hide Whois Data',icon='whois.png')
            else:
                new_query['whois']='yes'
                result.toolbar(link=new_query, text='Show Whois Data',icon='whois.png')

        #Find the names of all the columns in table:
        dbh.execute("select * from %s_log limit 1",query['logtable'])
            
        columns =[]
        names = []
        callbacks = {}
        links = []
        where = []
        table_name = query['logtable']+'_log'
        table = [ "%s as table_name" % table_name]
        for d in dbh.cursor.description:
            names.append(d[0])
            try:
                type = log.types[log.fields.index(d[0])]
                columns.append(LogFile.types[type].sql_out % ("table_name.`%s`" % (d[0])))
                links.append(None)
                if type == "IP Address" and query.has_key('whois'):
                    names.append("Whois %s" % d[0])
##                    columns.append("concat(whois_%s.country,'/',whois_%s.NetName)" % (d[0],d[0]))
                    columns.append("whois_%s.whois_id" % (d[0]))
                    callbacks["Whois %s" % d[0]] = render_whois_info
                    table.append('whois as whois_%s' % d[0])
                    where.append("table_name.`%s` = whois_%s.IP" % (d[0],d[0]))
                    links.append( FlagFramework.query_type((),case=query['case'],family='Log Analysis',report='LookupWhoisID',__target__='id', __opt__='popup'))
                    
            except ValueError,e:
                columns.append(d[0])
                links.append(None)

        result.table(
            columns=columns,
            names=names,
            links= links,
            table= ','.join(table),
            callbacks = callbacks,
            where=" and ".join(where),
            case=query['case']
            )

class CreateLogPreset(Reports.report):
    """ Creates a new type of log file in the database, so that they can be loaded using the Load Log File report """
    parameters = {"log_preset":"sqlsafe", "datafile":"filename",
                   }
    name="Create Log Preset"
    family = "Log Analysis"
    description="Create new preset log type"
    order=40

    def reset(self,query):
        dbh = self.DBO(None)
        dbh.execute("delete from meta where property='log_preset' and value=%r",query['log_preset'])
        dbh.execute("delete from meta where property='log_preset_%s'",query['log_preset'])

    def display(self,query,result):
        result.heading("New log file preset %s created" % query['log_preset'])
        result.link("Load a log file", FlagFramework.query_type((),case=query['case'],family='Load Data',report='LoadPresetLog',log_preset=query['log_preset']))
        return result

    def form(self,query,result):
        def step1(query,result):
            result.row("Select a sample log file for the previewer",stretch=False)
            tmp = result.__class__(result)
            tmp.filebox(target='datafile')
            result.row("Enter name of log file:",tmp)
            if query.has_key('datafile'):
                return True
            else:
                result.text("Please input a log file name\n",color='red')
                return False
        
        def step2(query,result):
            result.const_selector("Select Log Processor", 'delmethod',
                                  Registry.LOG_DRIVERS.drivers.keys() , Registry.LOG_DRIVERS.drivers.keys()
                                  )
            if query.has_key('delmethod'):
                return True
            else:
                result.text("Please select a processor",color='red')
                return False

        def step3(query,result):
            # Now we ask the log object to draw its form for us:
            log = Registry.LOG_DRIVERS.drivers[query['delmethod']]('datafile',query)

            #Ask the Log object to draw the form it requires
            log.form(query,result)
            
            return True

        def step4(query,result):
            dbh = self.DBO(query['case'])
            result.text("The following is the result of importing the first few lines from the log file into the database.\nPlease check that the importation was successfull before continuing.",wrap='full')
            log = Registry.LOG_DRIVERS.drivers[query['delmethod']]('datafile',query)
            display_test_log(dbh,log,result,query)
            return True

        def step5(query,result):
            result.textfield("name for preset:",'log_preset')
            if query.has_key('log_preset'):
                return True
            else:
                result.text("Please type a name for the preset.\n",color='red')
                return False

        result.wizard(
            names = ( "Step 1: Select a log file",
                      "Step 2: Select a Log processor",
                      "Step 3: Configure Log processor",
                      "Step 4: View test result",
                      "Step 5: Save Preset"),
            callbacks = (step1,step2,step3,step4,step5)
            )

        return

    def analyse(self, query):
        """ store this log type in the database """
        log = Registry.LOG_DRIVERS.drivers[query['delmethod']]('datafile',query)
        # pickle it to the database
        LogFile.store_loader(log, query['log_preset'])

class BandWidth(Reports.report):
    """ Calculates the approximate bandwidth requirements by adding the size of each log entry within time period """
    parameters = {"logtable":"casetable","timestamp":"sqlsafe","size":"sqlsafe"}
    name = "Estimate Bandwidth"
    family = "Log Analysis"
    hidden=True
    description="Estimate approximate bandwidth requirements from log file"

    def form(self,query,result):
        dbh = self.DBO(query['case'])
        result.para("This report approximates the amount of bandwidth used by the server that produced the log file. This is done by adding the total number of bytes transfered within a specified time preiod (called a bin). Bins are specified in seconds. The result is a graph showing how many bytes were transfered per bin.")
        try:
            result.case_selector()
            result.meta_selector(query['case'],'Select Log Table','logtable')
            dbh.execute("select * from %s limit 1",query['logtable'])
            columns = [ d[0] for d in dbh.cursor.description ]
            result.const_selector("Timestamp column:",'timestamp',columns,columns)
            result.const_selector("Size column:",'size',columns,columns)
        except KeyError:
            pass

    def display(self,query,result):
        dbh = self.DBO(query['case'])
        try:
            bin_size=int(query['bin_size'])
        except KeyError:
            bin_size=60
            query['bin_size']=str(bin_size)
            
        result.heading("Bandwidth estimate from log %s"%query['logtable'])
        result.start_table()
        result.start_form(query)
        result.textfield('Bin Size (Seconds):','bin_size')
        result.end_form(None)
        result.end_table()

        if query.has_key('graph'):
            new_query=query.clone()
            del new_query['graph']
            del new_query['limit']
            result.link("Click here to view table",new_query)

            params={'timestamp':query['timestamp'],'bin_size':bin_size,'size':query['size'],'logtable':query['logtable']}
            try:
                start=int(query['limit'])
                if not start: raise KeyError
            except KeyError:
                dbh.execute('select unix_timestamp(min(%(timestamp)s)) as `min` from %(logtable)s'%params)
                start=dbh.fetch()['min']

            params['start']=start
            
            result.para("")
            dbh.execute('select unix_timestamp(%(timestamp)s) as `timestamp`,floor(unix_timestamp(%(timestamp)s)/%(bin_size)s)*%(bin_size)s as `Unix Timestamp`,from_unixtime(floor(unix_timestamp(%(timestamp)s)/%(bin_size)s)*%(bin_size)s) as `DateTime`,sum(%(size)s) as `Count` from %(logtable)s  where `%(timestamp)s`>from_unixtime("%(start)s") and   `%(timestamp)s`<from_unixtime("%(start)s"+100*%(bin_size)s) group by `Unix Timestamp`  order by  `Unix Timestamp` asc   limit 0, 100' % params )
            x=[]
            y=[]
            z=[]
            for row in dbh:
                x.append(row['DateTime'])
                y.append(row['Count'])
                z.append(row['timestamp'])

            try:
                result.next=z[-1]
                result.previous=z[0]-100*bin_size
            except IndexError:
                del query['limit']
                result.refresh(0,query)

            import pyflag.Graph as Graph

            graph=Graph.Graph()
            graph.hist(x,y,xlabels='yes',stubvert='yes',xlbl="Timestamp Bin",ylbl="Bytes per Bin",ylbldet="adjust=-0.15,0",xlbldet="adjust=0,-1.1")
            result.image(graph)
            return

        result.link("Click here to view graph",query,graph=1)

        result.table(
            columns=('floor(unix_timestamp(%s)/%s)*%s' % (query['timestamp'],bin_size,bin_size) ,'from_unixtime(floor(unix_timestamp(%s)/%s)*%s)' % (query['timestamp'],bin_size,bin_size) ,'sum(%s)'%query['size']), 
            names=('Unix Timestamp','DateTime','Count'),
            links=[],
            table=query['logtable'],
            case=query['case'],
            groupby='`Unix Timestamp`'
            )

class RemoveLogPreset(Reports.report):
    """ Removes a log preset, dropping all tables created using it """
    name = "Remove Preset"
    hidden=True
    family = "Log Analysis"
    description = "Removes a preset"
    parameters= {"log_preset":"sqlsafe", "confirm":"sqlsafe"}

    def find_tables(self,preset):
        """ Yields the tables which were created by a given preset.

        @return: (database,table)
        """
        dbh=DB.DBO(None)
        ## Find all the cases we know about:
        dbh.execute("select value from meta where property='flag_db'")
        for row in dbh:
            ## Find all log tables with the current preset
            dbh2=DB.DBO(row['value'])
            dbh2.execute("select * from meta where property like \"log_preset_%%\" and value=%r",preset)
            for row2 in dbh2:
                yield (row['value'],row2['property'][len("log_preset_"):])

    def form(self,query,result):
        try:
            result.selector("Select Preset to delete",'log_preset',"select value,value from meta where property='log_preset'",(),case=None)

            tmp=result.__class__(result)
            found=0
            tmp.row("The following will also be dropped:",'')
            left=result.__class__(result)
            right=result.__class__(result)
            left.text("Case",font='bold',color='red')
            right.text("Table",font='bold',color='red')
            tmp.row(left,right)
            for a in self.find_tables(query['log_preset']):
                found=1
                tmp.row(*a)

            if found:
                result.row(tmp)
            result.checkbox("Are you sure you want to do this?","confirm",'yes')
        except KeyError:
            pass

    def display(self,query,result):
        ## First drop the tables:
        preset=query['log_preset']
        ## This will reset all reports that loaded using the given
        ## preset - This should cause those tables to drop
        dbh=DB.DBO(None)
        ## Find all the cases we know about:
        dbh.execute("select value from meta where property='flag_db'")
        for row in dbh:
            FlagFramework.reset_all(family='Load Data',report='LoadPresetLog',log_preset=preset,case=row['value'])

        ## Now lose the preset itself
        FlagFramework.reset_all(log_preset=preset,family=query['family'],report='Create Log Preset',case=None)
        
        result.heading("Deleted preset %s from the database" % query['log_preset'])
        
class ManageLogPresets(Reports.report):
    """ View and delete the available presets """
    name = "Manage Log Presets"
    family = "Log Analysis"
    description =     """ Log presets are templates which are used to parse different types of logs. Since each type of log file is subtablly different, a suitable preset should be created for the specific type of log file. This report allows you to create a new preset, view existing presets and delete unused presets. """
    
    def display(self,query,result):
        result.heading("These are the currently available presets")
        link = FlagFramework.query_type((),family=query['family'],report='CreateLogPreset')
                                                   
        result.toolbar(text="Add a new Preset",icon="new_preset.png",link=link,tooltip="Create a new Preset")
        def DeleteIcon(value):
            tmp=result.__class__(result)
            tmp.icon("no.png",border=0,alt="Click here to delete %s preset" % value)
            return tmp

        def Describe(value):
            try:
                log = LogFile.get_loader(value,None)
                return( "%s" % log.__class__)
            except KeyError:
                return "Unknown"
        
        result.table(
            columns = ( "value","value",'value' ),
            names = ( "Delete?","Log Preset","Type"),
            links = [ FlagFramework.query_type((),family=query['family'],report='RemoveLogPreset',__target__='log_preset'),],
            callbacks = { 'Delete?':DeleteIcon, 'Type':Describe },
            where = 'property="log_preset"',
            table="meta",
            case=None
            )
        
