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
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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
from pyflag.FlagFramework import query_type
import pyflag.LogFile as LogFile
import pyflag.DB as DB
import pyflag.conf
config=pyflag.conf.ConfObject()
import re
import plugins.LogAnalysis.Whois as Whois
import pyflag.Registry as Registry
from pyflag.TableObj import ColumnType, StringType

description = "Log Analysis"
order = 35

class ListLogFile(Reports.report):
    """ Lists the content of the log file using the table UI object """
    parameters = {"logtable":"casetable"}
    name="List log file contents"
    family = "Log Analysis"
    description="This report simply lists the log entries in a searchable/groupable table"

    def form(self,query,result):
        try:
            result.case_selector()
            result.selector('Select Log Table','logtable',
                            "select table_name as `key`, table_name as value from log_tables",
                            case=query['case'])
        except KeyError:
            pass

    def display(self,query,result):
        if (query.has_key('limit')):
            result.heading("Log File in Table %s" % query['logtable'])
        else:
            result.heading("Log File in Table %s" % query['logtable'])            
        dbh = DB.DBO(query['case'])
        
        ## Fetch the driver to use:
        dbh.execute("select * from log_tables where table_name='%s' limit 1",(query['logtable']))
        row=dbh.fetch()
        if not row:
            raise Reports.ReportError("Log Table %s not found" % query['logtable'])
                                      
        try:
            ## Instantiate the driver on this case:
            log = LogFile.load_preset(query['case'],
                                      row['preset'])
        except KeyError,e:
            raise Reports.ReportError("Unable to load the preset %s for table %s " % (row['preset'],query['logtable']))

        ## Display it now:
        log.display(query['logtable'],result);

class CreateLogPreset(Reports.report):
    """ Creates a new type of log file in the database, so that they
    can be loaded using the Load Log File report"""
    parameters = {"log_preset":"any", "final":"any"}
    name="Create Log Preset"
    family = "Log Analysis"
    description="Create new preset log type"
    order=40

    def reset(self,query):
        dbh = self.DBO(None)
        dbh.delete("log_preset", where="name = %r" % query['log_preset'])

    def display(self,query,result):
        result.heading("New log file preset %s created" % query['log_preset'])
        result.link("Load a log file", query_type(case=None,
                                                  family='Load Data',
                                                  report='LoadPresetLog',
                                                  log_preset=query['log_preset']))
        return result

    def form(self,query,result):
        try:
            ## Try to get the driver
            log=Registry.LOG_DRIVERS.dispatch(query['driver'])()

            ## Ask the driver to render a form:
            log.form(query,result)
        except KeyError,e:
            ## Chose a driver to use:
            result.const_selector("Select Log Processor", 'driver',
                                  Registry.LOG_DRIVERS.class_names , Registry.LOG_DRIVERS.class_names
                                  )
            
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

class RemoveLogTable(Reports.report):
    """ Remove a log table from the current case """
    name = "Remove Log Table"
    family = "Log Analysis"

    def display(self,query, result):
        if not query.has_key('table'):
            result.heading("Delete a table from this case")

            def DeleteIcon(value):
                tmp=result.__class__(result)
                target = query.clone()
                target.set('table',value)

                tmp.link("Delete", icon="no.png",
                         target=target)
                return tmp

            result.table(
                elements = [ ColumnType("Delete?",'table_name',
                                        callback = DeleteIcon),
                             StringType("Table Name",'table_name'),
                             StringType("Type", "preset"),
                             ],
                table="log_tables",
                case=query['case']
                )

        elif query.has_key('confirm'):
            LogFile.drop_table(query['case'] , query['table'])
            result.refresh(0, query_type(family=query['family'], case=query['case'],
                                         report=query['report']))
        else:
            result.heading("About to remove %s" % query['table'])            
            query['confirm']=1
            result.link("Are you sure you want to drop table %s. Click here to confirm"% query['table'], query)

class RemoveLogPreset(Reports.report):
    """ Removes a log preset, dropping all tables created using it """
    name = "Remove Preset"
    hidden=True
    family = "Log Analysis"
    description = "Removes a preset"
    parameters= {"log_preset":"any", "confirm":"sqlsafe"}

    def form(self,query,result):
        try:
            result.selector("Select Preset to delete",'log_preset',
                            "select name as `key`, name as `value` from log_presets",
                            case = None)

            found=0
            result.row("The following will also be dropped:",'')
            
            tmp=result.__class__(result)
            tmp.start_table(**{'class':'GeneralTable'})
            left=result.__class__(result)
            right=result.__class__(result)
            left.text("Case",font='bold',style='red')
            right.text("Table",font='bold',style='red')
            tmp.row(left,right)

            for case, tablename in LogFile.find_tables(query['log_preset']):
                tmp.row(case, tablename)

            result.row(tmp)
            result.checkbox("Are you sure you want to do this?","confirm",'yes')
        except KeyError,e:
            print e
            pass

    def display(self,query,result):
        LogFile.drop_preset(query['log_preset'])

        result.heading("Deleted preset %s from the database" % query['log_preset'])
        result.link("Manage more Presets", query_type(family=query['family'],
                                                      report="Manage Log Presets"))
        
class ManageLogPresets(Reports.report):
    """ View and delete the available presets """
    name = "Manage Log Presets"
    family = "Log Analysis"
    description =     """ Log presets are templates which are used to parse different types of logs. Since each type of log file is subtablly different, a suitable preset should be created for the specific type of log file. This report allows you to create a new preset, view existing presets and delete unused presets. """
    parameters = {}
    
    def display(self,query,result):
        result.heading("These are the currently available presets")
        link = FlagFramework.query_type((),family=query['family'],report='CreateLogPreset')
                                                   
        result.toolbar(text="Add a new Preset",icon="new_preset.png",link=link,tooltip="Create a new Preset")
        def DeleteIcon(value):
            tmp=result.__class__(result)
            tmp.link("Delete", icon="no.png",
                     target=query_type(family=query['family'],
                                       report='RemoveLogPreset',
                                       log_preset=value))
            return tmp

        result.table(
            elements = [ ColumnType("Delete?",'name',
                                    callback = DeleteIcon),
                         StringType("Log Preset",'name'),
                         StringType("Type", "driver"),
                         ],
            table="log_presets",
            case=None
            )
        
class LogTablesInit(FlagFramework.EventHandler):
    def init_default_db(self, dbh, case):
        ## Log presets live in this table - type is the class name
        ## which will be fetched through Registry.LOG_DRIVERS.dispatch.
        dbh.execute("""CREATE TABLE `log_presets` (
        `name` varchar(250) NOT NULL,
        `driver` varchar(250) NOT NULL,
        `query` text,
        primary key (`name`)
        ) engine=MyISAM""")

        ## Make sure the default db also has a log_tables
        self.create(self, dbh, None)

    def create(self, dbh, case):
        dbh.execute("""CREATE TABLE `log_tables` (
        `preset` varchar(250) NOT NULL,
        `table_name` varchar(250) NOT NULL,
        primary key (`table_name`)
        ) engine=MyISAM""")
