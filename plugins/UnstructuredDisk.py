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
#  Version: FLAG  $Version: 0.75 Date: Sat Feb 12 14:00:04 EST 2005$
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

""" Unstructured Disk Forensics:

This module implements a number of disk forensics techniques which work on disks which may have been damaged or otherwise are not mountable.

RAID 5 disks consist of an array of disks, We shall denote these as D1 ... Dn.
Data is written on the disk in blocks (typically blocks are multiples of 1024 bytes, commonly 4096 bytes).

At least one of the disk carries parity information. This means that the following equation is true:

>>> D1 ^ D2 ^ D3 = 0

The parity is typically alternated between the disks in a given pattern. This set of reports are designed to deduce this pattern so that the array data may be reconstructed. For example, suppose we have a 3 disk array, the parity may be alternated as:

>>>   Block  D1  D2  D3
...   1       -     -      P
...   2       -     P     -
...   3       P    -      -
      
This pattern may repeat over and over. In this case we say that the array period is 3. This is what this specific report aims to establish.

Algorithm:
==========

The algorithm implemented here is:
      - Find those blocks for which 2 disks carry text data, and exactly 1 disk carries non-uniform binary data. Since the parity is obtained by xoring the other disks together, and each carries printable characters, it is unlikely that the parity will consist also of printable characters. It is therefore assumed that the non-printable block is the parity. Since this only works for large text only files we get a random sample of parity position throughout the disks.
      - The period is calculated by taking the auto-correlation of the disk distribution pattern for different periods. When the period matches we get a very strong correlation across the sample points.
      - By manualy examining block ordering, it is possible to come up with a raid ordered map, or a consitant way in which blocks may be reassumbled within the period.
      - Once a map has been obtained, the disks may be reassembled. There is the possibility of checking the parity to detect errors, or to completely remove one disk from the array, if that disk is damaged.
         
"""

description = "Unstructured Forensics"
order = 80
active = False

import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB
import pyflag.IO as IO
import os,time

def MakeTableName(query,dbh):
    disks = [ query[d][-10:] for d in query.keys() if d.startswith("datafile") ]
    disks.sort()
    return dbh.MakeSQLSafe("_".join(disks))
    
def GetFiles(disk_count,query,result):
    """ Builds the form to retrieve all the filenames for the different disks

    @return: None if the user did not select all the files yet, list of files if all the files are selected.
    """
    disks = []
    try:
        for i in range(disk_count):
            try:
                disks.append(query['datafile%u' % i])
                result.row("Disk %u:" %i , "Filename  %s"% (query['datafile%u'%i]))
            except KeyError:
                tmp = result.__class__(result)
                tmp.filebox(target="datafile%u" % i)
                result.row("Select image number %u:"%i,tmp)
                
        result.end_table()
        if len(disks) == int(query['disk_count']):
            return disks
        else: return None
    except KeyError:
        pass

class ParseError(Exception):
    """ Exception raised when we can not parse an expression """
    pass

class MapActions:
    """ This class defines a series of actions to be taken on the default map in order to generate the new map.

    The actions are defined as a set of methods on this object. The prototype is:

    >>> def ActionName(self,slots,disks,values)
    ...            \"\"\" Docstring \"\"\"

    Where slots is a list of slots to apply this action to, disks is a list of disk numbers to apply the action to, and values is a list of values to apply the function to. These functions return nothing.

    @ivar map: Name of map table to operate on.
    @ivar dbh: A ready to use database handle
    @ivar actions: A Dict of action methods (as key words) and their descriptions.
    """
    actions = {}
    action_desc = {}

    def __init__(self,map,dbh):
        """ Constructor.

        @arg map: Name of map table
        @arg dbh: An initialised database handle pointing at the correct case.
        """
        self.map = map
        self.dbh  = dbh
        for a in dir(self):
            if a.startswith('Action'):
                self.action_desc[a] = MapActions.__dict__[a].__doc__
                self.actions[a] = MapActions.__dict__[a]
                
    def ActionSetValue(self,slots,disks,values):
        """ Set values into slots """
        for slot in slots:
            for disk,value in zip(disks,values):
                self.dbh.execute("update %s set disk%s=%r where slot=%r",(self.map,disk,self.ParseExpression(slot,value),slot))

    def ParseExpression(self,slot,expression):
        """ Parses the expression and evaluates it.

        expression is an arithmeric expression. The following subexpressions are recognized:
              - disk\\d*[\d*] - e.g. disk0[-1]
                    This means the value of disk0 at the current slot location less 1 slot.

        @returns: a number which is the evaluation of the expression after all substitutions are made
        """

        ## Allow the user to mark the disk as parity
        if expression == 'P' or expression=='p':
            self.dbh.execute("select * from %s where slot=%s",(self.map,slot))
            
            ## Find the original parity and reset it
            row = self.dbh.fetch()
            if row:
                for k,v in row.items():
                    if v<0:
                        self.dbh.execute("update %s set %s=0 where slot=%s",(self.map,k,row['slot']))
            return -1
        
        import re

        def expand_disks(match):
            """ Evaluate the disk expression, the RE that matches is assumed to be:
            
            (disk\d*)\[([-\d]*)].

            Hence match.group(1) = disknumber, match.group(2) = relative reference.
            """
            test_slot = slot+int(match.group(2))
            disk_number = match.group(1)
            self.dbh.execute("select %s from %s where slot=%s",(disk_number,self.map,test_slot))
            row=self.dbh.fetch()
            return str(row[disk_number])
        
        new_exp = re.sub("(disk\d*)\[([-\d]*)\]",expand_disks,expression)
        try:
            result=eval(str(new_exp),{},{})
        except Exception:
            raise ParseError,"'%s'" %expression
        
        return result
        
class ReassembleRaid(Reports.report):
    """ Reconstructs a raid partition from dd images of the individual disks """
    parameters = {'disk_count':'numeric','final':'alphanum'}
    name="Reassemble Raid disk"
    family = "Unstructured Forensics"
    description = "Reassemble raid disk from individual dd images"
    hidden=True
    
    def analyse_files():
        """ Analyse the disks in the array using the raid analysis tool. """
    
    def form(self,query,result):
        result.case_selector()
        result.textfield("Number of disks in array:","disk_count")
        disks=[]
        #Prepare the disk array:
        try:
            GetFiles(int(query['disk_count']),query,result)
            result.textfield("Select period:",'period')
            dbh=self.DBO(query['case'])

            temp_table= dbh.get_temp()
            dbh.execute("create table %s select offset,if(disk=0,1,0) as disk1,if(disk=1,1,0) as disk2,if(disk=2,1,0) as disk3 from raid",temp_table)
            
            correlation=dbh.get_temp()
            dbh.execute("create table  %s select 0 as period,0.000 as rating",correlation)

            for period in range(1500):
                dbh2 = self.DBO(query['case'])
                temp2 = dbh.get_temp()
                dbh2.execute("create table %s select offset %% %s as slot,sum(disk1) as s1,sum(disk2) as s2, sum(disk3) as s3 from %s group by slot",(temp2,period,temp_table))
                
                temp3  = dbh.get_temp()
                dbh2.execute("create table %s select slot,s1,s2,s3,if(s1=0 and s2=0 or s2=0 and s3=0 or s1=0 and s3=0,s1+s2+s3,0) as maybe from %s",(temp3,temp2))
                dbh2.execute("insert into %s select %s,sum(maybe)/(sum(s1)+sum(s2)+sum(s3)) from %s",(correlation,period,temp3))
                dbh2.execute("drop table %s",temp2)
                dbh2.execute("drop table %s",temp3)

            result.table(
                columns = ['period','rating'],
                names = ['Period','Rating'],
                table = correlation,
                case = query['case'],
                where = "rating > 0.9"
                )

        except KeyError:
            pass


class DeduceRaidPeriod(ReassembleRaid):
    """ Deduces The raid period. """
    hidden=True
    parameters = {'disk_count':'numeric','final':'alphanum','min_period':'numeric','max_period':'numeric'}
    description = "Deduce Raid Period from text based analysis."
    name = "Raid Period"

    def form(self,query,result):
        result.case_selector()
        result.textfield("Number of disks in array:","disk_count")

        #Some sensible defaults
        if not query.has_key('min_period'): query['min_period'] = "0"
        if not query.has_key('max_period'): query['max_period'] = "1500"

        result.textfield("Minimum period:",'min_period')
        result.textfield("Maximum period:",'max_period')

        try:
            if GetFiles(int(query['disk_count']),query,result):
                query['final'] = 'yes'
                result.refresh(0,query)
        except KeyError:
            pass

    def reset(self,query):
        dbh = self.DBO(query['case'])
        tablename=MakeTableName(query,dbh)
        dbh.execute("drop table raid_correlation_%s",(tablename));
        dbh.execute("drop table raid_breakdown_%s",(tablename));

    def analyse(self,query):
        dbh = self.DBO(query['case'])

        #First off, load the data into the case
        tablename=MakeTableName(query,dbh)
        
        #Create the table
        dbh.execute("create table if not exists `raid_%s` (offset int(11) not null default '0', disk int(11) not null default '0')",tablename)

        DB.MySQLHarness("raid_info -p -t raid_%s %s" % (tablename," ".join([ query[i] for i in query.keys() if i.startswith("datafile")])),dbh)
        
        raid_breakdown = 'raid_breakdown_%s' % tablename
        dbh.execute("create table if not exists %s select offset,if(disk=0,1,0) as disk1,if(disk=1,1,0) as disk2,if(disk=2,1,0) as disk3 from raid_%s",(raid_breakdown,tablename))
        
        correlation='raid_correlation_%s' % tablename
        dbh.execute("create table if not exists %s select 0 as period,0.000 as rating",correlation)
        
        for period in range(int(query['min_period']),int(query['max_period'])):
            temp2 = 'temp2'
            dbh.execute("create temporary table %s select offset %% %s as slot,sum(disk1) as s1,sum(disk2) as s2, sum(disk3) as s3 from %s group by slot",(temp2,period,raid_breakdown))
                
            temp3  = 'temp3'
            dbh.execute("create temporary table %s select slot,s1,s2,s3,if(s1=0 and s2=0 or s2=0 and s3=0 or s1=0 and s3=0,s1+s2+s3,0) as maybe from %s",(temp3,temp2))
            dbh.execute("insert into %s select %s,sum(maybe)/(sum(s1)+sum(s2)+sum(s3)) from %s",(correlation,period,temp3))
            dbh.execute("drop table %s",temp2)
            dbh.execute("drop table %s",temp3)

    def display(self,query,result):
        result.heading("Period Correlation")
        dbh = self.DBO(query['case'])
        tablename=MakeTableName(query,dbh)
        
        correlation='raid_correlation_%s' % tablename
        
        if query.has_key('graph'):
            del query['graph']
            tmp = self.ui(result)
            tmp.link("see table",query)
            result.row(tmp)
            
            import pyflag.Graph as Graph

            graph = Graph.Graph()
            dbh.execute("select period,rating from %s",correlation)
            x=[]
            y=[]
            for row in dbh:
                x.append(row['period'])
                y.append(row['rating'])

            graph.line(x,y)
            result.image(graph)
        else:
            tmp = self.ui(result)
            tmp.link("see graph",query,graph="1")
            result.row(tmp)

            newquery = query.clone()
            del newquery['report']
            newquery['report'] = 'ConstructMap'
            
            result.table(
                columns = ['period','rating'],
                names = ['Period','Rating'],
                table = correlation,
                links = [ result.make_link(newquery,'period')],
                case = query['case'],
                )

def parse_ranges(expression,min=0,max=1000):
    """ Parse the ranges specified in expression into a list containing all the values in those ranges.

    A range is specified as a comma seperated set of sub expressions, a subexpression is either an integer or a pair of integers seperated by a colon.

    e.g:
         - 1,2,3
         - 1-4,6-7
         - 2,5-8

    Note that ranges are bound by min and max, they are clamped to those values.
    """
    result = []
    
    sub_expressions = expression.split(",")
    for sub in sub_expressions:
        try:
            tmp = sub.split('-')
            tmin = int(tmp[0])
            tmax = int(tmp[1])
            if tmin < min: tmin=min
            if tmax > max: tmax=max
            result.extend(range(tmin,tmax+1))
        except IndexError:
            result.append(int(tmp[0]))
            
    return result

class ConstructMap(Reports.report):
    """ Builds a Raid reconstruction map. You will need this in order to reconstruct the array """
    parameters = {'disk_count':'numeric','period':'numeric','final':'alphanum'}
    name="Construct Map"
    family = "Unstructured Forensics"
    description = "Allows the construction of a raid map interactively"
    hidden=True

    def form(self,query,result):
        result.case_selector()
        result.textfield("Array Period:",'period')
        result.textfield("Number of disks in array:","disk_count")
        try:
            if GetFiles(int(query['disk_count']),query,result):
                query['final'] = 'yes'
            ## Thats all we need- lets analyse it
                result.refresh(0,query)
        except KeyError:
            pass

    def analyse(self,query):
        dbh = self.DBO(query['case'])
        tablename=MakeTableName(query,dbh)
        
        dbh.execute("create table if not exists `raid_map_%s` (`slot` INT NOT NULL ,`disk0` INT NOT NULL ,`disk1` INT NOT NULL ,`disk2` INT NOT NULL ,PRIMARY KEY ( `slot` )) ",(tablename))
        dbh.execute("delete from `raid_map_%s`",(tablename))
        #Create the default map:
        map = []
        for i in range(int(query['period'])):
            map.append([0] * int(query['disk_count']))

        dbh.execute("select offset %% %s as slot,if(sum(disk1)>0 and sum(disk2)=0 and sum(disk3)=0,1,0) as d0,if(sum(disk2)>0 and sum(disk1)=0 and sum(disk3)=0,1,0) as d1,if(sum(disk3)>0 and sum(disk1)=0 and sum(disk2)=0,1,0) as d2 from raid_breakdown_%s group by slot",(query['period'],tablename))
        for row in dbh:
            for i in range(int(query['disk_count'])):
                if row['d%u' % i] == 1:
                    print "Setting map %u disk %u to -1" % (row['slot'],i)
                    map[row['slot']][i] = -1

        for i in range(int(query['period'])):
            disks = []
            for j in range(int(query['disk_count'])):
                disks.append("disk%u=%s" % (j,map[i][j]))
            dbh.execute("insert into `raid_map_%s` set slot=%s,%s",(tablename,i,",".join(disks)))
                    
    def display(self,query,result):
        dbh=self.DBO(query['case'])
        tablename=MakeTableName(query,dbh)
        map = MapActions('raid_map_%s'%tablename,dbh)
        
        result.heading("Building a Raid Map")
        
        ## Interpret the actions and execute those:
        try:
            slots = parse_ranges(query['slot'],max=int(query['period']))
            disks = []
            values = []
            for i in range(int(query['disk_count'])):
                try:
                    value = query['disk%u' % i ]
                    if len(value)>0:
                        values.append(value)
                        disks.append(i)
                except KeyError:
                    pass
                
            print "Will process the following slots: %s, disks %s and values %s " % (slots,disks,values)
            try:
                map.actions[query['action']](map,slots,disks,values)
#            except DB.DBError,e:
#                result.text("An error occured executing the requested action. Please check that the parameters are appropriate for this action(%s)\r\n\r\n"%e,font="bold",color="red")
            except ParseError, e:
                result.text("Expression Error. There is an error in the fomula expression %s, please review it.\r\n\r\n" % e,font="bold",color="red")
        except KeyError:
            pass

        ## Draw a table of the current map
        result.para('')
        result.text("Click on any of the slots to examine them in detail. Choose an action to alter the map",color='black',font='normal')

        left = self.ui(result)

        newquery = query.clone()
        del newquery['report']
        newquery['report'] = 'ExamineRaidSlots'
        
        left.table(
            columns = ['slot' ] + [ 'if(disk%u<0,"P",disk%u)' % (i,i) for i in range(int(query['disk_count'])) ],
            names = ['slot' ] + [ 'disk%u' % i for i in range(int(query['disk_count'])) ],
            table = 'raid_map_%s'%tablename,
            links = [ result.make_link(newquery,'slot') ],
            case=query['case'],
           )

        right = self.ui(result)
        right.start_form(query)
        right.heading("Actions")
        right.const_selector("Select Action to perform:",'action',map.action_desc.keys(),map.action_desc.values())
        right.end_table()

        right.textfield("Slots to operate on: ",'slot')
        right.end_table()

        ## Make a new table
        uis = []
        for i in range(int(query['disk_count'])):
            tmp = self.ui(result)
            tmp.text("Disk %u" % i,font="bold",color="red")
            tmp.textfield("Value:",'disk%u' % i,size='10')
            uis.append(tmp)
        right.row(*uis)
        right.end_table()
        right.end_form('Update')

        right.heading("Hints")
        right.text("You may specify a slot range, by using the dash or by comma seperating slots, e.g. 1,2,3 or 1,2,4-9\r\n\r\n",color='black')
        right.text("""You may use formulas as expression in the values columns. You may use the following format to refer to values of other disks in other slots:
        \r
        diskx[y] - x is the number of the disk, and y is the relative slot location.\r
        \r
        Example:\r
        \r
        disk0[-1] - refers to the value of disk0 at one slot less than is currently referenced.\r
        \r
        You may mark a disk as parity by using a single P as the expression\r
        \r
        Warning: Do not be tempted to write a formula where the slot range being set overlaps with the referenced range in the forumula, this is risky since the formula may be evaluated more than once - for example, do not write:\r
        disk0[-4]+8 for range 0-15.\r
                
        """,color='black',font='normal')
        
        result.row(left,right,valign='top')

        ## This is required to fix the navigation for the main ui
        result.next = left.next
        result.previous = left.previous
        result.pageno = left.pageno

class ExamineRaidSlots(Reports.report):
    """ Examine Slots in raid map """
    parameters = {'disk_count':'numeric','period':'numeric','slot':'numeric','final':'alphanum'}
    name="Examine Slots"
    family = "Unstructured Forensics"
    description = "Examine slot relation in raid map"
    hidden=True
    
    def form(self,query,result):
        result.case_selector()
        result.textfield("Array Period:",'period')
        result.textfield("Slot:",'slot')
        result.textfield("Number of disks in array:","disk_count")
        try:
            if GetFiles(int(query['disk_count']),query,result):
                query['final'] = 'yes'
            ## Thats all we need- lets analyse it
                result.refresh(0,query)
        except KeyError:
            pass

    def display(self,query,result):
        result.heading("Examining slot %s" % query['slot'])
        dbh = self.DBO(query['case'])
        tablename=MakeTableName(query,dbh)

        dbh.execute('select min(offset) as `min`,count(*) as `count` from raid_%s where  offset %% %s =%r',(tablename,query['period'],query['slot']))
        row=dbh.fetch()
        if row['count']==0:
            result.para("Sorry, No text offsets are known to exists for this slot... You might want to guess the parity order of this slot from the sorounding slots")
            return
        
        if not query.has_key('offset'):
            query['offset']=row['min']

        ## selector
        result.start_form(query)
        result.start_table()
        result.selector("Other offsets within this slot (%s offsets):" % row['count'],'offset','select offset,offset from raid_%s where  offset %% %s =%r',(tablename,query['period'],query['slot']),case=query['case'],onchange="this.form.submit();")
        result.end_form()
        result.end_table()
        
        try:
            for offset,slot in zip(range(int(query['offset'])-1,int(query['offset'])+2),range(int(query['slot'])-1,int(query['slot'])+2)):
                dbh.execute("select %s,if(disk0<0,'P',disk0) as disk0, if(disk1<0,'P',disk1) as disk1,if(disk2<0,'P',disk2) as disk2 from raid_map_%s where slot=%r",(offset,tablename,slot))
                row = dbh.fetch()
                if not row: continue
                
                uis = []
                result.row("Offset %s, slot %s" % (offset,slot),colspan=50,align='center',bgcolor=config.HILIGHT)
                result.row(row['disk0'],row['disk1'],row['disk2'],bgcolor=config.BGCOLOR1,align='center')
                for i in range(int(query['disk_count'])):
                    tmp = self.ui(result)
                    fd = open("%s" % (query['datafile%u'%i]),'r')
                    fd.seek(1024*offset)
                    data = fd.read(1024)

                    if row['disk%u' % i]=='P':
                        color = 'red'
                    else: color='black'
                    
                    if not query.has_key('verbose'):
                        data = data[:80]+"    ........   "+data[-80:]
                    
                    tmp.text(data+"\n",font='typewriter',sanitise='full',wrap='full',wrap_size=config.WRAP/3,color=color)
                    fd.close()
                    uis.append(tmp)

                result.row(*uis)

        except KeyError:
            pass
        
        result.end_table()

        
        ##result.table(
##            columns = ['offset'],
##            names = ['Offset'],
##            table='raid_%s' % tablename,
##            where = ' offset %%%% %s =%r' % (query['period'],query['slot']),
##            links = [ result.make_link(query,'offset') ],
##            case=query['case'],
##           )

        ## Do the navigation bar
        del query['offset']
        slot = int(query['slot'])
        result.pageno = slot
        result.nav_query = query
        result.nav_query['__target__'] = 'slot'
        result.next =slot+2
        if slot>1:
            result.previous=slot-2
        else:
            result.previous=None

import pyflag.Graph as Graph

class ExgrepThumb(Graph.Thumbnailer):
    def Extract(self):
        try:
            self.fd.seek(self.offset)
            while 1:
                f=self.fd.read(1000000)
                if not f: break
                yield f

            self.fd.close()
        except IOError:
            pass
        
    def __init__(self,case,datafile,offset,size,extension):
        self.case=case
        self.datafile=datafile
        self.offset=offset
        self.size=size
        self.extension = extension
        self.fd=IO.open(self.case,self.datafile)

class ExgrepFiles(ExgrepThumb):
    """ This is the same as the thumbnail class, except we do not want to make thumbnails, we just return the full image back.
    """
    ## We dont want to produce any thumbnails
    dispatcher = {}

    ## Copy the binary data out as is.
    def Unknown(self):
        return self.Extract_size(self.size)

import pyflag.Strings
    
class ExtractFiles(Reports.report):
    """ Extract files from corrupted disks by using Magic """
    parameters = {"iosource":"iosource"}
    name = "Extract files"
    family = "Unstructured Forensics"
    description = "Extract files from unstructured data based on common file signatures"
    order = 50
    running=None

    def form(self,query,result):
        try:
            result.case_selector()
            result.ruler()
            result.meta_selector(message='Select IO Data Source', case=query['case'], property='iosource')
        except (KeyError,IOError):
            pass    
        
    def analyse(self,query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['iosource'])
        import Exgrep
        
        dbh.execute("create table if not exists `exgrep_%s` (`offset` BIGINT NOT NULL ,`length` INT NOT NULL ,`type` VARCHAR( 50 ) NOT NULL)",tablename)
        ## This starts a new thread for performing the exctraction in the back ground, the display method can then proceed while the extraction is taking place. We need to do some effort in syncronising the threads, but this will pay off in the end.
        import threading

        class ThumbNailGenerator(ExgrepThumb):
            """ A dummy generator to generate thumbnails """
            def set_image(self,name):
                pass
        
        class ExtractThread(threading.Thread):
            def run(self):
                for a in Exgrep.process(query['case'],query['iosource']):
                    dbh.execute("insert into `exgrep_%s` set offset=%r,length=%r,type=%r",(tablename,a['offset'],a['length'],a['type']))
                    thumbnail = ThumbNailGenerator(query['case'],query['iosource'],a['offset'],a['length'],a['type'])
                    thumbnail.display()

        ## Note this is not scalable if multiple requests are running at once!!!!
        self.running=ExtractThread()
        self.running.start()

    def progress(self,query,result):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['iosource'])
        dbh.execute("select max(offset)/1024/1024 as `max` from exgrep_%s",tablename)
        row=dbh.fetch()
        result.heading("Progress Report")
        result.para("Extracting files from raw image %s. (Last file extracted at offset %s Mbytes)" % (query['iosource'],row['max']))
        result.table(
            columns=['count(*)','type'],
            names=['Count','Type'],
            table='exgrep_%s' % tablename,
            case = query['case'],
            groupby = 'type'
            )

        return result

    def reset(self,query):
        dbh = self.DBO(query['case'])
        tablename = dbh.MakeSQLSafe(query['iosource'])
        dbh.execute("drop table `exgrep_%s`",tablename)

    def display(self,query,result):
        dbh = self.DBO(query['case'])
        opts = {"valign":"top","border":"10"}
        tablename = dbh.MakeSQLSafe(query['iosource'])
        if not query.has_key('limit'): query['limit']= 0

        #Prepare a new query based on the current one less any extra parameters passed around
        new_q = query.clone()
        del new_q['limit']
        del new_q['offset']
        del new_q['mode']
        
        xcount = 3
        ycount = 20
        
        if query.has_key('mode'):
            dbh.execute("select offset,length,type from `exgrep_%s` where offset=%s",(tablename,query['offset']))
            row = dbh.fetch()
            image = ExgrepFiles(query['case'],query['iosource'],row['offset'],row['length'],row['type'])
            result.heading("Viewing file at offset %s in %s" % (row['offset'],query['iosource']))
            result.text("Classified as %s by magic" % image.GetMagic())

            def thumbnail(query):
                ## Make the thumbnail
                thumb = ExgrepThumb(query['case'],query['iosource'],row['offset'],row['length'],row['type'])
                output=self.ui(result)
                output.image(thumb,width="200")
                return output

            def fullsize(query):
                ## Just return the whole object back
                output=self.ui(result)
                output.image(image)
                return output

            def download(query):
                if image:
                    result.result=image.display()
                    result.type=image.GetContentType()
                    result.display=result.__str__
                return None
            
            def hexview(query):
                output=self.ui(result)
                try:
                    max=config.MAX_DATA_DUMP_SIZE
                except AttributeError:
                    max=1024

                #Set limits for the dump
                try:
                    limit=int(query['hexlimit'])
                except KeyError:
                    limit=0
                dump = FlagFramework.HexDump(image.display(),output)
                dump.dump(offset=limit,limit=max)

                #Do the navbar (Note we operate on the result directly - gotta love the scoping rules in python...)
                result.next=limit+max
                if result.next>row['length']:
                    result.next=None
                result.previous=limit-max
                result.nav_query=query.clone()
                result.nav_query['__target__']='hexlimit'

                if result.previous<0:
                    result.previous = None
                result.pageno=limit/max
                return output

            def strings(query):
                fd=IO.open(query['case'],query['iosource'])
                str = pyflag.Strings.StringExtracter(fd)
                try:
                    offset=query['stroffset']
                    if offset.startswith("!"):
                    ## We search backwards for the correct offset
                        offset=str.find_offset_prior(int(offset[1:])+row['offset'],config.PAGESIZE-1)-row['offset']
                        if offset<0: offset=0
                except KeyError:
                    offset=0

                q=query.clone()
                del q['mode']
                del q['hexlimit']

                output=self.ui()
                output.start_table()
                row_number=0
                for i in str.extract_from_offset(row['offset']+int(offset)):
                    row_number+=1
                    if row_number>config.PAGESIZE: break
                    file_offset=i[0]-row['offset']
                    if file_offset>row['length']:
                        break
                    tmp_link=self.ui()
                    tmp_link.link("0x%x (%s)" % (file_offset,file_offset),q,mode="HexDump",hexlimit=file_offset)
                    tmp_string=self.ui()
                    tmp_string.text(i[1],color="red",sanitise="full")
                    output.row(tmp_link,'  ',tmp_string,valign="top")                                   
                    
                result.nav_query=query.clone()
                result.nav_query['__target__']='stroffset'
                result.next=file_offset
                if row_number<config.PAGESIZE: result.next=None
                result.previous="!%s" % offset
                result.pageno=offset
                
                return output
                          
            result.notebook(
                names=["Thumbnail","View FullSize","Download","HexDump","Strings"],
                callbacks=[thumbnail,fullsize,download,hexview,strings],
                context='mode'
                )
        else:
            ## Query does not have mode in it:
            try:
                dbh.execute("select type from  `exgrep_%s` group by type",tablename);
                types=['All'] + [ row['type'] for row in dbh ]

                try:
                    if query['type']=='All':
                        raise KeyError
                    where=" where type=%r " % query['type']
                except KeyError:
                    where=''
                    
                dbh.execute("select count(*) as `count` from  `exgrep_%s` %s ",(tablename,where));
                max_number=dbh.fetch()['count']

                rows=[]
                dbh.execute("select offset,length,type from `exgrep_%s` %s order by offset limit %s,%s",(tablename,where,query['limit'],xcount*ycount))
                    
                rows=[]
                for d in dbh:
                    rows.append(d)
                    if len(rows) == xcount*ycount:
                        break

                if len(rows) < xcount*ycount and self.running and self.running.isAlive():
                    self.progress(query,result)
                    result.refresh(3,query)
                    return

                xuis = []
                count=0
                result.heading("Analysing raw image %s"%query['iosource'])
                result.start_form(query)
                result.start_table()
                result.const_selector("Limit viewing to one file type: ",'type',types,types,onchange="this.form.submit();")
                result.end_table()
                result.end_form(None)
                for row in rows:
                    count+=1
                    ## Make the thumbnail
                    thumb = ExgrepThumb(query['case'],query['iosource'],row['offset'],row['length'],row['type'])

                    #Create a container for it
                    container = self.ui()
                    container.start_table(border='3',width="100%",height="100%")
                    tmp = self.ui(result)
                    tmp.image(thumb,width="200")
                    link_ui =  self.ui(result)
                    link_ui.link(tmp,query,mode='selected',offset=row['offset'])
                    container.row(link_ui)

                    #A nametag underneath the thumbnail
                    container.row("%s.%s" % (row['offset'],row['type']))
                    xuis.append(container)
                    if len(xuis)>xcount:
                        result.row(*xuis,**opts)
                        xuis = []

                ## Get the last  line in if its too short
                for i in range(len(xuis),xcount+1):
                    xuis.append("")

                result.row(*xuis,**opts)

                ## Build the navigation bar
                result.next=int(query['limit'])+xcount*ycount
                ## Are we at the end of the table?
                if count<xcount*ycount:
                    result.next=None
                result.previous = int(query['limit'])-xcount*ycount
                if result.previous<0:
                    result.previous=None

                result.pageno="%s / %s" % (int(query['limit'])/xcount/ycount,max_number/xcount/ycount)

            except KeyError,e:
                print "Got key error %s"%e

class BrowseDiskSector(Reports.report):
    """ Browses the disk image sector by sector """
    parameters = {"iosource":"iosource","limit":"numeric"}
    name = "Browse Disk Sectors"
    family = "Unstructured Forensics"
    description="Browse disk image a sector at a time "
    order=60

    def form(self,query,result):
        try:
            result.case_selector()
            result.ruler()
            result.meta_selector(message='Select IO Data Source', case=query['case'], property='iosource')
            result.textfield("Offset in bytes to view from:",'limit')
        except (KeyError,IOError):
            pass    

    def display(self,query,result):
        dbh = self.DBO(query['case'])
        io=IO.open(query['case'],query['iosource'])
        
        try:
            limit=int(query['limit'])
        except KeyError:
            limit=0

        result.heading("Viewing '%s' at offset %s" % (query['iosource'],limit))

        ## Set limits for the dump
        try:
            max=config.MAX_DATA_DUMP_SIZE
        except AttributeError:
            max=1024

        def textview(query):
            output=self.ui(result)        
            io.seek(limit)
            data=io.read(max)
            output.text(data,font='typewriter',sanitise='full',wrap='full')
            output.text(finish=1)
            do_navbar(query)
            return output
        
        def hexview(query):
            output=self.ui(result)        
            io.seek(limit)
            data=io.read(max)
            dump = FlagFramework.HexDump(data,output)
            io.close()
            
            dump.dump(limit=max,base_offset=limit)
            do_navbar(query)
            return output

        def do_navbar(query):
            ## Navbar stuff
            result.next=limit+max

            result.previous=limit-max
            result.nav_query=query.clone()
            result.nav_query['__target__']='limit'

            if result.previous<0:
                result.previous = None
            result.pageno=limit/max
            
        result.notebook(
            names=['HexDump','Text View'],
            callbacks=[hexview,textview],
            context='mode',
            )
