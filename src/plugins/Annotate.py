# ******************************************************
# Copyright 2007
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
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
""" This file contains all the things related to annotations.

Users may annotate important things for later reference.
"""
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
from pyflag.ColumnTypes import StringType,TimestampType,EditableStringType,InodeIDType,FilenameType, IntegerType, IPType, add_display_hook, clear_display_hook
import pyflag.Registry as Registry
import pyflag.DB as DB
import pyflag.TableObj as TableObj
import pyflag.TableActions as TableActions

class AnnotationCaseInit(FlagFramework.EventHandler):
    """ A handler for initialising the annotation framework """
    
    def create(self, case_dbh, case):
        case_dbh.execute("""CREATE TABLE if not exists `annotate` (
        `id` INT(11) not null auto_increment,
        `inode_id` int not null,
        `note` TEXT,
        `category` VARCHAR( 250 ) NOT NULL default 'Note',
        PRIMARY KEY(`id`)
        )""")        

        case_dbh.execute("""CREATE TABLE if not exists `timeline` (
        `id` INT(11) not null auto_increment,
        `time` timestamp,
        `notes` TEXT,
        `category` VARCHAR( 250 ) NOT NULL default 'Note',
        PRIMARY KEY(`id`)
        )""")        

        # The id field here feels kind of redundant, but it keeps DB.py happy for the
        # caching stuff...
        case_dbh.execute("""CREATE TABLE if not exists `interesting_ips` (
        `id` INT(11) not null auto_increment,
        `ip` INT(11) UNSIGNED UNIQUE,
        `notes` TEXT,
        `category` VARCHAR( 250 ) NOT NULL default 'Note',
        PRIMARY KEY(`id`)
        )""")

class ViewCaseReport(Reports.report):
    """ Show annotated entities in this case """
    name = "View Case Report """
    family = "Case Management"
    order = 70

    def display(self,query,result):
        def Annotated_inodes(query, result):
            result.table(
                elements = [ InodeIDType(case=query['case']),
                             FilenameType(case=query['case']),
                             StringType('Category','category'),
                             StringType('Note','note'),
                             ],
                table = 'annotate',
                case = query['case'],
                filter="filter1",
                )

        def Timeline(query, result):
            def add_new_event(query, result):
                timeline = TimelineObj(case=query['case'])

                ## We got submitted - actually try to do the deed:
                if 'Add To Timeline' in query.getarray('__submit__'):
                    result.start_table()
                    newEvent = timeline.add(query, result)
                    result.para("The following is the new timeline entry:")
                    timeline.show(newEvent,result)
                    result.end_table()
                    result.link("Close this window", target=original_query, pane='parent')
                    return result

                result.start_form(query, pane='self')
                result.heading("Add an arbitrary event")
                timeline.add_form(query,result)
                result.end_form(value="Add To Timeline")
                return result

            result.table(
                elements = [ IntegerType(name='id', column='id'),
                             TimestampType(name='Time', column='time'),
                             EditableStringType('Notes', 'notes'),
                             StringType('Category', 'category')
                            ],
                table = 'timeline',
                case = query['case'],
                filter="filter2",
            )

            result.toolbar(add_new_event, "Add abritrary event", 
                                                icon="clock.png")

        def Annotated_IPs(query, result):            
            result.table(
                elements = [ IntegerType('id','id'),
                             IPType('ip', 'ip'),
                             StringType('Notes', 'notes'),
                             StringType('Category', 'category')
                            ],
                table = 'interesting_ips',
                case = query['case'],
                filter="filter3",
            )

        result.heading("Report for case %s" % query['case'])
        result.notebook(
            names = [ 'Inodes',
                      'Timeline',
                      'IP Addresses'],
            callbacks = [ Annotated_inodes,
                          Timeline,
                          Annotated_IPs],
            )


class AnnotationObj(TableObj.TableObj):
    def store_inode(self, fieldname, proposed_value, query=None, id=None, result=None):
        dbh = DB.DBO(self.case)
        dbh.execute("select inode_id from inode where inode = %r limit 1", proposed_value)
        row = dbh.fetch()
        query.set(fieldname, row['inode_id'])

    def inode_action(self, table_obj, description = None, variable= None, result=None, defaults=None):
        dbh = DB.DBO(self.case)
        dbh.execute("select inode from inode where inode_id = %r limit 1", defaults[variable])
        row = dbh.fetch()
        result.defaults.set(variable, row['inode'])

        result.textfield(description, variable, size=40)
        
    table = "annotate"
    columns = (
        'inode_id', 'Inode', 
        'note','Notes', 
        'category', 'category',
        )

    add_constraints = {
        'category': TableActions.selector_constraint,
#        'inode_id': store_inode,
        }

    edit_constraints = {
        'category': TableActions.selector_constraint,
#        'inode_id': store_inode,
        }

    def __init__(self, case=None, id=None):
        self.form_actions = {
            #'inode_id': self.inode_action,
            'inode_id': TableActions.noop,
            'note': TableActions.textarea,
            'category': FlagFramework.Curry(TableActions.selector_display,
                              table='annotate', field='category', case=case),
            }

        TableObj.TableObj.__init__(self,case,id)

## We add callback to allow annotation of Inode displays:
def render_annotate_inode_id(self, inode_id, row, result):
    inode = ''
    if not inode_id: return ''
    
    link = FlagFramework.query_type(case=self.case,
                                    family='Disk Forensics',
                                    report='ViewFile',
                                    mode = 'Summary',
                                    inode_id = inode_id)
    ## This is the table object which is responsible for the
    ## annotate table:
    original_query = result.defaults

    def annotate_cb(query, result):
        # We just close since we have just deleted it
        if query.has_key('delete'):
            del query['delete']
            return result.refresh(0, query, pane='parent')

        annotate = AnnotationObj(case=self.case)
        ## We are dealing with this inode
        query.set('inode_id',inode_id)
        ## does a row already exist?
        row = annotate.select(inode_id=inode_id)
        if row:
            query['id'] = row['id']

        print query
        ## We got submitted - actually try to do the deed:
        if 'Annotate' in query.getarray('__submit__'):
            result.start_table()
            if row:
                new_id=annotate.edit(query,result)
            else:
                new_id=annotate.add(query,result)

            result.para("The following is the new annotated record:")
            annotate.show(new_id,result)

            result.end_table()
            result.link("Close this window", target=original_query, pane='parent')
            return result

        ## Present the user with the form:
        result.start_form(query, pane='self')
        result.heading("Inode %s" % inode)
        if row:
            annotate.edit_form(query,result)
        else:
            annotate.add_form(query,result)            

        result.end_form(value='Annotate')

        def del_annotation(query, result):
            dbh = DB.DBO(query['case'])
            dbh.delete('annotate', "inode_id=%r" % inode_id)

            del query['note']
            del query['category']
            query['delete'] = 'yes'

            result.refresh(0, query, pane='parent')

        result.toolbar(cb=del_annotation, icon='delete.png',tooltip="Click here to delete this annotation")

    ## Check to see if the inode exists at all:
    dbh = DB.DBO(self.case)
    dbh.execute("select inode,inode_id from inode where inode.inode_id = %r", inode_id)
    row = dbh.fetch()
    if not row: return ''

    inode = row['inode']
    annotate = AnnotationObj(case=self.case)
    row = annotate.select(inode_id=inode_id)

    tmp1 = result.__class__(result)
    tmp2 = result.__class__(result)
    if row:
        tmp1.popup(annotate_cb, row['note'], icon="balloon.png")
    else:
        tmp1.popup(annotate_cb, "Annotate", icon="pen.png")

    if len(inode)> 15:
        value1="..%s" % inode[-13:]
    else:
        value1 = inode
    tmp2.link(value1, tooltip = inode, target=link)
    result.row(tmp1,tmp2)

def operator_annotated(self, column, operator, pattern):
    """ This operator selects those inodes with pattern matching their annotation """
    return '`%s`.`%s` in (select annotate.inode_id from annotate' \
           ' where note like "%%%s%%")' % (self.table,
                                           self.column,
                                           pattern)

add_display_hook(InodeIDType, "render_annotate_inode_id", render_annotate_inode_id)
InodeIDType.operator_annotated = operator_annotated

class InterestingIPObj(TableObj.TableObj):
    table = "interesting_ips"
    columns = (
        'ip', 'IP Address',
        'notes','Notes',
        'category', 'category',
        )

    add_constraints = {
        'category': TableActions.selector_constraint,
        }

    edit_constraints = {
        'category': TableActions.selector_constraint,
        }

    def __init__(self, case=None, id=None):
        self.form_actions = {
            'notes': TableActions.textarea,
            'category': FlagFramework.Curry(TableActions.selector_display,
                              table='interesting_ips', field='category', case=case),
            }
        self.case=case
        self.key='id'
        TableObj.TableObj.__init__(self,case,id)

    def show(self,id,result):
        dbh = DB.DBO(self.case)
        dbh.execute("select * from %s where %s=%r",
                         (self.table,self.key,id))

        row=dbh.fetch()
        dbh.execute("select inet_ntoa(ip) as ip from %s where %s=%r", 
                                (self.table, self.key, id))
        iprow=dbh.fetch()
        row['ip']=iprow['ip']

        if not row:
            tmp=result.__class__(result)
            tmp.text("Error: Record %s not found" % id,color='red')
            result.row(tmp)
            return
        result.start_table()
        for k,v in zip(self._column_keys,self._column_names):
            ## If there are any specific display functions we let them
            ## do it here...
            cb = self.display_actions.get(k,None)
            if not cb:
                cb = getattr(self.__class__,"display_%s" % k, None)
                
            if cb:
                cb(self,description=v, variable=k, ui=result, defaults=row)
            else:
                try:
                    tmp = result.__class__(result)
                    tmp.text(row[k],color='red')
                    result.row(v,tmp)
                except KeyError:
                    pass

def render_annotated_ips(self, value, row, result):
    self.row = row
    original_query=result.defaults
    ## We can only have interesting IPs if we are associated with a case
    ## otherwise (e.g. for previews), it doesn't make sense..
    if original_query.has_key('case'):
        interestingIPs = InterestingIPObj(original_query['case'])
    else:
        interestingIPs = None

    def edit_ips_of_interest_cb(query, result):

        ## We got submitted - actually try to do the deed:
        if 'Edit Note' in query.getarray('__submit__'):
            result.start_table()
            row = interestingIPs.select(_ip='inet_aton(%r)' % value)
            if row:
                query['id'] = row['id']
            newEvent = interestingIPs.edit(query, result)

            result.para("The following is the new annotated record:")
            interestingIPs.show(newEvent,result)

            result.end_table()
            result.link("Close this window", target=original_query, pane='parent_pane')
            return result

        ## Present the user with the form:
        result.start_form(query, pane='self')
        result.heading("Adding a note for IP %s" % value)

        row = interestingIPs.select(_ip='inet_aton(%r)' % value)
        if row:
            query['id'] = row['id']

        query['ip']=value
        ## Then show the form
        interestingIPs.edit_form(query,result)
        result.end_form(value='Edit Note')

    def add_to_ips_of_interest_cb(query, result):
        ## We got submitted - actually try to do the deed:
        if 'Add Note' in query.getarray('__submit__'):
            result.start_table()
            newEvent = interestingIPs.add(query, result)

            result.para("The following is the new annotated record:")
            interestingIPs.show(newEvent,result)

            result.end_table()
            result.link("Close this window", target=original_query, pane='parent_pane')
            return result

        ## Present the user with the form:
        result.start_form(query, pane='self')
        result.heading("Adding a note for IP %s" % value)

        ## First set it up with the info from the table as defaults
        defaultInfo = dict() 
        defaultInfo['ip']=value
        defaultInfo['notes']=""

        defaultInfo['notes'] = "IP Address of Interest"

        ## Then show the form
        interestingIPs.add_form(query,result, defaultInfo)
        result.end_form(value='Add Note')

    ## Check if this IP has any notes with it:
    if interestingIPs:
        row = interestingIPs.select(_ip='inet_aton(%r)' % value)
    else:
        row = None

    ## Provide a way for users to save the IP address:
    opts = {}
    if row:
        result.popup(edit_ips_of_interest_cb, 
                     row['notes'], icon="balloon.png")
        opts = {'class': 'match'}
    elif interestingIPs:
        result.popup(add_to_ips_of_interest_cb, 
                     "Add a note about this IP", 
                     icon="treenode_expand_plus.gif")

add_display_hook(IPType, "render_annotated_ips", render_annotated_ips, 0)

class TimelineObj(TableObj.TableObj):
    table = "timeline"
    columns = (
        'time', 'Time',
        'notes','Notes',
        'category', 'category',
        )

    add_constraints = {
        'category': TableActions.selector_constraint,
        }

    edit_constraints = {
        'category': TableActions.selector_constraint,
        }

    def __init__(self, case=None, id=None):
        self.form_actions = {
            'notes': TableActions.textarea,
            'category': FlagFramework.Curry(TableActions.selector_display,
                              table='timeline', field='category', case=case),
            }
        self.case=case
        TableObj.TableObj.__init__(self,case,id)

## Annotate timeline objects:
def render_timeline_hook(self, value, row, result):
    original_query = result.defaults

    def add_to_timeline_cb(query, result):

        timeline = TimelineObj(case=query['case'])

        ## We got submitted - actually try to do the deed:
        if 'Add to Timeline' in query.getarray('__submit__'):
            result.start_table()

            newEvent = timeline.add(query, result)

            result.para("The following is the new annotated record:")
            timeline.show(newEvent,result)

            result.end_table()
            result.link("Close this window", target=original_query, pane='parent_pane')
            return result

        ## Present the user with the form:
        result.start_form(query, pane='self')
        result.heading("Adding an event at time %s" % value)

        ## First set it up with the info from the table as defaults
        defaultInfo = dict() 
        defaultInfo['time']=value
        defaultInfo['notes']=""
        for infoFromCol in row:
                defaultInfo['notes']+=str(infoFromCol)
                defaultInfo['notes']+=":"
                defaultInfo['notes']+=str(row[infoFromCol])
                defaultInfo['notes']+="     \n"

        #query.default('notes', defaultInfo['notes'])
        ## Then show the form
        timeline.add_form(query,result, defaultInfo)
        result.end_form(value='Add to Timeline')

    tmp1 = result.__class__(result)

    ## You can only add to timeline if you are dealing with a case
    if original_query.has_key('case') and value:
        tmp1.popup(add_to_timeline_cb, "Add to Timeline", 
                   icon="stock_timer.png")
        result.row(tmp1, value)
    else:
        result.row(value)

clear_display_hook(TimestampType)
add_display_hook(TimestampType, "render_timeline_hook", render_timeline_hook)
