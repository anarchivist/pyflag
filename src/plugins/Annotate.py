# ******************************************************
# Copyright 2007
#
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
""" This file contains all the things related to annotations.

Users may annotate important things for later reference.
"""
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
from pyflag.TableObj import StringType,TimestampType,EditableStringType,InodeType,FilenameType, TimelineObj, IntegerType
import pyflag.Registry as Registry

class ViewAnnotation(Reports.report):
    """ View the annotated Inodes """
    name = "View Annotations"
    family = "Case Management"
    order = 40

    def display(self, query,result):
        result.heading("Annotated Inodes for case %s" % query['case'])
        result.table(
            elements = [ InodeType('Inode', 'annotate.inode', case=query['case']),
                         FilenameType(case=query['case']),
                         StringType('Category','category'),
                         StringType('Note','note'),
                         ],
            table = 'annotate join file on file.inode=annotate.inode',
            case = query['case'],
            )

class ViewCaseTimeline(Reports.report):
    """ View the case time line """
    name = "View Case Timeline"
    family = "Case Management"
    order = 50

    def display(self, query, result):
        original_query = query
 
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
      
        result.heading("Case Time Line for case %s" % query['case'])
        result.text("Add arbitrary event:")
        result.popup(add_new_event, "Add abritrary event", 
                                            case=query['case'], 
                                            icon="clock.png")
        result.text("\n")
 
        result.table(
            elements = [ IntegerType(name='id', column='id'),
                         TimestampType(name='Time', column='time'),
                         EditableStringType('Notes', 'notes'),
                         StringType('Category', 'category')
                        ],
            table = 'timeline',
            case = query['case'],
        )



class ViewIPsOfInterest(Reports.report):
    """ View all IPs of interest """
    name = "View IPs of interest """
    family = "Case Management"
    order = 60

    def display(self,query,result):
        result.heading("IPs of interest for case %s" % query['case'])
        result.text("\n\nNYI\n\n")

class ViewCaseReport(Reports.report):
    """ View a pretty print case report """
    name = "View Case Report """
    family = "Case Management"
    order = 70

    def display(self,query,result):
        result.heading("Case report for %s" % query['case'])
        result.text("\n\nNYI\n\n")
