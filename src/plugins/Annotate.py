# ******************************************************
# Copyright 2007
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
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
from pyflag.TableObj import StringType,TimestampType,EditableStringType,InodeType,FilenameType, TimelineObj, IntegerType, IPType
import pyflag.Registry as Registry

class ViewCaseReport(Reports.report):
    """ Show annotated entities in this case """
    name = "View Case Report """
    family = "Case Management"
    order = 70

    def display(self,query,result):
        def Annotated_inodes(query, result):
            result.table(
                elements = [ InodeType('Inode', 'annotate.inode', case=query['case']),
                             FilenameType(case=query['case']),
                             StringType('Category','category'),
                             StringType('Note','note'),
                             ],
                table = 'annotate join file on file.inode=annotate.inode',
                case = query['case'],
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
