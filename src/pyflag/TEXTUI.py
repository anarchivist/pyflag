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
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
""" This is an implementation of an ASCII Text UI suitable for producing simple automated reports.
"""
import re, types, textwrap, csv, sys
import pyflag.FlagFramework as FlagFramework
import pyflag.DB as DB
import pyflag.conf
import pyflag.UI as UI
config=pyflag.conf.ConfObject()
import pyflag.Registry as Registry
import cStringIO

class TEXTUI(UI.GenericUI):
    """ A simple text UI """
    def __init__(self, default= None, query=None):
        self.result = ""
        self.text_var = ''
        self.current_table=None


        if query:
            self.defaults=query

        if default:
            self.defaults = default.defaults

    def display(self):
        if self.current_table:
            self.end_table()

        return self.result

    def __str__(self):
        return self.result

    def heading(self,string):
        self.result+=string+"\r\n"+ "-" * len(string) + "\r\n\r\n"

    def pre(self,string):
        self.result+=string
        
    def start_table(self,**options):
        if self.current_table==None:
            self.current_table_size=[0,0]
            self.current_table=[]

    def table(self,sql="select ",columns=[],names=[],links=[],table='',where='',groupby = None,case=None,callbacks={},**opts):
        names=list(names)
        
        ## Establish the sorting order
        try:
            self.sort=[list(names).index(self.defaults['order']),'order']
        except KeyError:
            try:
                self.sort=[self.defaults['dorder'],'dorder']
            except KeyError:
                self.sort=[0,'order']
                
        self.filter_conditions=[]
        self.filter_text=[]

        try:
            if not groupby:
                groupby=self.defaults['group_by']
        except KeyError:
            groupby=None

        # Get a new SQL generator for building the table with.
        generator,new_query,names,columns,links = self._make_sql(sql=sql,columns=columns,names=names,links=links,table=table,where=where,groupby = groupby,case=case,callbacks=callbacks, query=self.defaults)

        output = cStringIO.StringIO()

        writer=None
        for row in generator:
            if not writer:
                ## Print the headers in a comment field:
                output.write("#%s\r\n" % ','.join(row.keys()))        
                writer=csv.DictWriter(output, row.keys())

            writer.writerow(row)

        output.seek(0)
        self.result+=output.read()

    def text(self,*cuts,**options):
        self.text_var += "".join(cuts)
        try:
            if options['wrap']=='full':
                for line in self.text_var.splitlines(True):
                    new_lines = textwrap.wrap(line, config.WRAP)
                    for i in range(len(new_lines)):
                        new_line = new_lines[i]
                        self.result+=new_line
                        if len(new_line)<len(line) and i<len(new_lines)-1:
                            self.result += " " * (config.WRAP - len(new_line)) + "\\"
                return
        except KeyError:
            pass

        self.result+=self.text_var
        self.text_var = ''
        
    def notebook(self,names=[],context="notebook",callbacks=[],descriptions=[]):
        """ This text implementation of notebook will only show the page which is currently selected """
        print "%r" % self.defaults
        query=self.defaults.clone()            
        try:
            context_str=query[context]
            cbfunc=callbacks[names.index(context_str)]
        except (ValueError,KeyError):
            cbfunc=callbacks[0]
            context_str=names[0]

        result=self.__class__(self)
        cbfunc(query,result)

        self.result += result.display()

    def end_table(self):
        for row_index in range(len(self.current_table)):
            row=self.current_table[row_index]
            temp = []
            
            max_height = 0
            for item in row:
                width=0
                lines =  item.splitlines()
                if len(lines)>max_height: max_height=len(lines)
                
                for line in lines:
                    if width<len(line): width=len(line)

                #fill the line out to max width:
                lines = [ line + " "*(width-len(line)) for line in lines]

                temp.append(lines + ["\r\n"] * (max_height - len(lines)))

            for i in range(0,max_height):
                try:
                    self.result+="".join([c[i] for c in temp ]) + "\r\n"
                except IndexError:
                    pass

    def toolbar(self,cb=None,text=None,icon=None,popup=True,tooltip=None,link=None):
        pass

    def row(self, *columns, **options):
        if self.current_table == None:
            self.start_table()

        ## Add an extra row on the end
        self.current_table_size[0]+=1
        if self.current_table_size[1]<len(columns):
            self.current_table_size[1]=len(columns)

        column_widgets=[]
        for i in range(len(columns)):
            col=columns[i]
            if isinstance(col,self.__class__):
                col=col.display()
            column_widgets.append(col)
            
        ##Attach the column to row at the end of the table:
        self.current_table.append(column_widgets)

    def tree(self,tree_cb = None, pane_cb=None, branch = ('/'), layout="horizontal"):
        """ A Text tree implementation """
        query = self.defaults

        try:
            ## Get the right part:
            branch=FlagFramework.splitpath(query['open_tree'])
        except KeyError:
            branch=['']

        #Start building the tree using the branch.
        def draw_branch(depth,tree_array):
            #We search through all the items until we find the one
            #that matches the branch for this depth, then recurse into
            #it.
            branch_array=branch[:depth]
            path = FlagFramework.joinpath(branch[:depth])
            for k,v,t in tree_cb(path):
                if not k: continue
                if not t: continue
                tree_array.append((depth,k,v,t))

                try:
                    if k == branch[depth]:
                        #Recurse into the next level in the tree
                        draw_branch(depth+1,tree_array)
                except IndexError:
                    pass

        tree_array = []

        #The first item in the tree is the first one provided in branch
        if not branch[0]:
            tree_array.append((0,'/','/','branch'))
        else:
            tree_array.append((0,branch[0],branch[0],'branch'))

        #Build the tree_array
        draw_branch(1,tree_array)       

        left = self.__class__(self)
                        
        for depth,k,v,t in tree_array:
            icon = '-'
            if t=="branch":
                icon = '+'
            left.text(" "*depth + icon + v.__str__() + "\r\n")

        right = self.__class__(self)
        path = FlagFramework.joinpath(branch)
        pane_cb(path, right)

        self.row(left, right)

    def refresh(self, int, query):
        pass

    def link(self,string,target=FlagFramework.query_type(()),**target_options):
        pass

    def para(self,string,**options):
        self.result += string + "\r\n\r\n"
