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
#  Version: FLAG 0.4 (12-02-2004)
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

""" Flag module to manage the knowledge base obtained by analysing TCP Dump

The knowledge base is a graph which consists of nodes and edges. Nodes are characterised by their type and name. Each row in the table is an edge between nodes which are infered.
"""

description = "Knowledge Base"
order = 60
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.DB as DB

class ViewKB(Reports.report):
    """ Views the knowledge base edge tables """
    parameters = {"start":"alphanum"}
    name = "View KB table"
    family = "Knowledge Base"
    description = "View the Knowledge base table"

    def form(self,query,result):
        result.case_selector(message = 'Select case to operate on')
        result.hidden('start','ok')

    def display(self,query,result):
        result.heading("Knowledge Base table in case %s" % query['case'])
        result.table(
            columns = ('k.packet','n.type','n.value','m.type','m.value', 'description', 'link'),
            names = ('PID','Type','Value','P Type','P Value','Desc','Link'),
            table = 'knowledge as k, knowledge_node as n, knowledge_node as m',
            where = 'k.name = n.name and k.pname = m.name',
            case = query['case'],
            links = [
               FlagFramework.query_type((),case=query['case'],report='ShowPacket',family='TCPDumpAnalysis',__target__ = 'packet_id')
            ])

class DisplayObject(Reports.report):
    """ Displays the object passed in a nice tree structure """
    parameters = {"object_name":"sqlsafe"}
    name = "View object"
    family = "Knowledge Base"
    description = "Show object hierarchy"
    order = 20

    def form(self,query,result):
        result.case_selector()
        result.textfield("Enter object name to show:",'object_name')

    def display(self,query,result):
        result.heading("Object tree for %r" % query['object_name'])

        dbh = self.DBO(query['case'])
        branch = [query['object_name']]
        name = query['object_name']
        ##First we follow the object up the tree to find the root of the tree
        while 1:
            dbh.execute("select pname from knowledge where name=%r and link = 'no'",name)
            rs = dbh.fetch()
            if not rs: break

            branch.append(rs['pname'])
            name = rs['pname']

        ##Reverse the branch to render the tree from the root down
        branch.reverse()
        
        ##Callback to display the tree
        def tree_cb(branch):
            """ Callback for drawing the KB tree """
            name = branch[-1]
            result = []

            dbh = self.DBO(query['case'])
            ##First get properties of the object
            dbh.execute("select a.name, description,a.value from knowledge as b, knowledge_node as a where a.name=b.name and pname =%r and link='no' group by name",(name))
            for rs in dbh:
                tmp = self.ui()
                tmp.text("%s: " % rs['description'],color = 'black')
                tmp.text(rs['value'],color='blue')
                result.append((rs['name'],tmp,'branch'))

            ##Now get the transitive links this object connects to
            dbh.execute("select a.name, description,a.value from knowledge as b, knowledge_node as a where a.name=b.name and pname =%r and link='transitive' group by name",(name))
            for rs in dbh:
                tmp = self.ui()
                tmp.link("%s to %s" % (rs['description'],rs['value']),report = 'DisplayObject',family=query['family'],case=query['case'],object_name=rs['name'])
                result.append((rs['name'],tmp,'leaf'))

            ##Now get the transitive links this object experiences from other objects
            dbh.execute("select a.name, description,a.value from knowledge as b, knowledge_node as a where a.name=b.pname and b.name =%r and link='transitive' group by name",(name))
            for rs in dbh:
                tmp = self.ui()
                tmp.link("%s from %s" % (rs['description'],rs['value']),report = 'DisplayObject',family=query['family'],case=query['case'],object_name=rs['name'])
                result.append((rs['name'],tmp,'leaf'))

            return result

        result.tree(tree_cb = tree_cb,branch = branch)
        
class SearchObject(Reports.report):
    """ Searches the Knowledge Base for objects satisfying certain properties """
    parameters = {"type":"sqlsafe","search_term":"sqlsafe"}
    name = "Search Object"
    family = "Knowledge Base"
    description = "Searches KB for Objects"

    def form(self,query,result):
        result.case_selector(message="Select case to operate on:")
        try:
            result.selector("Select object property type: ","type","select type,type from knowledge_node group by type",(),case=query['case'])
            result.textfield("Search for (% is the wildcard): ","search_term")
        except DB.DBError:
            pass
        
    def display(self,query,result):
        result.heading("Objects matching search criteria")

        #Escape % in the search_term so we dont interrupt string interpolations
        search_term = query['search_term'].replace('%','%%')
        result.table(
            columns = ('name','value'),
            names = ('Property','Search Result'),
            links = [
                      FlagFramework.query_type((),report = 'DisplayObject',family = query['family'],case=query['case'],__target__ = 'object_name')
                  ],
            table = 'knowledge_node',
            case=query['case'],
            where='type = %r and value like %r' % (query['type'],search_term),
        )

class DrawNetworkDiagram(Reports.report):
    """ Draws a network diagram of the objects in the knowledge base """
    parameters = {'type':'sqlsafe','prog':'alphanum'}
    name = "Draw Network diagram"
    family = "Knowledge Base"
    description = "Draws the network diagram from the KB"

    def form(self,query,result):
        result.case_selector(message="Select case to operate on:")
        try:
            result.selector("Root node type: ","type","select type,type from knowledge_node as a,knowledge as b where pname=a.name group by type",(),case=query['case'])
            result.const_selector("Plotting program:",'prog',('dot','text','twopi','neato'),('dot','text','twopi','neato'))
        except DB.DBError:
            pass

        result.heading("Plotting Options")
        result.checkbox("Show disconnected objects:",'show_disc','yes')
        try:
            result.selector("Show deductions:",'deductions',"select description,description from knowledge where link = \"transitive\" group by  description",(),case=query['case'],multiple="multiple",size="5")
        except DB.DBError:
            pass

    def display(self,query,result):
        dbh = self.DBO(query['case'])
        graph = GraphViz(query['prog'],result)

        ##What conditions did the user ask to see?
        conditions = "description='%s'" % "' or description='".join(query.getarray('deductions'))

        ## If the user didnt ask to see disconnected nodes, we create a temporary knowledge table, else we use the original table
        if query.has_key('show_disc'):
            knowledge = 'knowledge'
        else:
            knowledge = dbh.get_temp()
            ## This gives us those nodes that appear in transitive links meeting the conditions
            dbh.execute("create table %s select * from knowledge as a where a.link='transitive' and (%s)",(knowledge,conditions))

        def find_root_node(name,type):
            """ Follows node named by name up the kb tree to find the node denoted by type

            @arg name: Name of node to start searching from
            @arg type: When a node of this type is found it is returned.
            @return: A node of the given type which is up the tree from the named node
            """
            dbh2 = self.DBO(query['case'])
            while 1:
                dbh2.execute('select type from knowledge_node where name = %r',name)
                rs = dbh2.fetch()
                if rs['type'] == type: return name
                dbh2.execute('select pname from knowledge where name = %r and link="no"' ,(name))
                rs = dbh2.fetch()
                if not rs: return None
                name = rs['pname']

        ## We follow each node up the tree to reach the root as defined by query['type']
        dbh.execute('select a.name,a.pname,description from %s as a,knowledge_node as b where a.name=b.name and a.link="transitive"',knowledge)
        for row in dbh:
            from_node = find_root_node(row['pname'],query['type'])
            to_node = find_root_node(row['name'],query['type'])

            new_query = FlagFramework.query_type((),
                                                 family=query['family'],
                                                 report='DisplayObject',
                                                 object_name=from_node,
                                                 case=query['case']
                                                 )
            graph.node(from_node,label=from_node,URL="f?%s" % new_query)

            new_query = FlagFramework.query_type((),
                                                 family=query['family'],
                                                 report='DisplayObject',
                                                 object_name=to_node,
                                                 case=query['case']
                                                 )
            graph.node(to_node,label=to_node,URL="f?%s" % new_query)
            graph.edge(from_node,to_node,label=row['description'])
            
        graph.draw()

import pyflag.Graph as Graph

class GraphViz(Graph.Image):
    """ This class encapsulates the graphviz graph plotting utility

    Example for use:
    
    >>> a = GraphViz('dot',result)
    ...     ... Some graphviz plotting code ...
    ...     ui.image(a)

    """

    out_format = 'svg'
    
    def __init__(self,progname,result):
        """ Constructor.

        @arg progname: Rendering engine to use, can be:
              - dot
              - neato
              - twopi
              - text
        @arg result: a UI object to use to base drawing on
        """
        self.prog = progname
        self.nodes = {}
        self.node_index = []
        self.edges = []
        self.result = result

    def node(self,name,**opts):
        """ Inserts a node into the current drawing """
        self.nodes[name]=opts
        self.node_index.append(name)

    def edge(self,From ,To ,**opts):
        """ Inserts an edge into the current drawing """
        self.edges.append((From,To,opts))

    def draw(self):
        """ Draw the graph by calling the relevant dispatcher """
        self.dispatcher[self.prog](self)

    def display(self):
        """ Exec the relevant program and extract the output into the UI """
        import popen2

        out_format = self.out_format
        if out_format == 'png':
            out_format = 'gif'

        print  "%s -T%s -Gstart=rand" % (self.prog,out_format)
        dot_prog = popen2.Popen3("%s -T%s -Gstart=rand" % (self.prog,out_format))
        dot_prog.tochild.write(self.text())
        dot_prog.tochild.close()
        result = dot_prog.fromchild.read()
        return result

    def execute(self):
        """ Function called for executing the graphviz tool on the data.

        This class is polymorphic with the graph class as far as the UI object is concerned.

        This function adds a graph to the UI object. Note that the UI object will depend on the display method to get the output from dot so we do indirectly end up calling display """
        self.result.image(self)

    def text(self):
        """ Output a graphviz program as a text string """

        result = """strict digraph G{\noverlap=scale;\nconcentrate=true;\n"""
        for k,v in self.nodes.items():
            tmp = [ '%s="%s"'% (x,y) for x,y in v.items() ]
            result+="obj_%s [ %s ];\n" % (self.node_index.index(k)," ".join(tmp))
        result+="\n"

        for From,To,opt in self.edges:
            tmp = [ "%s=\"%s\"" % (x,y) for x,y in opt.items() ]
            result+="obj_%s -> obj_%s [ %s ];\n" % (self.node_index.index(From),self.node_index.index(To)," ".join(tmp))
        result+="}"
        return result

    def formated_text(self):
        self.result.text(self.text(),font='typewriter')

    dispatcher = {'dot':execute,'twopi':execute,'neato':execute,'text':formated_text}
