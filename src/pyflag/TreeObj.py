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
#  Version: FLAG $Version: 0.84RC5 Date: Wed Dec 12 00:45:27 HKT 2007$
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

""" This module manages access to trees defined in the database.

PyFlag uses many trees. This class manages the representation of these
trees in the database to ensure consistency. This object is designed
to work around something like:

CREATE TABLE `tree` (
  `id` int(11) NOT NULL auto_increment,
  `name` varchar(250) NOT NULL,
  `parent` int(11) default 0 NOT NULL,
  PRIMARY KEY  (`id`)
)

"""
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.DB as DB
import os
import pyflag.FlagFramework as FlagFramework

class TreeObj:
    """ An abstract class to manage representing trees in the database"""
    ## This is the key for each node should be autoincrement
    key = 'id'

    ## The name of each node
    node_name = 'name'

    ## The column which contains the parent id of this node
    parent_field = 'parent'

    ## Paths are delimited by this:
    delimiter = '/'

    def __init__(self, case=None, table=None, id=None, path=None, **node):
        """ Retrieve or create the node with the id given.

        if id is given we retrieve said node, else we create a new
        node with fields as in the dictionary 'node'.
        """
        self.case = case
        self.table = table
        
        dbh = DB.DBO(self.case)
        if id!=None:
            dbh.execute("select * from %s where `%s`=%r",(self.table, self.key, id))
            self.row = dbh.fetch()
            if not self.row:
                raise IOError("Can not find node with id %s" % id)

            self.id = self.row[self.key]
        elif path!=None:
            parent = 0
            branches = FlagFramework.splitpath(path)
            if not branches:
                self.id = 0
                self.row = {self.parent_field: 0}
                return
            
            for name in branches:
                dbh.execute("select * from `%s` where `%s`=%r and `%s`=%r",
                            (self.table, self.parent_field,
                             parent, self.node_name, name))
                    
                self.row = dbh.fetch()
                if not self.row:
                    raise IOError("Can not find path element %s" % name)
                
                parent = self.row[self.key]

            self.id = self.row[self.key]
        else:
            self.id = self.new_node(node)
            self.row = node

    def new_node(self, node):
        """ Return the id of a new node created using the fields in **node """
        dbh = DB.DBO(self.case)

        dbh.mass_insert_start(self.table)
        dbh.mass_insert(**node)
        dbh.mass_insert_commit()
        return dbh.autoincrement()
        
    def add_child(self, **node):
        """ Creates a new node with the fields in node that has its parent as us """
        try:
            node[self.node_name]
        except KeyError:
            raise SystemError("Child must have field %s" % self.node_name)
        
        node['parent'] = self.id
        return self.new_node(node)

    def __str__(self):
        return "<Tree node of name %r>" % self.row[self.node_name]

    def __repr__(self):
        return "%s" % self.row

    def children(self):
        """ Generates all our children """
        dbh = DB.DBO(self.case)
        dbh.execute("select `%s` from %s where `%s`=%r",
                    (self.key, self.table, self.parent_field, self.id))
        for row in dbh:
            yield self.__class__(id=row[self.key], case=self.case, table=self.table)

    def get_root(self):
        """ Follow our parent until we reach the root. Returns the root node """
        dbh = DB.DBO(self.case)
        id = self.id
        while 1:
            dbh.execute("select `%s` from %s where id=%r",(self.parent_field,self.table, id))
            row=dbh.fetch()
            if not row or not row[self.parent_field]:
                break

            id=row[self.parent_field]

        return self.__class__(id=id, case=self.case, table=self.table)

    def __getitem__(self,item):
        return self.row.get(item, None)

    def __setitem__(self, item, value):
        dbh = DB.DBO(self.case)
        dbh.execute("update `%s` set `%s`=%r where `%s`=%r",
                    (self.table, item, value, self.key, self.id))
        self.row[item]=value
