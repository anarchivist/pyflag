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

""" Module used to interface to the flag version of ethereal

@var sql_schema: the SQL schema supported by tethereal
@var sql_drop: The corresponding drop statements used to delete tethereal tables
"""
import os
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.DB as DB
import time

def load_sql(case,filename):
    """ Loads the tcpdump into the case """
    #Create the tables and invoke tethereal
    dbh = DB.DBO(case)
    dbh.MySQLHarness("%s -G sql" % config.TETHEREAL)
    dbh.MySQLHarness("%s -Qxnr %r"%(config.TETHEREAL,filename))

def del_sql(case):
    """ Deletes all tcpdump tables from case """
    dbh = DB.DBO(case)
    dbh.MySQLHarness("%s -G drop" % config.TETHEREAL)

def load_kb(case,filename):
    """ Uses ethereal to load the knowledge base into the case. Following is a short extract from the Flag documentation:
    
    The following definitions hold:
      - A knowledge base is a graph consisting of nodes and edges.
      - Each node represents a basic unique fact.
      - Edges are deductions which relate those facts to one another. 
      - A transitive edge is a relationship connecting two objects.
      - An object is defined as a subtree rooted at a particular node. Note that objects are necessarily trees (i.e. a-cyclic graphs) and therefore transitive edges are not counted as parts of objects.
          
      The knowledge base schema looks like this:

      >>> CREATE TABLE `knowledge_node` (
      ...        `type` char(50) default NULL,
      ...        `name` char(50) default NULL,
      ...        `value` char(50) NOT NULL default '',
      ...        `packet` int(11) NOT NULL default '0'
      ...        )

      The above is the knowledge node table. The following fields are important:
            - packet: Stores the packet id which caused the deduction
            - type: the type of the node
            - name: A Unique name for the node (usualy made up by concatenating the type and value and a unique identifier). The name is not necessarily human readable, but is a unique identifier.
            - value: The lable which identifies the node.

      Links (edges) are stored in the knowledge table:

      >>> CREATE TABLE `knowledge` (
      ...        `field` VARCHAR(50) NOT NULL,
      ...        `packet` INT NOT NULL,
      ...        `name` VARCHAR(50),
      ...        `pname` VARCHAR(50),
      ...        description varchar(100) NOT NULL,
      ...        link enum('no', 'transitive'),
      ...        INDEX ( `packet`))

      The important fields are:
            - name: The name of the node we are linking to
            - parent: The name of the node we are linking from
            - description: A short description of the type of the link
            - link: A tag to designate the link as transitive or not. Transitive links join different objects, while non-transitive links join properties within the same object.
    """
    #First create table in case:
    t1 = time.time()
    
    dbh = DB.DBO(case)
    dbh.execute(""" CREATE TABLE `knowledge_node` (
    `type` char(50) default NULL,
    `name` char(50) default NULL,
    `value` char(50) NOT NULL default '',
    `packet` int(11) NOT NULL default '0') """,())
    
    dbh.execute(""" CREATE TABLE `knowledge` (
    `field` VARCHAR(50) NOT NULL,
    `packet` INT NOT NULL,
    `name` VARCHAR(50),
    `pname` VARCHAR(50),
    description varchar(100) NOT NULL,
    link enum('no', 'transitive'),
    INDEX ( `packet`)) """ , ())
    
    dbh.MySQLHarness("%s -Knr %r"%(config.TETHEREAL,filename))
    
    dbh.execute("alter table knowledge_node add index(name)",())
    print "It took %g sec" % (time.time()-t1)
    
def clear_kb(case):
    """ Drops the knowledge base tables """
    dbh = DB.DBO(case)
    dbh.execute("drop table knowledge",())
    dbh.execute("drop table knowledge_node",())
