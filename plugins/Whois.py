# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Name:  $ $Date: 2004/10/16 13:28:37 $
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

""" Module for performing Whois Lookups """
import pyflag.Reports as Reports
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework
import pyflag.LogFile as LogFile
import pyflag.conf
config=pyflag.conf.ConfObject()
import re

description = "Offline Whois"
hidden = False
order = 40

def lookup_whois(ip):
    """ Functions searches the database for the most specific whois match.

    @arg ip: Either an unsigned int or a string IP in decimal notation.
    Returns a whois id. This id can be used to display the whois table.
    """
    dbh = DB.DBO(None)
    if type(ip) == type(1):
        ip="%r" % ip
    else:
        ip = "inet_aton(%r)" % ip
        
    netmask = 0
    while 1:
        dbh.execute("select whois_id from whois_routes where ( %s & inet_aton('255.255.255.255') & ~%r ) = network and (inet_aton('255.255.255.255') & ~%r) = netmask limit 1 " , (ip,netmask,netmask))
#        dbh.execute("select whois_id from whois_routes where ( %s & ~(pow(2,%r) -1)) = network and ~(pow(2,%r)-1) = netmask limit 1 " , (ip,netmask,netmask))
        row=dbh.fetch()
        ## If we found it, we return that, else we increase the
        ## netmask one more step and keep trying. Worst case we should
        ## pick off the 0.0.0.0 network which is our exit condition.
        if row:
            break

        netmask = netmask * 2 + 1

    return row['whois_id']

def identify_network(ip):
    """ Returns a uniq netname/country combination """
    dbh = DB.DBO(None)
    whois_id = lookup_whois(ip)
    dbh.execute("select netname,country from whois where id=%r" , (whois_id))
    row = dbh.fetch()
    return "%s/%s" % (row['country'],row['netname'])

class LookupIP(Reports.report):
    """ Display Whois data for the given IP address """
    parameters = {"address":"ipaddress"}
    name = "Whois Lookup"
    hidden = True
    description = "Perform Whois Lookup on IP Address"

    def form(self, query, result):
        result.textfield("Enter IP Address:",'address')

    def display(self, query, result):
        # lookup IP address and show a nice summary of Whois Data
        dbh = self.DBO(None)
        ## get route id
        whois_id = lookup_whois(query['address'])
        dbh.execute("SELECT INET_NTOA(start_ip) as start_ip, numhosts, country, descr, status from whois where id=%s",whois_id)
        res = dbh.fetch()
        result.heading("Whois Search Results For: %s" % query['address'])
        
        for name in res.keys():
            result.text("%s:\n" % name, color='red',font='typewriter')
            result.text("%s\n\n" % (res[name]),color='black',font='typewriter')
