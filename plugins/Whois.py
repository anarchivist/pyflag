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
#  Version: FLAG $Name:  $ $Date: 2004/10/22 08:34:33 $
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
    ## Polymorphic code - if its numeric we use it as such - if its a
    ## string it must be an IP in dot notation.
    try:
        ip/2
        ip=str(ip)
    except TypeError:
        ip = "inet_aton(%r)" % ip
        
    netmask = 0
    while 1:
        dbh.execute("select whois_id from whois_routes where ( %s & inet_aton('255.255.255.255') & ~%r ) = network and (inet_aton('255.255.255.255') & ~%r) = netmask limit 1 " , (ip,netmask,netmask))
#        dbh.execute("select whois_id from whois_routes where ( %s & ~(pow(2,%r) -1)) = network and ~(pow(2,%r)-1) = netmask limit 1 " , (ip,netmask,netmask))
        row=dbh.fetch()
        ## If we found it, we return that, else we increase the
        ## netmask one more step and keep trying. Worst case we should
        ## pick off the 0.0.0.0 network which is our exit condition.
        if row: break

        if netmask>pow(2,32):
            raise Reports.ReportError("Unable to find whois entry for %s " % ip)

        netmask = netmask * 2 + 1

    return row['whois_id']

def identify_network(whois_id):
    """ Returns a uniq netname/country combination """
    dbh = DB.DBO(None)
    dbh.execute("select netname,country from whois where id=%r" , (whois_id))
    row = dbh.fetch()
    try:
        return "%s/%s" % (row['country'],row['netname'])
    except TypeError:
        return ''

class LookupIP(Reports.report):
    """ Display Whois data for the given IP address """
    parameters = {"address":"ipaddress"}
    name = "Whois Lookup"
    hidden = True
    description = "Perform Whois Lookup on IP Address"

    def form(self, query, result):
        result.textfield("Enter IP Address:",'address')

    def display(self, query, result):
        ## get route id
        result.heading("Whois Search Results For: %s" % query['address'])
        whois_id = lookup_whois(query['address'])
        self.display_whois(query,result,whois_id)

    def display_whois(self,query,result,whois_id):
        # lookup IP address and show a nice summary of Whois Data
        dbh = self.DBO(None)
        dbh.execute("SELECT INET_NTOA(start_ip) as start_ip, numhosts, country, descr, status from whois where id=%s",whois_id)
        res = dbh.fetch()
        
        for name in res.keys():
            result.text("%s:\n" % name, color='red',font='typewriter')
            result.text("%s\n\n" % (res[name]),color='black',font='typewriter')

class LookupWhoisID(LookupIP):
    """ A report to show the IP by netname """
    parameters = {'id':'numeric'}
    hidden=True

    def display(self,query,result):
        result.heading("Whois Search Results")
        self.display_whois(query,result,int(query['id']))

