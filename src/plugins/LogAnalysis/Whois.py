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
#  Version: FLAG $Version: 0.82 Date: Sat Jun 24 23:38:33 EST 2006$
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

    ## First check the cache:
    dbh.check_index("whois_cache", "ip")
    dbh.execute("select id from whois_cache where ip=%s limit 1" , ip)
    row = dbh.fetch()
    if row:
        return row['id']
        
    netmask = 0
    while 1:
        dbh.check_index("whois_routes","netmask")
        dbh.execute("select whois_id from whois_routes where ( %s & inet_aton('255.255.255.255') & ~%r ) = network and (inet_aton('255.255.255.255') & ~%r) = netmask limit 1 " , (ip,netmask,netmask))
        row=dbh.fetch()
        ## If we found it, we return that, else we increase the
        ## netmask one more step and keep trying. Worst case we should
        ## pick off the 0.0.0.0 network which is our exit condition.
        if row: break

        if netmask>pow(2,32):
            raise Reports.ReportError("Unable to find whois entry for %s " % ip)

        netmask = netmask * 2 + 1

    ## Cache it:
    dbh.execute("insert into whois_cache set ip=%s, id=%r" , (ip, row['whois_id']))
    return row['whois_id']

def identify_network(whois_id):
    """ Returns a uniq netname/country combination """
    dbh = DB.DBO(None)
    dbh.check_index("whois","id")
    dbh.execute("select netname,country from whois where id=%r limit 1" , (whois_id))
    row = dbh.fetch()
    try:
        return "%s/%s" % (row['country'],row['netname'])
    except TypeError:
        return ''

class LookupIP(Reports.report):
    """ Display Whois data for the given IP address """
    parameters = {"address":"ipaddress"}
    name = "Whois Lookup"
    family = "Log Analysis"
    hidden = False
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
        dbh.check_index("whois","id")
        dbh.execute("SELECT INET_NTOA(start_ip) as start_ip, numhosts, country, descr, remarks, adminc, techc, status from whois where id=%s limit 1",whois_id)
        res = dbh.fetch()
        
        for name in res.keys():
            tmp=result.__class__(result)
            tmp2=result.__class__(result)
            tmp.text("%s:" % name, style='red',font='typewriter')
            tmp2.text("%s" % (res[name]),style='black',font='typewriter')
            result.row(tmp,tmp2,valign="top")

class LookupWhoisID(LookupIP):
    """ A report to show the IP by netname """
    parameters = {'id':'numeric'}
    hidden=True
    name="WhoisID"
    family = "Log Analysis"

    def display(self,query,result):
        try:
            if query['__pyflag_name']!='main':
                result.decoration='naked'
        except:
            pass
        
        result.heading("Whois Search Results")
        self.display_whois(query,result,int(query['id']))

### Some unit tests for Whois:
import unittest

## These are some test ip addresses - were confirmed using the on-line
## whois tool. More can be added in the following format:
## [ Domain, IP, NETNAME ]
test_ips = [
    ## These come from APNIC (Asia Pacific):
    ["www.msn.com.au",       '202.58.56.1', "HOSTWORKS"], 
    ["www.microsoft.com.au", "202.139.232.157", "WEBCENTRAL"],

    ## These come from RIPE (Europe)
    ["www.microsoft.co.uk", "217.64.231.177", "microsoft-com"],
    ["www.germnews.de",     "217.10.9.47",    "IN-ULM-NET2"],
    ]

class WhoisTest(unittest.TestCase):
    """ Whois tests (Requires Whois DB to be loaded) """
    def test01TestCommonWhoisQueries(self):
        """ Test some well known IP addresses """
        dbh = DB.DBO()
        dbh.delete("whois_cache", where=1)
        for domain, ip, netname in test_ips:
            id = lookup_whois(ip)
            dbh.execute("select netname from whois where id=%r", id)
            row = dbh.fetch()
            self.assertEqual(netname, row['netname'])
