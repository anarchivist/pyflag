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

""" Module for performing Whois Lookups """
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.LogFile as LogFile
import pyflag.conf
config=pyflag.conf.ConfObject()
import re

description = "Offline Whois"
order = 40

class LookupIP(Reports.report):
    """ Display Whois data for the given IP address """
    parameters = {"address":"ipaddress"}
    name = "Whois Lookup"
    description = "Perform Whois Lookup on IP Address"

    def form(self, query, result):
        result.textfield("Enter IP Address:",'address')

    def display(self, query, result):
        # lookup IP address and show a nice summary of Whois Data
        dbh = self.DBO(None)
        # get route id
        dbh.execute("SELECT whois_id from whois_routes where (INET_ATON(%r) & netmask) = network order by netmask desc limit 1;", query['address'])
        whois_id = dbh.fetch()['whois_id']
        dbh.execute("SELECT INET_NTOA(start_ip) as start_ip, numhosts, country, descr, status from whois where id=%s",whois_id)
        res = dbh.fetch()
        result.heading("Whois Search Results For: %s" % query['address'])
        
        for name in res.keys():
            result.para("%s: %s" % (name, res[name]))
