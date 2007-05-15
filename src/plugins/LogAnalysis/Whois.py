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

""" Module for performing Whois Lookups """
import pyflag.Reports as Reports
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()
import re
import pyflag.pyflaglog as pyflaglog
import pyflag.Store as Store

description = "Offline Whois"
hidden = False
order = 40

config.add_option("GEOIPDIR", default=config.DATADIR, help="The directory containing all the GeoIP files. We try to open (in this order) GeoIPCity.dat, GeoLiteCity.dat (if GeoIPCity.dat fails), GeoIPISP.dat, GeoIPOrg.dat. If any of them fail we just don't use them")

config.add_option("GEOIP_MEMORY_CACHE", default=True, help="Should the GEOIP database(s) (if found) be loaded into memory? Will result in better performance but will use more memory")

## NYI - Current the PRECACHE IP METADATA does this

#config.add_option("SEARCHABLE_WHOIS", default=True, help="Should the WHOIS data be preloaded so you can search on it (makes things slower)")
#config.add_option("SEARCHABLE_ORG
#config.add_option("SEARCHABLE_ISP


# Would be nice if somewhere we did a count(*) and if whois wasn't there 
# we didn't show this either....
config.add_option("WHOIS_DISPLAY", default=True, 
                  help="Should the WHOIS data (if available) be shown?")


## A cache of whois addresses - This really does not need to be
## invalidated as the data should never change
WHOIS_CACHE = Store.Store()

## Try for the GeoIP City Stuff....

try:
    import GeoIP
    if config.GEOIP_MEMORY_CACHE:
        gi_resolver = GeoIP.open(config.GEOIPDIR + "/GeoIPCity.dat", 
                                GeoIP.GEOIP_MEMORY_CACHE)
        
    else:
        gi_resolver = GeoIP.open(config.GEOIPDIR + "/GeoIPCity.dat", 
                                GeoIP.GEOIP_STANDARD)

except Exception,e:
    pyflaglog.log(pyflaglog.WARNING, 
                  "Unable to import the GeoIP city database (%s) - " \
                  "will attempt to load the free one." % e)
    try:
        import GeoIP
        if config.GEOIP_MEMORY_CACHE:
            gi_resolver = GeoIP.open(config.GEOIPDIR + "/GeoLiteCity.dat", 
                                    GeoIP.GEOIP_MEMORY_CACHE)
    
        else:
            gi_resolver = GeoIP.open(config.GEOIPDIR + "/GeoLiteCity.dat", 
                                    GeoIP.GEOIP_STANDARD)

    except Exception, e:
        pyflaglog.log(pyflaglog.WARNING,
                    "Unable to import the GeoIP city database (the free one) " \
                    "error was: %s. No GeoIP available." %e)

        gi_resolver = None


if gi_resolver:
    config.add_option("GEOIP_DISPLAY", default=True, 
                      help="Should we show GEOIP data in the normal " \
                      "display of IP addresses? This only works if the " \
                      "GEOIPDIR option is set correctly")

## Now try for the GeoIPISP

try:
    import GeoIP
    if config.GEOIP_MEMORY_CACHE:
        gi_isp_resolver = GeoIP.open(config.GEOIPDIR + "/GeoIPISP.dat",
                                    GeoIP.GEOIP_MEMORY_CACHE)
    else:
        gi_isp_resolver = GeoIP.open(config.GEOIPISPDB + "/GeoIPISP.dat",
                                    GeoIP.GEOIP_STANDARD)

except Exception,e:
    pyflaglog.log(pyflaglog.WARNING, 
                  "Unable to import the GeoIP ISP database (%s) - " \
                  "will not use it." % e)
    gi_isp_resolver = None

## Now try the GEOIPOrg

try:
    import GeoIP
    if config.GEOIP_MEMORY_CACHE:
        gi_org_resolver = GeoIP.open(config.GEOIPDIR + "/GeoIPOrg.dat",
                                     GeoIP.GEOIP_MEMORY_CACHE)
    else:
        gi_org_resolver = GeoIP.open(config.GEOIPDIR + "/GeoIPOrg.dat",
                                     GeoIP.GEOIP_STANDARD)

except Exception,e:
    pyflaglog.log(pyflaglog.WARNING, 
                  "Unable to import the GeoIP organisation database (%s) - will not use it." % e)
    gi_org_resolver = None

if gi_org_resolver or gi_isp_resolver:
    config.add_option("EXTENDED_GEOIP_DISPLAY", default=True, 
                      help="Should we show extended GEOIP information? " \
                      "This only works if the GEOIP* options are set " \
                      "correctly. In particular this option needs the ISP " \
                      " and/or ORG GeoIP databases (not free)")

def get_all_geoip_data(ip):
    try:
        ipinfo = gi_resolver.record_by_addr(ip)
        assert(ipinfo != None)
    except Exception, e:
        ##pyflaglog.log(pyflaglog.WARNING, "Error doing GeoIP lookup: %r" % e)
        ipinfo = dict(city = 'Unknown', country_code3='---')

    ## We should try for the other things too...
    try:
        organisation = gi_org_resolver.org_by_addr(ip)
        assert(organisation != None)
    except Exception, e:
        organisation = "Unknown"

    try:
        isp = gi_isp_resolver.org_by_addr(ip)
        assert(isp != None)
    except Exception, e:
        isp = "Unknown"


    ipinfo['org'] = organisation
    ipinfo['isp'] = isp

    return ipinfo

def insert_whois_cache(sql_ip, id, ipinfo):
    dbh = DB.DBO(None)
    dbh.execute("insert into whois_cache set ip=%s, id=%s, geoip_city= " \
                " (select id from geoip_city where city='%s' limit 1), " \
                " geoip_country = (select id from geoip_country where country" \
                "='%s' limit 1), geoip_isp = (select id from geoip_isp where" \
                " isp='%s' limit 1), geoip_org = (select id from " \
                " geoip_org where org='%s')" % (sql_ip,id,ipinfo['city'],
                ipinfo['country_code3'], ipinfo['isp'], ipinfo['org']));
    
def lookup_whois(ip):
    """ Functions searches the database for the most specific whois match.

    @arg ip: Either an unsigned int or a string IP in decimal notation.
    Returns a whois id. This id can be used to display the whois table.
    """
    ## Polymorphic code - if its numeric we use it as such - if its a
    ## string it must be an IP in dot notation.
    try:
        ip/2
        sql_ip = ip
    except TypeError:
        if ip == None:
            pyflaglog.log(pyflaglog.WARNING, "Was asked to perform a whois lookup on a blank IP address. Will return the default route, but this might suggest an error") 
            return 0
        sql_ip = "inet_aton(%r)" % ip

    ## First check the cache:
    id = 0
    try:
        return WHOIS_CACHE.get(ip)
    except KeyError:
        dbh = DB.DBO()
        
        dbh.check_index("whois_cache", "ip")
        dbh.execute("select id from whois_cache where ip=%s limit 1" , sql_ip)
        row = dbh.fetch()
        if row:
            id = row['id']
            WHOIS_CACHE.put(id, key=ip)
            
            return id

    netmask = 0
    while 1:
        dbh.check_index("whois_routes","netmask")
        dbh.check_index("whois_routes","network")
        dbh.execute("select whois_id from whois_routes where ( %s & inet_aton('255.255.255.255') & ~%r ) = network and (inet_aton('255.255.255.255') & ~%r) = netmask limit 1 " , (sql_ip,netmask,netmask))
        row=dbh.fetch()
        ## If we found it, we return that, else we increase the
        ## netmask one more step and keep trying. Worst case we should
        ## pick off the 0.0.0.0 network which is our exit condition.
        if row:
            id = row['whois_id']
            break

        if netmask>pow(2,32):
            raise Reports.ReportError("Unable to find whois entry for %s " % ip)

        netmask = netmask * 2 + 1
                
    ## Cache it. We also may as well do a GEOIP lookup :)
    try:
        ipinfo = get_all_geoip_data(ip)
    except Exception, e:
        ##pyflaglog.log(pyflaglog.WARNING, "Error doing GeoIP lookup: %r" % e)
        ipinfo = dict(city = 'Unknown', country_code3='---', 
                      isp='Unknown', org='Unknown')

    ## For speed we try and do it all in one go
    try:
        insert_whois_cache(sql_ip, id, ipinfo)
    ## we can only assume that we got nothing back from the geoip stuff
    except DB.DBError,e:
        ##
        ## LOOKUP GEOIP COUNTRY
        ##
        try:
            dbh.insert("geoip_country", _fast=True,
                       country = ipinfo['country_code3'])
        except DB.DBError, e:
            ##pyflaglog.log(pyflaglog.WARNING, "Could not insert new places: %s" % e)
            ## We probably tried to put a dupe in there
            pass

        ## 
        ## LOOKUP GEOIP CITY
        ##
        try:
            dbh.insert("geoip_city", _fast=True,
                       city=ipinfo['city'])
        except DB.DBError, e:
            ## pyflaglog.log(pyflaglog.WARNING, "Could not insert new places: %s" % e)
            ## We probably tried to put a dupe in there
            pass

        ##
        ## LOOKIP GEOIP ISP
        ##
        try:
            dbh.insert("geoip_isp", _fast=True,
                       isp=ipinfo['isp'])
        except DB.DBError, e:
            ## pyflaglog.log(pyflaglog.WARNING, "Could not insert new places: %s" % e)
            ## We probably tried to put a dupe in there
            pass

        ## 
        ## LOOKIP GEOISP ORG
        ##
        try:
            dbh.insert("geoip_org", _fast=True,
                       org=ipinfo['org'])
        except DB.DBError, e:
            ## pyflaglog.log(pyflaglog.WARNING, "Could not insert new places: %s" % e)
            ## We probably tried to put a dupe in there
            pass


        ## 
        ## Try again
        ##
        try:
            insert_whois_cache(sql_ip, id, ipinfo)
        except DB.DBError, e: 
            pyflaglog.log(pyflaglog.WARNING, "There was a problem doing the GeoIP " \
                          "stuff. We had an error, tried to re insert stuff then " \
                          "had an error: %s" % e)
    return id

def geoip_cached_record(ip):
    country = ""
    city = ""
    row = None
    ip_sql = "inet_aton(%r)" % ip
    dbh = DB.DBO(None)
    
    try:
        dbh.execute("select * from whois_cache join " \
                   " (geoip_country join geoip_city join geoip_isp " \
                   " join geoip_org) " \
                   " on (whois_cache.geoip_city = geoip_city.id and " \
                   "whois_cache.geoip_country = geoip_country.id and " \
                   "whois_cache.geoip_isp = geoip_isp.id and " \
                   "whois_cache.geoip_org = geoip_org.id)" \
                    "where whois_cache.ip=" \
                   "%s" % ip_sql)
        row = dbh.fetch()
    except:
        pyflaglog.log(pyflaglog.WARNING, "GeoIP information not cached...")

    if not row:
        id = lookup_whois(ip)
        ## Now it really should be there...        
        try:
            dbh.execute("select * from whois_cache join " \
                        " (geoip_country join geoip_city join geoip_isp " \
                        " join geoip_org) " \
                        " on (whois_cache.geoip_city = geoip_city.id and " \
                        "whois_cache.geoip_country = geoip_country.id and " \
                        "whois_cache.geoip_isp = geoip_isp.id and " \
                        "whois_cache.geoip_org = geoip_org.id)" \
                        "where whois_cache.ip=" \
                        "%s" % ip_sql)
            row = dbh.fetch()
        except:
            return dict(city="Unknown", country_code3="---",
                        isp="Unknown", org="Unknown")
    return dict(city=row['city'], country_code3=row['country'],
                org=row['org'], isp=row['isp'])


def geoip_resolve_extended(ip):
    rec = geoip_cached_record(ip)
    return "%s / %s" % (rec['org'], rec['isp'])


def geoip_resolve(ip):
    rec = geoip_cached_record(ip)
    return "%s (%s) " % (rec['city'], rec['country_code3'])

def identify_network(whois_id):
    """ Returns a uniq netname/country combination """
    dbh = DB.DBO(None)
    dbh.check_index("whois","id")
    dbh.execute("select netname,country from whois where id=%r limit 1" , whois_id)
    row = dbh.fetch()
    try:
        return "%s/%s" % (row['country'],row['netname'])
    except TypeError:
        return ''

class PrecacheWhois(Reports.report):
    """
    Precaching Whois Lookups
    ------------------------

    Often we would like to search on specific properties of the whois properties of IP addresses. Unfortunately, to calculate the whois relationships of an IP address takes a fair amount of calculations. Pyflag normally calculates this on the fly while displaying the IP address, and stores it in the cache. In order to properly search by whois entries all the IP addresses in a table should be in the cache.

    This report does this by pre-caching all IP addresses within a certain table.
    """
    parameters = {"table": "any", "column":"any"}
    name = "PreCache Whois"
    family = "Log Analysis"
    hidden = True
    count = 0
    processed = 0

    def analysis(self, query):
        dbh = DB.DBO(query['case'])
        ## Find out how many columns there are
        dbh.execute("select count(*) as count from %s" , query['table'])
        row = dbh.fetch()
        self.count = row['count']

        ## Now find all IP addresses:
        dbh.execute("select count(*) as count, inet_ntoa(`%s`) as ip from `%s` group by `%s`",
                    (query['column'], query['table'], query['column']))
        
        for row in dbh:
            lookup_whois(row['ip'])
            self.processed += row['count']

    def progress(self, query, result):
        result.heading("Caching IP addresses from table %s" % query['table'])
        result.para("Processed %s out of %s rows" % (self.progress, self.count))

    def display(self, query,result):
        result.heading("Done caching whois lookups")

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
        result.decoration = 'naked'
        ## get route id
        self.display_geoip(result, query['address'])
        self.display_whois(query,result,query['address'])

    def display_geoip(self,result ,ip):
        try:
            record = get_all_geoip_data(ip)
            #global gi_resolver
            #record = gi_resolver.record_by_addr(ip)
            result.heading("GeoIP Resolving - by maxmind.com")
            self.render_dict(record, result)
        except Exception,e:
            pass
        
    def display_whois(self,query,result, address):
        # lookup IP address and show a nice summary of Whois Data
        whois_id = lookup_whois(address)
        dbh = self.DBO(None)
        dbh.check_index("whois","id")
        dbh.execute("SELECT INET_NTOA(start_ip) as start_ip, numhosts, country, descr, remarks, adminc, techc, status from whois where id=%s limit 1",whois_id)
        res = dbh.fetch()
        result.heading("Whois Search Results For: %s" % query['address'])
        self.render_dict(res,result)

    def render_dict(self, dict, result):
        result.start_table()
        for k,v in dict.items():
            result.row(k,v)
        result.end_table()

    def xxrender_dict(self, dict, result):
        result.start_table()
        for name in dict.keys():
            tmp=result.__class__(result)
            tmp2=result.__class__(result)
            tmp.text("%s:" % name.strip(), style='red',font='typewriter')
            tmp2.text(dict[name].__str__().strip(),style='black',font='typewriter')
            result.row(tmp,tmp2)
        result.end_table()

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

class WhoisInit(FlagFramework.EventHandler):
    def init_default_db(self, dbh, case):
        dbh.execute("""CREATE TABLE `whois` (
        `id` int(11) NOT NULL,
        `src_id` int(11) default NULL,
        `start_ip` int(10) unsigned default NULL,
        `netname` varchar(50) default NULL,
        `numhosts` int(11) default NULL,
        `country` char(2) default NULL,
        `adminc` varchar(50) default NULL,
        `techc` varchar(50) default NULL,
        `descr` text default NULL,
        `remarks` text default NULL,
        `status` enum('assigned','allocated','reserved','unallocated') default NULL
        ) engine=MyISAM""")

        dbh.execute("""CREATE TABLE `whois_routes` (
        `network` int(10) unsigned NOT NULL default '0',
        `netmask` int(10) unsigned NOT NULL default '0',
        `whois_id` int(11) NOT NULL default '0'
        ) ENGINE=MyISAM""")
        
        dbh.insert("whois_routes",
                   whois_id = 1, _fast=True);
        
        dbh.insert("whois",
                   id=1,
                   src_id=1,
                   country='--',
                   descr='Default Fallthrough Route: IP INVALID OR UNASSIGNED',
                   status='unallocated')

        dbh.execute("""CREATE TABLE `whois_sources` (
        `id` int(11) NOT NULL,
        `source` varchar(20) default NULL,
        `url` varchar(255) default NULL,
        `updated` datetime default NULL
        ) engine=MyISAM""")

        dbh.execute("""create table whois_cache (
        `ip` int(11) unsigned not NULL,
        `id` int(11) unsigned not NULL,
        `geoip_city` int(11) unsigned not NULL,
        `geoip_country` int(11) unsigned not NULL,
        `geoip_isp` int(11) unsigned not NULL,
        `geoip_org` int(11) unsigned not NULL,
        PRIMARY KEY(`ip`)
        ) engine=MyISAM""")

        dbh.execute("""CREATE TABLE `geoip_city` (
        `id` int(11) unsigned NOT NULL auto_increment,
        `city` varchar(64) NOT NULL UNIQUE,
        PRIMARY KEY (`id`),
        UNIQUE KEY (`city`)
        ) engine = MyISAM""")

        dbh.insert("geoip_city", city="Unknown")

        dbh.execute("""CREATE TABLE `geoip_country` (
        `id` int(11) unsigned NOT NULL auto_increment,
        `country` char(3) NOT NULL UNIQUE,
        PRIMARY KEY (`id`),
        UNIQUE KEY (`country`)
        ) engine = MyISAM""")

        dbh.execute("""insert into geoip_country (country) values("---")""")

        dbh.execute("""CREATE TABLE `geoip_isp` (
        `id` int(11) unsigned NOT NULL auto_increment,
        `isp` varchar(128) NOT NULL UNIQUE,
        PRIMARY KEY (`id`),
        UNIQUE KEY (`isp`)
        ) engine = MyISAM""")

        dbh.execute("""insert into geoip_isp (isp) values("Unknown")""")

        dbh.execute("""CREATE TABLE `geoip_org` (
        `id` int(11) unsigned NOT NULL auto_increment,
        `org` varchar(128) NOT NULL UNIQUE,
        PRIMARY KEY (`id`),
        UNIQUE KEY (`org`)
        ) engine = MyISAM""")

        dbh.execute("""insert into geoip_org (org) values("Unknown")""")

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
