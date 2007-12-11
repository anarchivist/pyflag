# gregsfdev <gregsfdev@users.sourceforge.net>
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

import time,re
import plugins.LogAnalysis.Simple as Simple
import pyflag.FlagFramework as FlagFramework
import pyflag.LogFile as LogFile

## I cant enable this until I have unit tests. (MC)
active=False

months = { 'jan':1, 'feb':2,
           'mar':3, 'apr':4,
           'may':5, 'jun':6,
           'jul':7, 'aug':8,
           'sep':9, 'oct':10,
           'nov':11, 'dec':12}

def normalise_time(month, day, time, year="1970"):
    return "%s:%02u:%02u:%s" % (year, months[month.lower()[:3]], day, time)

class CiscoPixSyslogged(Simple.SimpleLog):
    """ Log parser designed to handle Cisco Pix log files that have been sent to a syslog server.
    """
    name = "CiscoPixSyslogged"

            
    def form(self, query, result):
        if LogFile.save_preset(query,result, self):
            query['finished']='yes'
            result.refresh(0,query)


    def load(self,tablename, rows = 0):
        """ We create a standard set of tables to support the pix logs """
        self.dbh.execute("""CREATE TABLE if not exists `%s` (
        `id` INT NOT NULL AUTO_INCREMENT ,
        `syslog_ts` TIMESTAMP NOT NULL ,
        `hostname` VARCHAR( 50 ) NOT NULL ,
        `pix_ts` TIMESTAMP NOT NULL ,
        `pix_code` VARCHAR( 50 ) NOT NULL ,
        `message` MEDIUMTEXT NOT NULL ,
        PRIMARY KEY ( `id` )
        )""", tablename)

        self.dbh.execute("""CREATE TABLE if not exists `conn_%s` (
        `id` INT NOT NULL,
        `pix_ts` TIMESTAMP NOT NULL ,
        `direction` VARCHAR(10) ,
        `conn_number` INT ,
        `protocol` VARCHAR(10) ,
        `src_if` VARCHAR( 10 ) NOT NULL ,
        `src_host` VARCHAR(50) ,
        `src_port` INT UNSIGNED ,
        `dst_if` VARCHAR( 10 ) NOT NULL ,
        `dst_host` VARCHAR(50) ,
        `dst_port` INT UNSIGNED ,
        `rule` VARCHAR(255) NOT NULL ,
        `action` enum('deny','deny:no connection','built connection','tcp teardown','access-list','stored-file') default NULL ,
        `duration` TIME NOT NULL ,
        `bytes` INT UNSIGNED
        )""", tablename)
        
        self.dbh.execute("select max(id) as max from `%s`", tablename)
        row = self.dbh.fetch()
        try:
            count = row['max']+1
        except:
            count = 0
            
        self.dbh_conn = self.dbh.clone()
        
        self.dbh.mass_insert_start(tablename)
        self.dbh_conn.mass_insert_start("conn_"+tablename)

        inserted = None
        for line in self.read_record():
            if not count % 100:
                yield "Uploaded %s rows" % count
                
            count +=1
            if rows>0 and count> rows:
                break

            try:
                #General stuff that is common to all messages
                #e.g.: Dec 25 00:00:10 myhost Dec 25 1970 00:00:00: %PIX-0-000000: mymessage
                columns = re.split(r"\s+",line,9)
                
                if columns[4].startswith("last"):
                    #Also handle the case of repeated messages
                    #Oct 21 16:28:31 myhost last message repeated 1 time
                    #These messages are inserted with duplicate IDs.
                    if inserted:
                        for i in range(int(columns[7])):
                            self.dbh_conn.mass_insert(**inserted)
    
                    
                else:
                    if inserted:
                        self.dbh_conn.mass_insert(**inserted)
                        
                    pix_ts=normalise_time(columns[4], int(columns[5]), columns[7], year=columns[6])
                    self.dbh.mass_insert(
                        id=count,
                        syslog_ts = normalise_time(columns[0],int(columns[1]),columns[2]),
                        hostname = columns[3],
                        pix_ts = pix_ts,
                        pix_code = columns[8],
                        message = columns[9]
                        )


                    #FIXME: Should actually do all the splits on the CISCO codes rather than random words.  The doco can be found on the Cisco site - do a search for "Cisco Security Appliance System Log Messages" and download the PDF.
                    
                    #denied connections
                    #e.g. %PIX-4-106023: Deny tcp src inside:myhost/55810 dst outside:192.168.0.1/80 by access-group "none_for_you"
                    #%PIX-4-106023: Deny icmp src inside:myservername dst outside:destservername (type 8, code 0) by access-group "none_for_you"

                    #This means packet was not associated with a connection and was not a SYN.
                    #%PIX-6-106015: Deny TCP (no connection) from 192.168.0.1/40549 to 192.168.3.1/21 flags RST  on interface outside.
                    
                    

                    colns = re.split(r"[\s+:/]",columns[9],17)

                    if columns[9].startswith("Deny"):

                        if colns[1].startswith("tcp") and colns[2].startswith("src"):

                            src = colns[3]
                            dst = colns[5]
                            action='deny'
                            src_if = colns[3]
                            src_host = colns[4]
                            src_port = colns[5]

                            dst_if = colns[7]
                            dst_host = colns[8]
                            dst_port = colns[9]

                            rule=" ".join(colns[11:])

                        elif colns[2].startswith("(no"):

                            action='deny:no connection'
                            src_if = ''
                            src_host = colns[5]
                            src_port = colns[6]

                            dst_if = ''
                            dst_host = colns[8]
                            dst_port = colns[9]
                            rule=" ".join(colns[10:])

                        elif colns[1].startswith("icmp"):

                            action='deny'

                            src_if = colns[3]
                            src_host = colns[4]
                            src_port = ''

                            dst_if = colns[6]
                            dst_host = colns[7]
                            dst_port = ''
                            rule=" ".join(colns[8:])

                        
                        inserted = {
                            'id':count,
                            'pix_ts':pix_ts,
                            'direction':'',
                            'protocol':colns[1],
                            'conn_number':'',
                            'src_if':src_if,
                            'src_host':src_host,
                            'src_port':src_port,
                            'dst_if':dst_if,
                            'dst_host':dst_host,
                            'dst_port':dst_port,
                            'duration':'Null',
                            'bytes':0,
                            'rule':rule,
                            'action':action
                            }

                    #built connections
                    #e.g. %PIX-6-302013: Built inbound TCP connection 323796 for outside:192.168.0.1/40532 (192.168.0.1/40532) to inside:192.168.3.1/21 (192.168.3.1/21)
                    # %PIX-6-302013: Built outbound TCP connection 1084734 for outside:192.168.3.1/20 (192.168.3.1/20) to inside:192.168.0.1/63076 (192.168.0.1/63076)
                    #Stuff in brackets is mapped address and mapped port.  I'm ignoring for now.
                    #FIXME: This format is retarded.  If inbound:
                    # Built inbound <outside host/high port> to <inside host/low port>
                    #If outbound:
                    # Built outbound <outside host/low port> to <inside host/high port>
                    #Which means I will have to swap around src and dest for outbound for it to make sense.
                    elif columns[9].startswith("Built"):

                        inserted = {
                            'id':count,
                            'pix_ts':pix_ts,
                            'direction':colns[1],
                            'protocol':colns[2],
                            'conn_number':colns[4],
                            'duration':'Null',
                            'bytes':0,
                            'rule':'',
                            'action':'built connection'
                            }
                        
                        if colns[1]=='inbound':
                            directions={
                            'src_if':colns[6],
                            'src_host':colns[7],
                            'src_port':colns[8],
                            'dst_if':colns[12],
                            'dst_host':colns[13],
                            'dst_port':colns[14]
                            }
                            inserted.update(directions)
                            
                        elif colns[1]=='outbound':
                            #Flip all this stuff around
                            directions={
                            'dst_if':colns[6],
                            'dst_host':colns[7],
                            'dst_port':colns[8],
                            'src_if':colns[12],
                            'src_host':colns[13],
                            'src_port':colns[14]
                            }
                            inserted.update(directions)
                        else:
                            print "Didn't understand Built connection message, unable to insert line id %s: %s: %s" % (count, line)
                            #Clear so we don't insert a duplicate of the last line
                            inserted=None

                    #TCP teardown
                    #e.g. %PIX-6-302014: Teardown TCP connection 323796 for outside:192.168.0.1/63847 to inside:192.168.3.1/28905 duration 0:00:01 bytes 398 TCP FINs
                    #Doco says bytes is "for the connection" which I'm assuming means two-way.
                    #Unfortunately tcp teardowns suffer from the same stupid reversing as built connections (see above) HOWEVER, there is no direction flag, which means I am just guessing based on the port number range which direction it is going.

                    elif columns[9].startswith("Teardown"):
                        
                        inserted={
                            'id':count,
                            'pix_ts':pix_ts,
                            'protocol':colns[1],
                            'conn_number':colns[3],
                            'duration':":".join(colns[13:16]),
                            'bytes':colns[17],
                            'action':'tcp teardown',
                            'src_if':colns[5],
                            'src_host':colns[6],
                            'src_port':colns[7],
                            'dst_if':colns[9],
                            'dst_host':colns[10],
                            'dst_port':colns[11],
                            }

                    #Access List info
                    #%PIX-6-106100: access-list outside_access_in permitted tcp outside/192.168.0.1(6666) -> inside/192.168.3.1(22) hit-cnt 1 (first hit)
                    elif columns[9].startswith("access-list"):
                        
                        inserted={
                            'id':count,
                            'pix_ts':pix_ts,
                            'direction':colns[6],
                            'protocol':colns[3],
                            'conn_number':0,
                            'src_if':colns[4],
                            'src_host':colns[5].split("(")[0],
                            'src_port':colns[5].split("(")[1][:-1],
                            'dst_if':colns[7],
                            'dst_host':colns[8].split("(")[0],
                            'dst_port':colns[8].split("(")[1][:-1],
                            'duration':0,
                            'bytes':0,
                            'rule':" ".join(colns[0:3])+": "+" ".join(colns[9:]),
                            'action':'access-list',
                            }

                    #File stored
                    #%PIX-6-303002:  192.168.0.1 Stored 192.168.3.1:filename.ext
                    #This code can actually be FTP stored or retrieved.
                    elif colns[1].startswith("Stored"):
                        
                        inserted={
                            'id':count,
                            'pix_ts':pix_ts,
                            'direction':'',
                            'protocol':'',
                            'conn_number':0,
                            'src_if':'',
                            'src_host':colns[0],
                            'src_port':0,
                            'dst_if':'',
                            'dst_host':colns[2],
                            'dst_port':0,
                            'duration':0,
                            'bytes':0,
                            'rule':colns[3],
                            'action':'stored-file',
                            }
                    #You could explicitly ignore some types here, I just have one of the really noisy, not particularly interesting ones excluded.

                    #New security association.  Appears to be specific to 6.something Pixes.
                    #%PIX-6-602301: sa created, (sa) sa_dest= 192.168.0.1, sa_prot= 50, sa_spi= 0x888ddddd(9999999999), sa_trans= esp-3des esp-md5-hmac , sa_conn_id= 8\n
                    ## (" ".join(colns[0:2]).startswith("sa created"))

                    #Delete security association.  Appears to be specific to 6.something Pixes.
                    #%PIX-6-602302: deleting SA, (sa) sa_dest= 192.168.0.1, sa_prot= 50, sa_spi= 0x888ddddd(9999999999), sa_trans= esp-3des esp-md5-hmac , sa_conn_id= 6\n
                    ## (" ".join(colns[0:2]).startswith("deleting SA"))
                    
                    #%PIX-6-602201: ISAKMP Phase 1 SA created (local 192.168.0.1/500 (responder), remote myhost/500, authentication=pre-share, encryption=3DES-CBC, hash=MD5, group=2, lifetime=86400s)
                    # (colns[0].startswith("ISAKMP"))

                    #Appears after a TCP connection restarts.  x in use indicates the current number of connections.
                    #%PIX-6-302010: 1 in use, 399 most used.
                    elif (" ".join(colns[1:3]).startswith("in use")):
                        inserted=None
                    else:
                        print "Unable to insert line id %s: %s" % (count, line)
                        #Clear so we don't insert a duplicate of the last line
                        inserted=None

            except Exception,e:
                print "Unable to insert line id %s: %s: %s" % (count, line,e)
                print FlagFramework.get_bt_string(e)

        #Insert the final left over line
        if inserted:
            self.dbh_conn.mass_insert(**inserted)
            
        
        self.dbh.mass_insert_commit()
        self.dbh_conn.mass_insert_commit()

        #We are done inserting now, it is time to build the indexes to help searching speed.
        yield "Finished inserting, building indexes - this may take a while."

        self.dbh.check_index(tablename,'id')
        self.dbh_conn.check_index("conn_"+tablename,'id')
        self.dbh.check_index(tablename,'pix_ts')
        self.dbh_conn.check_index("conn_"+tablename,'pix_ts')
        
        self.dbh_conn.check_index("conn_"+tablename,'src_host')
        self.dbh_conn.check_index("conn_"+tablename,'src_port')
        self.dbh_conn.check_index("conn_"+tablename,'dst_host')
        self.dbh_conn.check_index("conn_"+tablename,'dst_port')
        self.dbh_conn.check_index("conn_"+tablename,'duration')
        self.dbh_conn.check_index("conn_"+tablename,'bytes')
        self.dbh_conn.check_index("conn_"+tablename,'action')

    def display(self,query,result):
        
        def message_view(query, result):
            result.table(
                columns=['id','syslog_ts' ,'hostname', 'pix_ts', 'pix_code','message'],
                names=['ID', 'Syslog TS', 'Hostname', 'PIX TS', 'PIX Code', 'Message'],
                table= query['logtable']+"_log",
                case=query['case']
                )

        def conn_view(query, result):
            result.table(
                columns = ['id','pix_ts','action','rule','src_if', 'src_port', 'src_host', 'dst_if', 'dst_host', 'dst_port','direction','conn_number','protocol',  'duration','bytes'],
                names = ['ID','PIX TS','PIX Action','PIX Rule', 'Src IF', 'Src Port', 'Src Host', 'Dest IF', 'Dest Host', 'Dest Port', 'Connection Direction','Connection Num','Protocol','Conn Duration','Conn Bytes'],
                table= "conn_" + query['logtable']+"_log",
                case=query['case']
                )
        
        result.notebook(
            names = [ "General", "Connections" ],
            callbacks = [message_view, conn_view],
            descriptions = [ "View General information", "View Connections" ],
            )
