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

""" Module for analysing TCPDump data as uploaded by the modified FLAG ethereal """
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.conf
config=pyflag.conf.ConfObject()

import pyflag.DB as DB

import pyflag.UI as UI

description = "TCPDump Analysis"
order = 40

class ConTable(Reports.report):
    """ Report to create and browse the connection table.

    A connection is a unique tuple (source_ip,source_port,dest_ip,dest_port) forming one end of the connection."""
    parameters = {'case':'flag_db'}
    name = "Connection Table"
    description = "Show unique TCP connections"
    order = 10
    
    def form(self,query,result):
        result.case_selector(message='Select Flag case to work with')
    
    def display(self,query,result):
        result.heading("Connection Table for case %r" % query['case'])
        
        links = [
            FlagFramework.query_type((),report='TCPTrace',family=query['family'],case=query['case'],__target__='con_id'),
            ]
        
        result.table(
            links=links,
            columns = ('con_id','INET_NTOA(src_ip)','src_port' ,'INET_NTOA(dest_ip)','dest_port','count'),
            names = ("Connection","Source IP","Source Port","Dest IP","Dest Port","No.Packets"),
            table='connection_table',
            case=query['case']
            )

    def analyse(self,query):
        dbh = self.DBO(query['case'])
        temp_table = dbh.get_temp()
        try:
            dbh.execute("create table %s (con_id int auto_increment, src_ip int unsigned, src_port int, dest_ip int unsigned, dest_port int,  count int,key(con_id), key(src_ip), key(dest_ip),key(src_port),key(dest_port))",(temp_table))

            dbh.execute("create table if not exists connection_table (con_id int auto_increment, src_ip int unsigned, src_port int, dest_ip int unsigned, dest_port int, count int, key(con_id), key(src_ip), key(dest_ip),key(src_port),key(dest_port))",())

            dbh.execute("insert into %s select NULL, ip_src , tcp_srcport , ip_dst , tcp_dstport,count(ip_dst)  from ip,tcp where ip.key_id = tcp.key_id group by ip_src , tcp_srcport , ip_dst , tcp_dstport",(temp_table))

            temp2 = dbh.get_temp()

            dbh.execute("create table %s select * from %s ",(temp2,temp_table))

            dbh.execute('insert into connection_table select if(a.con_id<b.con_id,b.con_id,a.con_id) as "con_id",(a.src_ip),a.src_port ,(a.dest_ip),a.dest_port,a.count+ifnull(b.count,0) as "total"  from %s as a left join %s as b on a.src_ip=b.dest_ip and a.dest_ip=b.src_ip and a.src_port=b.dest_port and a.dest_port=b.src_port group by "con_id"',(temp2,temp_table))
        except DB.DBError,e:
            tmp=self.ui()
            tmp.para("Unable to find the Pcap tables in this case, did you remember to upload data to this case?")
            tmp.para("Error reported was: %s" % e)
            raise Reports.ReportError(tmp)

    def reset(self,query):
        dbh = self.DBO(query['case'])
        dbh.execute('drop table connection_table',())

class DNSData(Reports.report):
    """ Class to browse the DNS traffic seen """
    name = 'DNS Traffic'
    description = 'View DNS traffic'
    parameters = {'case':'flag_db'}
    order = 20

    def form(self,query,result):
        result.case_selector(message='Select Flag case to work with')

    def display(self,query,result):
        result.heading("DNS table")
        
        result.table(
            columns = ('ip.key_id','if(isnull(dns_data_data),"Q","RR") ','dns_data_name','dns_data_type','dns_data_class' ,'dns_data_data ','INET_NTOA(ip_src)','INET_NTOA(ip_dst)'),
            names    = ("Packet ID","Type","Name","DNS Type","Class","Data","Source", "Dest"),
            table       = 'dns_data,ip',
            where     = ' ip.key_id=dns_data.key_id ',case=query['case'],
            links = [
                FlagFramework.query_type((),report='ShowPacket',family=query['family'],case=query['case'],__target__='packet_id')]
            )

class ProtocolsSeen(Reports.report):
    """ Reports statistics about the different protocols seen within the TCPDump and their frequency """
    name = "Protocols Seen"
    description = "Shows the different protocols seen within the capture"
    parameters = {'case':'flag_db'}
    order = 30

    def form(self,query,result):
        result.case_selector(message='Select Flag case to work with')
     

    def analyse(self,query):
        dbh = self.DBO(query['case'])
        dbh.execute("create table protocols_seen select eth_type, count(eth_type ) as count from eth group by eth_type",());

    def reset(self,query):
        dbh = self.DBO(query['case'])
        dbh.execute('drop table if exists protocols_seen',())

    def display(self,query,result):
        result.heading("Different Protocols Seen")
        result.table(
            columns = ('eth_type','string','count'),
            names    = ("Eth Type","Description","Packet #"),
            links = [ FlagFramework.query_type((),report='ProtocolDistro',family=query['family'],case=query['case'],__target__='protocol') ],
            table = 'protocols_seen, enum ',
            where = 'name="eth_type" and value=eth_type',case = query['case'],
            groupby='eth_type'
            )

class ProtocolDistro(ProtocolsSeen):
    """ Examine protocol distribution """
    hidden = True
    description = "This report shows all the different protocols transport layer procols seen (e.g. UDP,TCP etc)"
    name = "Examine protocol distribution"
    parameters = {"protocol":"numeric"}

    def form(self,query,result):
        result.heading("This report was not meant to be called seperately ")
        
    def analyse(self,query):
        #This needs reworking... The algorithm sucks! There has to be a better way
        dbh = self.DBO(query['case'])
        dbh.execute("create table if not exists proto_distro (`proto` int,`ip_proto` int,`count` int)",())
        
        #IP
        if query['protocol'] == '2048':
            dbh.execute("insert into proto_distro select 2048,ip_proto , count(ip_proto ) as count from ip group by ip_proto",())

    def display(self,query,result):
        result.heading("IP protocols used")
        dbh = self.DBO(query['case'])
        
        if query.has_key('graph'):
            dbh.execute('select ip_proto as `IP Protocol`,string as `Description`,count as `Packet #` from proto_distro, enum   where name="ip_proto" and value=ip_proto  group by ip_proto,string  order by  `IP Protocol`')
            x=[]
            y=[]
            for row in dbh:
                x.append("%s %s"%(row['IP Protocol'],row['Description']))
                y.append(row['Packet #'])

            import pyflag.Graph as Graph
                
            graph=Graph.Graph()
            graph.pie(x,y,explode='0.1',legend='yes')
            result.image(graph)
            return

        result.link("Click here to view graph",query,graph=1)
        result.table(
            columns = ('ip_proto','string','count'),
            names    = ("IP Protocol","Description","Packet #"),
            links = [ FlagFramework.query_type((),report='IPProtoBreakdown',family=query['family'],case=query['case'],__target__='ip_proto') ],
            table = 'proto_distro, enum ',
            where = 'name="ip_proto" and value=ip_proto',case = query['case'],
            groupby = 'ip_proto,string'
            )
        
    def reset(self,query):
        dbh = self.DBO(query['case'])
        dbh.execute('drop table if exists proto_distro',())


class IPProtoBreakdown(ProtocolDistro):
    """ This report shows how the IP protocols are broken down, and the relative proportions of traffic appearing in the capture """
    hidden = True
    name = "IP protocol break down"
    description="This report shows how the IP protocols are broken down"
    parameters = {"ip_proto":"numeric"}

    def analyse(self,query):
        #This needs reworking... The algorithm sucks! There has to be a better way
        dbh = self.DBO(query['case'])
        dbh.execute("create table if not exists ip_proto_breakdown (`ip_proto` int,`dest_port` int,`Packet Count` int)",())

        if int(query['ip_proto']) == 6:
             dbh.execute("insert into ip_proto_breakdown select 6,tcp_dstport , count(tcp_dstport ) as \"Packet Count\" from tcp where tcp_flags =2 group by tcp_dstport",())
        elif int(query['ip_proto']) == 17:
            dbh.execute("insert into ip_proto_breakdown select 17,U.udp_dstport, count(U.udp_dstport) from udp as U group by U.udp_dstport",())
        elif int(query["ip_proto"])==1:
            dbh.execute("insert into ip_proto_breakdown select 1,I.icmp_type,  count(I.icmp_type)  from icmp as I group by I.icmp_type",())

    def display(self,query,result):
        q = int(query['ip_proto'])
        dbh=self.DBO(query['case'])
        
        if q == 6:
            result.heading("TCP ports connected to")
            if query.has_key('graph'):
                dbh.execute('select T.dest_port as `Destination Port`,E.string as `Description`,`Packet Count` as `Packet Count` from ip_proto_breakdown as T left join %s.enum as E on T.dest_port = E.value and E.name="tcp_proto"  where ip_proto=6  order by  `Packet Count`',(config.FLAGDB))
                x=[]
                y=[]
                for row in dbh:
                    x.append("%s %s"%(row['Destination Port'],row['Description']))
                    y.append(row['Packet Count'])
                    
                import pyflag.Graph as Graph

                graph=Graph.Graph()
                graph.pie(x,y,explode='0.1',legend='yes')
                result.image(graph)
                return

            result.link("Click here to view graph",query,graph=1)
            result.table(
                columns = ('T.dest_port','E.string','`Packet Count`'),
                names    = ("Destination Port","Description","Packet Count"),
                links = [ FlagFramework.query_type((),report='TCPProtoBreakdown',family=query['family'],case=query['case'],__target__='tcp_dstport') ],
                table = 'ip_proto_breakdown as T left join %s.enum as E on T.dest_port = E.value and E.name="tcp_proto"' % config.FLAGDB,
                where = 'ip_proto=6',case = query['case'],
                )
        elif q == 17:
            result.heading("UDP ports connected to")

            result.table(
                columns = ('T.dest_port','E.string','`Packet Count`'),
                names    = ("Destination Port","Description","Packet Count"),
                links = [ FlagFramework.query_type((),report='udp_proto_breakdown',family=query['family'],case=query['case'],__target__='udp_dstport') ],
                table = 'ip_proto_breakdown as T left join flag.enum as E on T.dest_port = E.value and E.name="udp_proto"',
                where = 'ip_proto=17',case = query['case'],
                )
        elif q == 1:
            result.heading("ICMP Packets")

            result.table(
                columns = ('T.dest_port','E.string','`Packet Count`'),
                names    = ("Type","Description","Packet Count"),
                links = [ FlagFramework.query_type((),report='udp_proto_breakdown',family=query['family'],case=query['case'],__target__='udp_dstport') ],
                table = 'ip_proto_breakdown as T left join %s.enum as E on T.dest_port = E.value and E.name="icmp_type"' % config.FLAGDB,
                where = 'ip_proto=1',case = query['case'],
                )

        else:
            result.heading("Unimplemented protocol")
            result.para("Could not find a matching protocol for %r" % q)
    
    def reset(self,query):
        dbh = self.DBO(query['case'])
        dbh.execute('delete from ip_proto_breakdown where ip_proto = %r',(query['ip_proto']))

class TCPProtoBreakdown(IPProtoBreakdown):
    """ Lists TCP connections broken down by destination port """
    hidden = True
    name = "TCP protocol break down"
    description="Lists TCP connections broken down by destination port"
    parameters={"tcp_dstport":"numeric"}

    def analyse(self,query):
        #Check to see if we ran report connection_table which is a prepreq for this one.
        del query['report']
        query['report'] = 'ConTable'
        self.check_prereq(query);

    def display(self,query,result):
         result.heading("Connections to port %s " % query['tcp_dstport'])
         result.table(
             columns = ("con_id","INET_NTOA(src_ip)",'src_port','INET_NTOA(dest_ip)' ,'dest_port ','count'),
             names = ('Connection','Source IP','Source Port','Dest IP','Dest Port','count'),
             links = [
                FlagFramework.query_type((),report='TCPTrace',case=query["case"],family=query['family'],__target__='con_id'),
                FlagFramework.query_type((),report='search_ip',case=query["case"],family=query['family'],__target__='src_ip')],
             table = 'connection_table',
             where = 'dest_port=%r or src_port =%r ' % (query['tcp_dstport'],query['tcp_dstport']),
             case =query['case']
             )

    def reset(self,query):
        pass


class UDPProtoBreakdown(IPProtoBreakdown):
    """ Lists UDP packets broken down by destination port """
    hidden = True
    name = "UDP protocol break down"
    description="Lists UDP packets broken down by destination port "
    parameters={"udp_dstport":"numeric"}

    def analyse(self,query):
        #Check to see if we ran report connection_table which is a prepreq for this one.
        del query['report']
        query['report'] = 'ConTable'
        self.check_prereq(query);

    def display(self,query,result):
         result.heading("Packets to UDP port %s " % query['udp_dstport'])
         result.table(
             columns = ("udp.key_id","concat(INET_NTOA(ip.ip_src),\" -> \",INET_NTOA(ip.ip_dst))",'count(*)'),
             names = ('Packet ID','Communicating IPs','Total Packets'),
             links = [
                FlagFramework.query_type((),report='packet_breakdown',case=query["case"],family=query['family'],__target__='key_id'),
                FlagFramework.query_type((),report='udp_packet_stream',case=query["case"],family=query['family'],__target__='connection')],
             table = 'udp,ip',
             where = 'ip.key_id =udp.key_id and udp.udp_dstport =%r' % query['udp_dstport'],
             case =query['case']
             )

    def reset(self,query):
        pass

class TCPTrace(Reports.report):
    """ Reassembles the TCP connection and allowes the visulization of traffic exchanged """
    name = "TCP packet trace"
    hidden = "yes"
    description="Reassemble the data that forms the tcp stream in the same screen"
    parameters={"con_id" : "numeric"}

    def form(self,query,result):
        result.textfield("Select TCP connection to operate on ",'con_id')

    def analyse(self,query):
        del query['report']
        query['report'] = 'ConTable'
        self.check_prereq(query);

        dbh = self.DBO(query['case'])
        #Create the connection_cache table to store reassembled streams... This is done for speed.
        dbh.execute("create table if not exists connection_cache (con_id int, id int, direction char(1), size int, key(con_id))",())

        #Do the actual stream reconstruction and store the result in the connection_cache table.
        dbh.execute("insert into connection_cache select %s,ip.key_id,\">\",1+frame_pkt_len-ip_len+ ip_hdr_len+ tcp_hdr_len from frame,ip,tcp,data, connection_table where frame.key_id=ip.key_id and tcp.key_id=ip.key_id and ip.key_id = data.key_id and src_ip= ip_src and dest_ip= ip_dst and src_port = tcp_srcport and dest_port = tcp_dstport and con_id = %r",(query['con_id'],query['con_id']));
		  
        dbh.execute("insert into connection_cache select %s,ip.key_id, \"<\",1+frame_pkt_len-ip_len+ ip_hdr_len+ tcp_hdr_len from frame,ip,tcp,data, connection_table where frame.key_id=ip.key_id and tcp.key_id=ip.key_id and ip.key_id = data.key_id and src_ip= ip_dst and dest_ip= ip_src and src_port = tcp_dstport and dest_port = tcp_srcport and con_id = %r",(query['con_id'],query['con_id']));

    def reset(self,query):
        dbh =self.DBO(query['case'])
        dbh.execute("delete from connection_cache where con_id=%r",(query['con_id']))

    def display(self,query,result):
        dbh =self.DBO(query['case'])
        result.heading("Data dump for TCP connection")

        dbh.execute("select  INET_NTOA(src_ip) as source,src_port,INET_NTOA(dest_ip) as dest,dest_port from connection_table where con_id=%r",(query['con_id']))
        rs=dbh.fetch()

        result.start_table()
        result.row("Connection ",rs['source'],": ",rs['src_port']," -> ",rs['dest'],": ",rs['dest_port'])
        tmp = self.ui(result)
        del query['report']
        query['report'] = 'HTMLVisualise'
        tmp.link('Visualise',query)
        result.row(tmp, colspan = '50')
        result.end_table()

        #Get all the data from the connection cache:
        dbh.execute("select substring(data.data,size) as data,direction from connection_cache,data where connection_cache.id=data.key_id and con_id=%r group by id order by id",(query['con_id']))

        while 1:
            rs = dbh.cursor.fetchone()
            if not rs: break
            if rs[1] == '>':
                result.text(rs[0],color='red',font='typewriter',sanitise='full',wrap='full')
            else: result.text(rs[0],color='blue',font='typewriter',sanitise='full',wrap='full')

        result.text(finish=1)

class HTMLVisualise(TCPTrace):
    """ Visualises the content of a TCP stream by printing the connection data into the browser window. If the data is HTML, it displays what the page would have looked like """
    name = "HTML Visualise"
    hidden = "yes"
    description = "Visualise HTML pages"
    parameters={"con_id" : "numeric"}

    def analyse(self,query):
        #Check that we ran the tcptrace report on this already
        del query['report']
        query['report'] = 'TCPTrace'
        self.check_prereq(query)
    
    def display(self,query,result):
        dbh =self.DBO(query['case'])

        if result.name != "HTMLUI":
            result.heading("Error")
            result.para("This report will currently only work with the HTML UI")
            return 
        
        #Get all the data from the connection cache:
        dbh.execute("select substring(data.data,size) as data,direction from connection_cache,data where connection_cache.id=data.key_id and con_id=%r group by id order by id",(query['con_id']))
        import re

        for i in (1,2):
            tmp = ''
            while 1:
                rs = dbh.cursor.fetchone()
                if not rs: break
                tmp += rs[0]
                pattern = re.search("Content-Type:([^\r]*)",tmp)
                if pattern:
                    result.type = pattern.group(1)
                    
                if tmp.find("\r\n\r\n")>0: break

        def find_url(pattern):
            """ This function queries the database to find the url of the object mentioned in pattern. It then returns a URL that redirects back to HTMLVis to view it. pattern is a match object. """
            dbh2= self.DBO(query['case'])
            url = pattern.group(2)

            file_match = re.match("(http://[^\/]*/)?(.*)",url)
            print file_match.group(2)
            #Find the con_id for each of those urls
            dbh2.execute("select key_id from http where http_request_uri like '%%%s%%'",file_match.group(2))
            rs = dbh2.cursor.fetchone()
            if not rs: return "<img nosrc=%r" % file_match.group(2)
            #now find the con_id:
            dbh2.execute("select ip_src,ip_dst from ip where key_id=%s",rs[0])
            ip = dbh2.fetch()
            dbh2.execute("select tcp_srcport , tcp_dstport from tcp where key_id=%s",rs[0])
            ports = dbh2.fetch()

            dbh2.execute("select con_id from connection_table where ( src_ip=%s and src_port = %s and dest_ip = %s and dest_port = %s) or ( src_ip=%s and src_port = %s and dest_ip = %s and dest_port = %s)",(ip['ip_src'],ports['tcp_srcport'],ip['ip_dst'],ports['tcp_dstport'],ip['ip_dst'],ports['tcp_dstport'],ip['ip_src'],ports['tcp_srcport']))
            rs = dbh2.cursor.fetchone()
            if not rs: return "<img nosrc=%r" % file_match.group(2)
            del query['con_id']
            query['con_id'] = rs[0]
            print "My conid is %s " % query
            return "%sf?%s" % (pattern.group(1),query)

        def sanitise(s):
            """ Sanitises s from javascript and rewrites the img tags so they point back at flag for reconstruction """
            import re

            #Find all the urls:
            s=re.sub("(?is)(<\s*?img.*?src=['\"]?)([^\s'\"]*)",find_url,s)
            return s
        
        while 1:
            rs = dbh.cursor.fetchone()
            if not rs: break
            san =sanitise(rs[0])
            result.text(san,sanitise='none')
            
        result.text(finish=1)

        #This tricky call overloads the UI's display method with its stream method - this has the effect of dumping out the HTML verbatim into the browser. (Note this only makes sense for the HTMLUI).
        result.display = result.__str__


class HTTPURLs(Reports.report):
    """ Shows the URLs seen in the dump and links to their reconstruction """
    parameters =  {'case':'flag_db'}
    name = "Show HTTP URLs"
    description = " Displays URLs in dump "

    def form(self,query,result):
        result.case_selector(message='Select Flag case to work with')

    def display(self,query,result):
        result.heading("URLs found in case %s " %query['case'])
        
        result.table(
            columns = ('key_id', 'http_request_method' , 'http_request_uri'),
            names    = ('Packet','Method','URI'),
            links = [
               FlagFramework.query_type((),report='ShowPacket',family=query['family'],case=query['case'],__target__='packet_id'),
               ],
            table = 'http',
            case = query['case'],
            where = 'not isnull(http_request_uri )'
            )

class ShowPacket(Reports.report):
    """ Displays the content of the packet, as broken into different protocols in a nice tabular structure """
    parameters = {"packet_id":"numeric"}
    name = "Show packet"
    description = "Displays the packet in detail"

    def form(self,query,result):
        result.case_selector(message='Select Flag case to work with')
        result.textfield("Packet number to show:",'packet_id')

    def analyse(self,query):
        """ We depend on the connection_table for our report """
        new_query = FlagFramework.query_type((),
                                             family=query['family'],
                                             report='ConTable',
                                             case=query['case'])
        self.check_prereq(new_query)

    def display(self,query,result):
        #Create a new translate object
        translate = Translate(query['case'])
        
        packet_id = int (query['packet_id'])
        result.heading("Packet dump for packet number %s "% packet_id)
        dbh = self.DBO(query['case'])

        #Fix up the navigation bar so the user can scroll through all the packets:
        result.pageno = packet_id
        result.nav_query = query
        result.nav_query['__target__'] = 'packet_id'
        result.next = packet_id + 1
        if packet_id>1:
            result.previous=packet_id-1
        else:
            result.previous =None
        
        #Find all the tables in the case that contain TCPDump information:
        dbh.execute("select * from meta where property='tcpdump_table'",())
        for rs in dbh:
            dbh2 = self.DBO(query['case'])
            dbh2.execute("select * from %s where key_id=%s",(rs['value'],packet_id))
            rs2 = dbh2.fetch()
            if not rs2: continue

            result.para("Table %s" % rs['value'])
            del rs2['key_id']
            headings = rs2.keys()
            values = rs2.values()

            v =[]
            h=[]
            for i in range(len(headings)):
                h.append(headings[i].replace('_'," "))
                tmp = self.ui()
                d = translate.translate(headings[i],values[i])
                d = d.replace(r"\n","\n")
                d = d.replace(r"\r","")
                tmp.text(d,font='typewriter')
                v.append(tmp)

            result.start_table(border=3,width='100%')
            
            result.row(*h,**{'type':'heading'})
            result.row(*v)
            result.end_table()

        result.heading("Hex Dump of packet")
        dbh2.execute("select data from data where key_id = %s",packet_id)
        rs2 = dbh2.fetch()
        tmp = FlagFramework.HexDump(rs2['data'] , result)
        tmp.dump()

        #Now find out if this is in the connection table:
        dbh.execute("select ip_dst,ip_src from ip where key_id=%s",packet_id)
        ips = dbh.fetch()
        dbh.execute("select tcp_srcport,tcp_dstport from tcp where key_id=%s",packet_id)
        ports = dbh.fetch()

        if not ports or not ips: return
        
        dbh.execute("select con_id from connection_table where (src_ip=%s and src_port=%s and dest_ip=%s and dest_port=%s) or (src_ip=%s and src_port=%s and dest_ip=%s and dest_port=%s)",(ips['ip_src'],ports['tcp_srcport'],ips['ip_dst'],ports['tcp_dstport'],ips['ip_dst'],ports['tcp_dstport'],ips['ip_src'],ports['tcp_srcport']))

        rs = dbh.fetch()
        tmp = self.ui(result)
        
        #Make a new link object
        tmp.link("See the associated connection",FlagFramework.query_type((),report='TCPTrace',family='TCPDumpAnalysis',con_id = rs['con_id'],case=query['case']))
        result.para(tmp)

class Translate:
    """ Translate the given field to before displaying it in a table """
    def __init__(self,case=None):
        self.DBO = DB.DBO(case)

    def translate(self,name,value):
        """ Select the appropriate dispatcher to translate the field named by name.

        @arg name: Field name from the database
        @arg value: Value of field to translate (string)
        @return: A translated string or the value string if there is no translation """

        try:
            return self.dispatcher[name](self,name,value)
        except (KeyError,TypeError):
            return str(value)

    def enumerate(self,name,arg):
        """ Show the string representation from the case enum table """

        self.DBO.execute('select concat(string," (",value,")") as name from enum where name=%r and value=%r group by value',(name,arg))

        rs = self.DBO.fetch()
        return rs['name']

    def TCPPortEnum(self,name,arg):
        """ Show the string representation of the TCP Port from the main flag enum table """
        db = DB.DBO(None)
        db.execute('select concat(string," (",value,")") as name from enum where name="tcp_proto" and value=%r group by value',(arg))

        rs = db.fetch()
        return rs['name']

    def inet2A(self,name,arg):
        """ Converts from the u32 bit Inet format to a well formatted IP address """
        self.DBO.execute('select INET_NTOA(%r) as a',str(arg))
        rs = self.DBO.fetch()
        return rs['a']
    
    dispatcher = {
        'eth_type': enumerate,
        'ip_dst': inet2A,
        'ip_src': inet2A,
        'ip_proto':enumerate,
        'tcp_dstport':TCPPortEnum,
        'tcp_srcport':TCPPortEnum,
        'icmp_type':enumerate,
        }
    
        
