""" This modules handles the IRC protocol.

"""
# Michael Cohen <scudette@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
#   Added recipient column to table
#
# ******************************************************
#  Version: FLAG $Version: 0.80.1 Date: Tue Jan 24 13:51:25 NZDT 2006$
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
import pyflag.conf
config=pyflag.conf.ConfObject()
from pyflag.Scanner import *
import pyflag.DB as DB
from pyflag.FileSystem import CachedFile
import pyflag.FlagFramework as FlagFramework
from pyflag.FlagFramework import Curry
from NetworkScanner import *
import pyflag.Reports as Reports
import pyflag.logging as logging
import cStringIO,re
import plugins.NetworkForensics.PCAPFS as PCAPFS

class IRC:
    """ Class to manage the IRC state """
    ## This is a mapping between IRC numeric codes and an english
    ## version of their meaning (taken from
    ## http://www.irchelp.org/irchelp/ircd/numerics.html):
    command_lookup = {        
        1: "Reply: WELCOME",
        2: "Reply: YOURHOST",
        3: "Reply: CREATED",
        4: "Reply: MYINFO",
        5: "Reply: BOUNCE",
        5: "Reply: MAP",
        5: "Reply: PROTOCTL",
        6: "Reply: MAPMORE",
        7: "Reply: MAPEND",

        8: "Reply: SNOMASK",

        9: "Reply: STATMEMTOT",
        10: "Reply: STATMEM",
        14: "Reply: YOURCOOKIE",
        200: "Reply: TRACELINK",
        201: "Reply: TRACECONNECTING",
        202: "Reply: TRACEHANDSHAKE",
        203: "Reply: TRACEUNKNOWN",
        204: "Reply: TRACEOPERATOR",
        205: "Reply: TRACEUSER",
        206: "Reply: TRACESERVER",
        207: "Reply: TRACESERVICE",
        208: "Reply: TRACENEWTYPE",
        209: "Reply: TRACECLASS",
        210: "Reply: TRACERECONNECT",
        211: "Reply: STATSLINKINFO",
        212: "Reply: STATSCOMMANDS",
        213: "Reply: STATSCLINE",
        214: "Reply: STATSNLINE",
        215: "Reply: STATSILINE",
        216: "Reply: STATSKLINE",
        217: "Reply: STATSQLINE",
        217: "Reply: STATSPLINE",
        218: "Reply: STATSYLINE",
        219: "Reply: ENDOFSTATS",
        220: "Reply: STATSPLINE",
        221: "Reply: UMODEIS",
        222: "Reply: STATSBLINE",
        223: "Reply: STATSELINE",
        224: "Reply: STATSFLINE",
        225: "Reply: STATSDLINE",
        225: "Reply: STATSZLINE",
        226: "Reply: STATSCOUNT",
        227: "Reply: STATSGLINE",
        231: "Reply: SERVICEINFO",
        232: "Reply: ENDOFSERVICES",
        233: "Reply: SERVICE",
        234: "Reply: SERVLIST",
        235: "Reply: SERVLISTEND",
        239: "Reply: STATSIAUTH",
        240: "Reply: STATSVLINE",
        241: "Reply: STATSLLINE",
        242: "Reply: STATSUPTIME",
        243: "Reply: STATSOLINE",
        244: "Reply: STATSHLINE",
        245: "Reply: STATSSLINE",
        246: "Reply: STATSPING",
        246: "Reply: STATSTLINE",
        246: "Reply: STATSULINE",
        247: "Reply: STATSBLINE",
        247: "Reply: STATSGLINE",
        247: "Reply: STATSXLINE",
        248: "Reply: STATSDEFINE",
        248: "Reply: STATSULINE",
        249: "Reply: STATSDEBUG",
        250: "Reply: STATSDLINE",
        250: "Reply: STATSCONN",
        251: "Reply: LUSERCLIENT",
        252: "Reply: LUSEROP",
        253: "Reply: LUSERUNKNOWN",
        254: "Reply: LUSERCHANNELS",
        255: "Reply: LUSERME",
        256: "Reply: ADMINME",
        257: "Reply: ADMINLOC1",
        258: "Reply: ADMINLOC2",
        259: "Reply: ADMINEMAIL",
        261: "Reply: TRACELOG",
        262: "Reply: TRACEEND",
        262: "Reply: ENDOFTRACE",
        262: "Reply: TRACEPING",
        263: "Reply: TRYAGAIN",
        263: "Reply: LOAD2HI",
        265: "Reply: LOCALUSERS",
        266: "Reply: GLOBALUSERS",
        271: "Reply: SILELIST",
        272: "Reply: ENDOFSILELIST",
        274: "Reply: STATSDELTA",
        275: "Reply: STATSDLINE",
        280: "Reply: GLIST",
        281: "Reply: ENDOFGLIST",
        290: "Reply: HELPHDR",
        291: "Reply: HELPOP",
        292: "Reply: HELPTLR",
        293: "Reply: HELPHLP",
        294: "Reply: HELPFWD",
        295: "Reply: HELPIGN",
        300: "Reply: NONE",
        301: "Reply: AWAY",
        302: "Reply: USERHOST",
        303: "Reply: ISON",
        304: "Reply: TEXT",
        305: "Reply: UNAWAY",
        306: "Reply: NOWAWAY",
        307: "Reply: USERIP",
        307: "Reply: WHOISREGNICK",
        308: "Reply: WHOISADMIN",
        309: "Reply: WHOISSADMIN",
        310: "Reply: WHOISSVCMSG",
        311: "Reply: WHOISUSER",
        312: "Reply: WHOISSERVER",
        313: "Reply: WHOISOPERATOR",
        314: "Reply: WHOWASUSER",
        315: "Reply: ENDOFWHO",
        316: "Reply: WHOISCHANOP",
        317: "Reply: WHOISIDLE",
        318: "Reply: ENDOFWHOIS",
        319: "Reply: WHOISCHANNELS",
        321: "Reply: LISTSTART",
        322: "Reply: LIST",
        323: "Reply: LISTEND",
        324: "Reply: CHANNELMODEIS",
        325: "Reply: UNIQOPIS",
        326: "Reply: NOCHANPASS",
        327: "Reply: CHPASSUNKNOWN",
        329: "Reply: CREATIONTIME",
        331: "Reply: NOTOPIC",
        332: "Reply: TOPIC",
        333: "Reply: TOPICWHOTIME",
        334: "Reply: LISTUSAGE",
        334: "Reply: COMMANDSYNTAX",
        338: "Reply: CHANPASSOK",
        339: "Reply: BADCHANPASS",
        341: "Reply: INVITING",
        342: "Reply: SUMMONING",
        346: "Reply: INVITELIST",
        347: "Reply: ENDOFINVITELIST",
        348: "Reply: EXCEPTLIST",
        349: "Reply: ENDOFEXCEPTLIST",
        351: "Reply: VERSION",
        352: "Reply: WHOREPLY",
        353: "Reply: NAMREPLY",
        354: "Reply: WHOSPCRPL",
        361: "Reply: KILLDONE",
        362: "Reply: CLOSING",
        363: "Reply: CLOSEEND",
        364: "Reply: LINKS",
        365: "Reply: ENDOFLINKS",
        366: "Reply: ENDOFNAMES",
        367: "Reply: BANLIST",
        368: "Reply: ENDOFBANLIST",
        369: "Reply: ENDOFWHOWAS",
        371: "Reply: INFO",
        372: "Reply: MOTD",
        373: "Reply: INFOSTART",
        374: "Reply: ENDOFINFO",
        375: "Reply: MOTDSTART",
        376: "Reply: ENDOFMOTD",
        381: "Reply: YOUREOPER",
        382: "Reply: REHASHING",
        383: "Reply: YOURESERVICE",
        384: "Reply: MYPORTIS",
        385: "Reply: NOTOPERANYMORE",
        391: "Reply: TIME",
        392: "Reply: USERSSTART",
        393: "Reply: USERS",
        394: "Reply: ENDOFUSERS",
        395: "Reply: NOUSERS",
        401: "Error: NOSUCHNICK",
        402: "Error: NOSUCHSERVER",
        403: "Error: NOSUCHCHANNEL",
        404: "Error: CANNOTSENDTOCHAN",
        405: "Error: TOOMANYCHANNELS",
        406: "Error: WASNOSUCHNICK",
        407: "Error: TOOMANYTARGETS",
        408: "Error: NOSUCHSERVICE",
        408: "Error: NOCOLORSONCHAN",
        409: "Error: NOORIGIN",
        411: "Error: NORECIPIENT",
        412: "Error: NOTEXTTOSEND",
        413: "Error: NOTOPLEVEL",
        414: "Error: WILDTOPLEVEL",
        415: "Error: BADMASK",
        416: "Error: TOOMANYMATCHES",
        416: "Error: QUERYTOOLONG",
        421: "Error: UNKNOWNCOMMAND",
        422: "Error: NOMOTD",
        423: "Error: NOADMININFO",
        424: "Error: FILEERROR",
        429: "Error: TOOMANYAWAY",
        431: "Error: NONICKNAMEGIVEN",
        432: "Error: ERRONEUSNICKNAME",
        433: "Error: NICKNAMEINUSE",
        434: "Error: SERVICENAMEINUSE",
        435: "Error: SERVICECONFUSED",
        435: "Error: BANONCHAN",
        436: "Error: NICKCOLLISION",
        437: "Error: UNAVAILRESOURCE",
        437: "Error: BANNICKCHANGE",
        438: "Error: DEAD",
        438: "Error: NICKTOOFAST",
        438: "Error: NCHANGETOOFAST",
        439: "Error: TARGETTOOFAST",
        440: "Error: SERVICESDOWN",
        441: "Error: USERNOTINCHANNEL",
        442: "Error: NOTONCHANNEL",
        443: "Error: USERONCHANNEL",
        444: "Error: NOLOGIN",
        445: "Error: SUMMONDISABLED",
        446: "Error: USERSDISABLED",
        451: "Error: NOTREGISTERED",
        452: "Error: IDCOLLISION",
        453: "Error: NICKLOST",
        455: "Error: HOSTILENAME",
        461: "Error: NEEDMOREPARAMS",
        462: "Error: ALREADYREGISTRED",
        463: "Error: NOPERMFORHOST",
        464: "Error: PASSWDMISMATCH",
        465: "Error: YOUREBANNEDCREEP",
        466: "Error: YOUWILLBEBANNED",
        467: "Error: KEYSET",
        468: "Error: INVALIDUSERNAME",
        468: "Error: ONLYSERVERSCANCHANGE",
        471: "Error: CHANNELISFULL",
        472: "Error: UNKNOWNMODE",
        473: "Error: INVITEONLYCHAN",
        474: "Error: BANNEDFROMCHAN",
        475: "Error: BADCHANNELKEY",
        476: "Error: BADCHANMASK",
        477: "Error: MODELESS",
        477: "Error: NOCHANMODES",
        477: "Error: NEEDREGGEDNICK",
        478: "Error: BANLISTFULL",
        479: "Error: BADCHANNAME",
        481: "Error: NOPRIVILEGES",
        482: "Error: CHANOPRIVSNEEDED",
        483: "Error: CANTKILLSERVER",
        484: "Error: DESYNC",
        484: "Error: ISCHANSERVICE",
        485: "Error: UNIQOPPRIVSNEEDED",
        487: "Error: CHANTOORECENT",
        488: "Error: TSLESSCHAN",
        489: "Error: VOICENEEDED",
        491: "Error: NOOPERHOST",
        492: "Error: NOSERVICEHOST",
        501: "Error: UMODEUNKNOWNFLAG",
        502: "Error: USERSDONTMATCH",
        503: "Error: GHOSTEDCLIENT",
        504: "Error: LAST_ERR_MSG",
        511: "Error: SILELISTFULL",
        512: "Error: NOSUCHGLINE",
        512: "Error: TOOMANYWATCH",
        513: "Error: BADPING",
        514: "Error: TOOMANYDCC",
        521: "Error: LISTSYNTAX",
        522: "Error: WHOSYNTAX",
        523: "Error: WHOLIMEXCEED",
        600: "Reply: LOGON",
        601: "Reply: LOGOFF",
        602: "Reply: WATCHOFF",
        603: "Reply: WATCHSTAT",
        604: "Reply: NOWON",
        605: "Reply: NOWOFF",
        606: "Reply: WATCHLIST",
        607: "Reply: ENDOFWATCHLIST",
        617: "Reply: DCCSTATUS",
        618: "Reply: DCCLIST",
        619: "Reply: ENDOFDCCLIST",
        620: "Reply: DCCINFO",
        999: "Error: NUMERIC_ERR",
        }

    def __init__(self,fd,dbh):
        self.fd=fd
        self.dbh = dbh

    def rewrite_reply(self,prefix,command,line):
        return line, self.command_lookup[command]+"(%s)" % command

    def store_command(self,prefix,command,line):
        packet_id = self.fd.get_packet_id(position=self.fd.tell())

        if not prefix: prefix = self.nick

        m=re.search("^:?([^!@]+)",prefix)
        if m:
            short_name = m.group(1)
        else:
            short_name = prefix

        try:
            base_stream_inode = self.fd.inode[:self.fd.inode.index('/')]
        except IndexError:
            base_stream_inode = self.fd.inode
            
        if (line != None):
            recipient = line.split(':')[0]
        else:
            recipient = ""
            
        self.dbh.execute(""" insert into irc_messages set sender=%r,full_sender=%r,
        inode=%r, packet_id=%r, data=%r, command = %r, recipient = %r""",(
            short_name,prefix,base_stream_inode, packet_id,
            line, command, recipient 
            ))

    password = ''
    def PASS(self,prefix,command,line):
        self.password = line
        return line,command

    nick = ''
    def NICK(self,prefix,command,line):
        """ When a user changes their nick we store it in the database """
        self.nick = line
        self.dbh.execute(
            """ insert into  `irc_userdetails`  set
            inode=%r, nick=%r, username=%r, password=%r
            """,( self.fd.inode, self.nick, self.username, self.password))
        return line,command

    username = ''
    def USER(self,prefix,command,line):
        self.username = line
        return line,command

    def dispatch(self,prefix,command,line):
        """ A dispatcher to handle the command given. """
        try:
            line = ("%r" % line)[1:-1]
        except:
            pass
        
        try:
            line,command=getattr(self,command)(prefix,command,line)
        except AttributeError,e:
            ## If the command is an int, we try to remap it:
            try:
                line,command=self.rewrite_reply(prefix,int(command),line)
            except (ValueError,KeyError):
                pass

        self.store_command(prefix,command,line)

    def parse(self):
        regex = re.compile("(?::([^ ]+) )?([^ ]+)(?: (.*))?")
        
        while 1:
            line = self.fd.readline().strip()
            if len(line)==0: break
            try:
                m=regex.match(line)
                ## Dispatch a command handler:
                self.dispatch(m.group(1),m.group(2),m.group(3))
            except IndexError,e:
                logging.log(logging.WARNINGS, "unable to parse line %s (%s)" % (line,e))
                

class IRCScanner(NetworkScanFactory):
    """ Collect information about IRC traffic """
    default = True
    depends = ['StreamReassembler']
    
    def prepare(self):
        self.dbh.execute(
            """CREATE TABLE if not exists `irc_messages` (
            `id` int auto_increment,
            `sender` VARCHAR( 250 ) NOT NULL ,
            `full_sender` VARCHAR( 255 ) NOT NULL ,
            `recipient` VARCHAR(50),
            `command` VARCHAR(255) NOT NULL,
            `inode` VARCHAR(50) NOT NULL,
            `packet_id` INT,
            `session` VARCHAR(250),
            `data` TEXT NOT NULL,
            key(id)
            )""")
        self.dbh.execute(
            """ CREATE TABLE if not exists `irc_session` (
            `id` VARCHAR(250),
            `user` VARCHAR( 250 ) NOT NULL
            )""")
        self.dbh.execute(
            """ CREATE TABLE if not exists `irc_userdetails` (
            `inode` VARCHAR(250),
            `nick` VARCHAR(250),
            `username` VARCHAR(250),
            `password` VARCHAR(250)
            )""")
        self.dbh.execute(
            """ CREATE TABLE if not exists `irc_p2p` (
            `inode` VARCHAR(250),
            `session_id` INT,
            `channel_id` INT,
            `to_user` VARCHAR(250),
            `from_user` VARCHAR(250),
            `context` VARCHAR(250)
            )""")

    def process_stream(self, stream, factories):
        forward_stream, reverse_stream = self.stream_to_server(stream, "IRC")
        if not reverse_stream or not forward_stream: return

        combined_inode = "I%s|S%s/%s" % (stream.iosource.name, forward_stream, reverse_stream)
        logging.log(logging.DEBUG,"Openning %s for IRC" % combined_inode)

        ## We open the file and scan it for IRC:
        fd = self.fsfd.open(inode=combined_inode)
        irc=IRC(fd,self.dbh)
        irc.parse()
                    
class BrowseIRCChat(Reports.report):
    """ This allows chat messages to be browsed. """
    name = "Browse IRC Chat"
    family = "Network Forensics"
    def form(self,query,result):
        try:
            result.case_selector()
            PCAPFS.draw_only_PCAPFS(query,result)
        except KeyError:
            pass

    def display(self,query,result):
        result.heading("Chat sessions")

        def Stream_cb(value):
            tmp = result.__class__(result)
            try:
                base_stream_inode = value[:value.index('/')]
            except IndexError:
                base_stream_inode = value
                
            tmp.link(value,target = FlagFramework.query_type((),
                    family='Disk Forensics', case=query['case'],
                    inode=base_stream_inode,
                    report='View File Contents', mode="Combined streams"
                                                             ))
            return tmp

        def text_cb(value, **options):
            tmp = result.__class__(result)
            tmp.text(value, **options)
            return tmp
        
        result.table(
            columns = ['pcap.id', 'from_unixtime(pcap.ts_sec,"%Y-%m-%d")','concat(from_unixtime(pcap.ts_sec,"%H:%i:%s"),".",pcap.ts_usec)','inode','concat(left(inode,instr(inode,"|")),"p0|o",cast(packet_id as char))','command','sender','recipient', 'data'],
            names = ['ID','Date','Time','Stream','Packet','Command','Sender Nick','Recipient','Text'],
            table = "irc_messages join pcap on packet_id=pcap.id" ,
#            callbacks = { 'Text': Curry(text_cb, wrap='full',wrap_size=80, font='typewriter'),
#                          'Recipient': Curry(text_cb, wrap_size=20, wrap='full', font='typewriter')
#                          },
            links = [None, None,None,
                     FlagFramework.query_type((),
                        family='Disk Forensics', case=query['case'],
                        __target__='inode',
                        report='View File Contents', mode="Combined streams"
                        ),
                     FlagFramework.query_type((),
                        family="Network Forensics", case=query['case'],
                        report='View Packet', 
                        __target__='inode'),
                     ],
            case = query['case']
            )
