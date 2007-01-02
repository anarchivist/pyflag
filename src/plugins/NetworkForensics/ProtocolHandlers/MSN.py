""" This module implements processing for MSN Instant messager traffic

Most of the information for this protocol was taken from:
http://www.hypothetic.org/docs/msn/ietf_draft.txt
http://www.hypothetic.org/docs/msn/client/file_transfer.php
http://www.hypothetic.org/docs/msn/notification/authentication.php

Further info from the MSNPiki (an MSN protocol wiki)

TODO: Further work to make this scanner compatible with the latest MSN
version (I believe this is version 11 at 20060531).

"""
# Michael Cohen <scudette@users.sourceforge.net>
# Gavin Jackson <gavz@users.sourceforge.net>
# Greg <gregsfdev@users.sourceforge.net>
#
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

import pyflag.conf
config=pyflag.conf.ConfObject()
from pyflag.Scanner import *
import struct,sys,cStringIO
import pyflag.DB as DB
from pyflag.FileSystem import File
import pyflag.IO as IO
from pyflag.FlagFramework import query_type
from NetworkScanner import *
import pyflag.Reports as Reports
import pyflag.pyflaglog as pyflaglog
import base64
import plugins.NetworkForensics.PCAPFS as PCAPFS
import urllib
from pyflag.TableObj import StringType, TimestampType, InodeType, IntegerType

class RingBuffer:
    def __init__(self, size_max):
        self.size_max = size_max
        self.cur=0
        self.data={}        

    def append(self, datum):
        self.data[self.cur]=datum
        self.cur=(self.cur+1) % self.size_max

    def has_key(self,string):
        return self.data.has_key(string)

def safe_base64_decode(s):
    """ This attempts to decode the string s, even if it has incorrect padding """
    tmp = s
    for i in range(1,5):
        try:
            return base64.decodestring(tmp)
        except:
            tmp=tmp[:-i]
            continue

    return s

allowed_file_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_ "

def get_temp_path(case,inode):
    """ Returns the full path to a temporary file based on filename.
    """
    filename = inode.replace('/','-')
    result= "%s/case_%s/%s" % (config.RESULTDIR,case,filename)
    return result

class message:
    """ A class representing the message """
    def __init__(self,dbh,fd,ddfs):
        self.dbh=dbh
        self.fd=fd
        self.ddfs = ddfs
        self.client_id='Unknown'
        self.session_id = -1
        self.inodes = []
        self.participants = []
        self.contact_list_groups = {}

        self.list_lookup={}
        self.list_lookup['forward_list']=self.forward_list = []
        self.list_lookup['allow_list']=self.allow_list = []
        self.list_lookup['block_list']=self.block_list = []
        self.list_lookup['reverse_list']=self.reverse_list = []
        self.list_lookup['pending_list']=self.pending_list = []

    def get_packet_id(self):
        self.offset = self.fd.tell()
        ## Try to find the time stamp of this request:
        self.packet_id = self.fd.get_packet_id(self.offset)
        return self.packet_id

    def store_list(self,list,listname):
        """Store list in DB"""
        if len(list)>0:
            #pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Inserting list: %s" % ",".join(list))
            self.insert_user_data(nick="%s (Target)" % self.client_id,data_type=listname,data=",".join(list),sessionid=-99)
                    
    def add_unique_to_list(self,data,list):
        #Add a unique entry to the list specified
        try:
            if (list.index(data)):
                #Already in the list
                pass
        except ValueError:
            #Don't have this one, so insert it
            list.append(data)
            #pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Appending to list:%s" % (list))

    def del_participant(self,username):
        try:
            #pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Removing participant:%s" % username)
            self.participants.remove(username)
        except:
            #name wasn't in participants for some reason, shouldn't really happen.
            pass

    def insert_session_data(self,sender,recipient,type,tr_id=-99,data=None,sessionid=None,p2pfile=None):
        """
        Insert MSN session data.  A session id of -1 means we couldn't
        figure out what the session id was, but it matters to this
        type of entry.  This only really happens when the target does
        not participate in chat at all for that stream.


        A session id of -99 means that a session id
        doesn't make sense for this sort of data (e.g. presence
        notifications).  This an important distinction - if we later
        find out the session id we override any -1's for the stream.
        However -99 values are left unchanged.

        """
        if not sessionid:
            sessionid=self.session_id

        self.dbh.insert("msn_session",
                        inode=self.fd.inode,
                        packet_id=self.get_packet_id(),
                        sender=sender,
                        recipient=recipient,
                        type=type,
                        transaction_id=tr_id,
                        data=data,
                        session_id=sessionid,
                        p2p_file= p2pfile,
                        )
        
    def insert_user_data(self,nick,data_type,data,tr_id=-1,sessionid=None):
        """
        Insert user data into the table.  We only keep each type of
        user data once for each stream and session, otherwise we get
        way too many rows of the same data.  The primary key is
        inode,session_id,user_data_type.
        
        """
        if not sessionid:
            sessionid=self.session_id

        try:
            self.dbh.insert("msn_users",
                           inode=self.fd.inode,
                           packet_id=self.get_packet_id(),
                           transaction_id=tr_id,
                           session_id=session_id,
                           nick=nick,
                           user_data_type=data_type,
                           user_data=data)
        except:
            #We have duplicate user data,
            #pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Ignoring data as duplicate:%s,%s,%s" % (nick,data_type,data))
            pass

    def store_phone_nums(self,nick,type,number):
        """
        Store intercepted phone numbers
        
        Valid Types:
        
        # PHH - home phone number
        # PHW - work phone number
        # PHM - mobile phone number
        # MOB - are other people authorised to contact me on my MSN Mobile (http://mobile.msn.com/) device?
        # MBE - do I have a mobile device enabled on MSN Mobile (http://mobile.msn.com/)?
        
        Phone numbers are not sent if they are empty, MOB and MBE
        aren't sent unless they are enabled. Because of this, the only
        way to tell whether you've finished receiving PRPs is when you
        receive the first LSG response (there will always be at least
        one LSG response).

        The value for the first three items can be anything up to 95
        characters. This value can contain any characters allowed in a
        nickname and is URL Encoded.

        The value of MOB and MBE can only be Y (yes). If MOB is set,
        the client has allowed other people to contact him on his
        mobile device through the PAG command. If MBE is set, that
        shows that the client has enabled a mobile device on MSN
        Mobile (http://mobile.msn.com/). Note that these values are
        completely independent from the PHM mobile device number.
        """
        
        if (type=="PHH"):
            
            self.insert_user_data(nick,'home_phone',urllib.unquote(number),sessionid=-99)
            
        elif (type=="PHW"):
            
            self.insert_user_data(nick,'work_phone',urllib.unquote(number),sessionid=-99)
            
        elif (type=="PHM"):
            
            self.insert_user_data(nick,'mobile_phone',urllib.unquote(number),sessionid=-99)
            
        elif (type=="MOB"):
            
            self.insert_user_data(nick,'msn_mobile_auth',urllib.unquote(number),sessionid=-99)
            
        elif (type=="MBE"):
            
            self.insert_user_data(nick,'msn_mobile_device',urllib.unquote(number),sessionid=-99)
            
        else:
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Unknown phone type: %s" % self.cmdline.strip())
        
        
    def parse(self):
        """ We parse the first message from the file like object in
        fp, thereby consuming it"""
        
        # Read the first command:
        self.cmdline=self.fd.readline()
        if len(self.cmdline)==0: raise IOError("Unable to read command from stream")

        try:
            ## We take the last 3 letters of the line as the
            ## command. If we lose sync at some point, readline will
            ## resync up to the next command automatically
            self.cmd = self.cmdline.split()[0][-3:]

            ## All commands are in upper case - if they are not we
            ## must have lost sync:
            if self.cmd != self.cmd.upper() or not self.cmd.isalpha(): return None
        except Exception, e:
            print "Error parsing commandline %s" % self.cmdline
            pyflaglog.log(pyflaglog.ERROR, e)
            return ''

        self.words = self.cmdline.split()
        ## Dispatch the command handler
        try:
            return getattr(self,self.cmd)()
        except AttributeError,e:
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Unable to handle command %r from line %s (%s)" % (self.cmd,self.cmdline,e))
            return None

    def get_data(self):
        return self.data

    def parse_mime(self):
        """ Parse the contents of the headers

        """
        #print "words%s"%self.words
        try:
            self.length = int(self.words[-1])
        except:
            #The last parameter isn't the length, so this message is stuffed
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Line %s is not a valid MSG, no length in bytes" % self.cmdline)
            return False
        
        self.offset = self.fd.tell()
        self.headers = {}
        ## Read the headers:
        while 1:
            line = self.fd.readline()
            #print "parsing header line:%s" % line
            #We are finished if we see a newline
            if (line =='\r\n'): break
            try:
                header,value = line.split(":")
                self.headers[header.lower()]=value.lower().strip()
            except ValueError:
                #We don't have : separated parameters, so something is wrong.
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Parse mime failed on:%s.  Headers:%s" % (line,self.headers))
                return False

        current_position = self.fd.tell()
        self.data = self.fd.read(self.length-(current_position-self.offset))
        return True
    
    def CAL(self):

        """ Target is inviting someone to a new session

        CAL 8 dave@passport.com\r\n

        Server responds, saying I am ringing the person:

        We use this to store the current session ID for the entire TCP stream.
        
        CAL 8 RINGING 17342299\r\n

        """
        
        if (self.words[2] == "RINGING"):
            self.session_id=self.words[3]
        else:
            self.insert_session_data("%s (Target)" % self.client_id,self.words[2],"INVITE FROM TARGET",tr_id=self.words[1])            
            self.insert_user_data(self.words[2],'user_msn_passport',self.words[2],tr_id=self.words[1])
            
	self.state = "CAL"

    def OUT(self):
        """Target left MSN session"""
        
        
        self.insert_session_data("%s (Target)" % self.client_id,'SWITCHBOARD SERVER',"TARGET LEFT SESSION")
        
    def BYE(self):
        """A participant has left the session

        e.g.

        BYE blah@hotmail.com

        """
        
        
        self.del_participant(self.words[1])
        self.insert_session_data(self.words[1],'SWITCHBOARD SERVER',"USER LEFT SESSION")

    def USR(self):
        """
        Target pyflaglog into switchboard server using same auth string as passed back by server in XFR

        Most of this info is pretty boring.  I only store stuff that has usernames in it.
        
                
        USR <transation id> example@passport.com 17262740.1050826919.32307

        If successful, server passes back (currently ignoring):
        
        USR <same transaction id> OK example@passport.com Example%20Name


        Initial USR

        Initiates authentication process.

        USR trid TWN I account_name

            * trid : Transaction ID
            * TWN : Name of authentication system (always "TWN")
            * I : Status of authentication (always "I" for initial)
            * account_name : Your passport address 

        Returns
        The server will either respond with XFR to transfer you, or with USR to continue the authentication process.

        Subsequent USR Response:

        USR trid TWN S auth_string

            * trid : Transaction ID
            * TWN : Name of authentication system (always "TWN")
            * S : Status of authentication (always "S" for subsequent)
            * auth_string : String used for Tweener authentication 


        [edit]
        Final USR

        USR trid TWN S ticket

            * trid : Transaction ID
            * TWN : Name of authentication system (always "TWN" for Tweener)
            * S : Status of authentication (always "S" for subsequent)
            * ticket : Ticket retrieved after Tweener authentication 

        Returns

        USR trid OK account_name display_name verified 0

            * trid : Transaction ID
            * OK : Confirms a successful login
            * account_name : Your Passport account-name
            * display_name : Your URL Encoded friendly-name
            * verified : Either 0 or 1 if your account is verified
            * 0 : Unknown (Kids passport?) 
        
	"""
	
        
        #pyflaglog.log(pyflaglog.VERBOSE_DEBUG,  "USR:%s" % self.cmdline.strip())
        self.state = "USR"
        
        if (self.words[2]=="OK"):
            
            self.client_id = self.words[3]
            #print "USR setting self.client_id to %s for inode %s" %(self.client_id,self.fd.inode)
            self.insert_session_data("%s (Target)" % self.client_id,'SWITCHBOARD SERVER',"TARGET ENTERING NEW SWITCHBOARD SESSION")

            self.insert_user_data("%s (Target)" % self.client_id,'target_msn_passport',self.words[3],tr_id=self.words[1])
            self.insert_user_data("%s (Target)" % self.client_id,'url_enc_display_name',urllib.unquote(self.words[4]),tr_id=self.words[1])
            
        elif (self.words[2]=="TWN")and(self.words[3]=="I"):
            #Ignore 'S' messages - no value.
            self.client_id = self.words[4]
            #print "USR setting self.client_id to %s for inode %s" %(self.client_id,self.fd.inode)
            self.insert_user_data("%s (Target)" % self.client_id,'target_msn_passport',self.words[4],tr_id=self.words[1])
        elif (self.words[2]!="TWN"):
            #must be of form: USR <transation id> example@passport.com 17262740.1050826919.32307
            self.client_id = self.words[2]
            #print "USR  setting self.client_id to %s for inode %s" %(self.client_id,self.fd.inode)
            self.insert_user_data("%s (Target)" % self.client_id,'target_msn_passport',self.words[2],tr_id=self.words[1])

    def XFR(self):

        self.state = "XFR"
        pass
        
        """This command creates a new switchboard session.

        It is largely uninteresting.  I have kept it to record the
        switchboard server IP.  If this is proving to be useless we
        can take it out.

        Request:
        XFR <transaction id> SB

        e.g.
        XFR 15 SB

        Response:
        XFR <same transaction id> SB <ip of switchboard server:port> <auth type, always=CKI> <auth string to prove identity>

        e.g.
        XFR 15 SB 207.46.108.37:1863 CKI 17262740.1050826919.32308

        OR you can be transferred to a different nameserver:

        XFR trid NS address 0 current_address

        * trid : Transaction ID
        * NS : Tells you that you are being redirected to a notification server
        * address : IP and port of server you are being redirected to (separated by a colon)
        * 0 : unknown
        * current_address : The address of the dispatch/notification server you are currently connected to

        """

        
        #print "XFR:%s" % self.cmdline.strip()
        try:
            self.switchboard_ip = self.words[3].split(":")[0]
            self.switchboard_port = self.words[3].split(":")[1]
            #This is a server response
            self.insert_session_data("NOTIFICATION SERVER","%s (Target)" % self.client_id,"SWITCHBOARD SERVER OFFER",tr_id=self.words[1],data="switchboard server:%s" % self.words[3])

        except:
            pass
            #This is a client request, I don't think it is interesting enough to record.
		
    def ANS(self):
        """ Logs into the Switchboard session.

        We use this to store the current session ID and client_id (target username) for this entire TCP stream.

        ANS <transaction id> <account name> <auth string> <session id>
        
        e.g.
        ANS 1 name_123@hotmail.com 849102291.520491113 11752013

        Ignore these responses from the server:
        ANS 1854 OK
        
        """
        

        if (self.words[2].find("OK")<0):

            try:
                self.session_id=int(self.words[-1])
                ## This stores the current clients username
                self.client_id = self.words[2]
                #print "ANS setting self.client_id to %s for inode %s" %(self.client_id,self.fd.inode)
                self.insert_session_data("%s (Target)" % self.client_id,"SWITCHBOARD SERVER","TARGET JOINING_SESSION",tr_id=self.words[1])
                
                self.insert_user_data("%s (Target)" % self.client_id,'target_msn_passport',self.words[2],tr_id=self.words[1])
            except Exception,e:
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"ANS not decoded correctly: %s. Exception: %s" % (self.cmdline.strip(),e))
                pass

            self.state = "ANS"
	
    def IRO(self):
        """
        List of current participants.

        IRO <transaction id> <number of this IRO> <total number of IRO that will be sent> <username> <display name>
        
        """
        
        try:
            self.insert_session_data(sender=self.words[4],recipient="%s (Target)" % self.client_id,type="CURRENT_PARTICIPANTS",tr_id=self.words[1])
            self.state = "IRO"

            self.insert_user_data(self.words[4],'user_msn_passport',self.words[4],tr_id=self.words[1])
            self.insert_user_data(self.words[4],'url_enc_display_name',urllib.unquote(self.words[5]),tr_id=self.words[1])
            self.add_unique_to_list(self.words[4],self.participants)                

        except Exception,e:
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "IRO not decoded correctly: %s. Exception: %s" % (self.cmdline.strip(),e))
                pass

    def parse_psm(self,length,trid=None):
        """ Parse read the contents of the xml personal message following a UBX/UUX command

        """
        if length > 0:
            #print "Reading %s bytes of personal message" % length
            self.insert_user_data(nick=self.words[1],data_type='personal_message',data=self.fd.read(length),tr_id=trid)
        

    def UUX(self):
        """
        UUX
        
        This is the command used to set your Personal Message (PSM) or currently playing song. It is a payload command, with the only parameter after the TrID being the length of the payload:
        
        < UUX 10 72\r\n
        
        If this command is successful, the server will reply with a message containing the TrID you used and a 0 as the only parameter.
        
        > UUX 10 0\r\n
        
        The contents of the payload depend on whether you have a currently playing song or not.
        [edit]
        Without a Current Media
        
        <Data><PSM>My Personal Message</PSM><CurrentMedia></CurrentMedia></Data>
        
        The contents of the PSM tag is your personal message (XML encoded!), leaving <CurrentMedia> blank. Both may be specified, but this is not recommended. See below to find out how to set both and show only the one you want (Enabled setting).
        
        The client will always limit your PSM to 129 characters (same as the friendly name). Server-wise however, a payload of up to 1KB (including XML) is being accepted. The client will always show only 129 characters in the main contact list, but will show the full PSM in conversation windows.
        [edit]
        With a Current Media
        
        The value of the CurrentMedia tag can be thought of as an array separated by the string "\0" (literal backslash followed by zero, not NULL). The elements of this 'array' are as follows:

        * Application - This is the app you are using. Usually empty (iTunes and Winamp are the only ones known to be accepted)
        * Type - This is the type of PSM, either 'Music', 'Games' or 'Office'
        * Enabled - This is a boolean value (0/1) to enable/disable the Current Media setting
        * Format - A formatter string (you may be familiar with this syntax if you've used .NET); for example, "{0} - {1}"
        * First line - The first line (Matches {0} in the Format)
        * Second line - The second line (Matches {1} in the Format)
        * Third line - The third line (Matches {2} in the Format) 
        
        There is no known limit to the number of formatter tags, but it is speculated to be 99.
        [edit]
        Examples of the CurrentMedia Tag

        Currently Playing Song
        
         <CurrentMedia>\0Music\01\0{0} - {1}\0 Song Title\0Song Artist\0Song Album\0\0</CurrentMedia>
         
         Playing a Game
         
         <CurrentMedia>\0Games\01\0Playing {0}\0Game Name\0</CurrentMedia>
         
         Microsoft Office
         
         <CurrentMedia>\0Office\01\0Office Message\0Office App Name\0</CurrentMedia>


        """
        
        self.parse_psm(length=int(self.words[2]),trid=int(self.words[1]))
        self.state = "UUX"
        
        
    def UBX(self):
        """
        UBX

        UBX is the sister command to UUX. UUX is used to set your personal message, UBX is sent by the server to all principles to inform them of the change (where B means Buddy). The format is similar to UUX; they are payload commands where the first parameter is the passport address of the contact who has just changed their personal message or currently playing song, and the second parameter is the length of the payload:
        
        > UBX passport@hotmail.com xxx\r\n
        <Data><PSM>My Personal Message</PSM><CurrentMedia></CurrentMedia></Data>
        
        > UBX passport@hotmail.com xxx\r\n
        <Data><PSM></PSM><CurrentMedia>\0Music\01\0{0} - {1}\0Song Title\0
        Song Artist\0Song Album\0{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\0</CurrentMedia></Data>
        
        (Sent on one line - split for ease of viewing here)
        """
        
        self.parse_psm(length=int(self.words[2]))
        self.insert_user_data(nick=self.words[1],data_type='user_msn_passport',data=self.words[1])
        self.state = "UBX"

    def RNG(self):
        """ Target is being invited to a new session

        We use this to store the current session ID for this entire TCP stream.

        Format:
        RNG <sessionid> <switchboard server ip:port> <auth type, always=cki> <auth string> <nick of inviter> <url encoded display name of inviter>
        """
        
        self.session_id = self.words[1]

        #The inviter is a participant
        self.add_unique_to_list(self.words[5],self.participants)
        self.insert_session_data(sender=self.words[5],recipient="%s (Target)" % self.client_id,type="TARGET INVITED")
	self.state = "RNG"

        self.insert_user_data(self.words[5],'user_msn_passport',self.words[5])
        self.insert_user_data(self.words[5],'url_enc_display_name',urllib.unquote(self.words[6]))
                
    def JOI(self):
        """ Sent to all participants when a new client joins

        JOI bob@passport.com Bob
        
        """
        
        self.add_unique_to_list(self.words[1],self.participants)
        self.insert_session_data(sender=self.words[1],recipient="%s (Target)" % self.client_id,type="USER JOINING_SESSION WITH TARGET")

        self.insert_user_data(self.words[1],'user_msn_passport',self.words[1])
        self.insert_user_data(self.words[1],'url_enc_display_name',urllib.unquote(self.words[2]))
        
	self.state = "JOI"

    def CVR(self):
        """Version information, including OS information

        From the client:
        CVR <transaction id> <locale ID in hex> <os type> <os ver> <arch> <client name> <client version> <always MSMSGS> <msn passport>

        >>> CVR 2 0x0409 win 4.10 i386 MSNMSGR 5.0.0544 MSMSGS example@passport.com\r\n

        From the server:

        CVR <transaction id> <recommended verion> <same again> <minimum version required> <download url> <more info url>
        
        <<< CVR 2 6.0.0602 6.0.0602 1.0.0000 http://download.microsoft.com/download/8/a/4/8a42bcae-f533-4468-b871-d2bc8dd32e9e/SETUP9x.EXE http://messenger.msn.com\r\n

        """
        

        # I think we only care about the client, not the server, hence:
        if (self.words[2].find("x")==1):
            self.client_id=self.words[9]
            #print "CVR  setting self.client_id to %s for inode %s" %(self.client_id,self.fd.inode)
            try:
                self.insert_user_data("%s (Target)" % self.client_id,'locale',self.words[2],tr_id=self.words[1])
                self.insert_user_data("%s (Target)" % self.client_id,'os'," ".join(self.words[3:6]),tr_id=self.words[1])
                self.insert_user_data("%s (Target)" % self.client_id,'client'," ".join(self.words[6:8]),tr_id=self.words[1])
                self.insert_user_data("%s (Target)" % self.client_id,'target_msn_passport',self.words[9],tr_id=self.words[1])
                
                self.state = "CVR"

            except Exception,e:
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG,  "CVR not decoded correctly: %s. Exception: %s" % (self.cmdline.strip(),e))
                pass

    def PRP(self):
        """Target's Phone numbers.

        The only time you can receive the phone numbers that you have
        set for yourself is during a SYN. Personal phone numbers are
        sent immediately after BLP.

        e.g.
        PRP PHH 555%20555-0690

        """
        

        #pyflaglog.log(pyflaglog.VERBOSE_DEBUG,  "PRP: %s" % self.cmdline)
        
        self.store_phone_nums(nick="%s (Target)" % self.client_id,type=self.words[1],number=self.words[2])
            
        self.state = "PRP"    

    def BPR(self):
        """Phone numbers for other users.  Same format is PRP.  Only
        way to know who owns the number is to look at the previous
        command, which should have been a LST.
        
        e.g.
        BPR PHH 555%20555-0690

        """
        

        #pyflaglog.log(pyflaglog.VERBOSE_DEBUG,  "BPR: %s" % self.cmdline)

        try:
            user=self.state.split(":")[1]
        except:
            user='Unknown'
        self.store_phone_nums(nick=user,type=self.words[1],number=self.words[2])
                    
        self.state = "PRP"    

    def LSG(self):
        """Contact groups.  Sent by the server when target logs on.

        TODO: Modify to handle GUIDs used in current version of protocol

        LSG 0 Other%20Contacts 0\r\n
        LSG 1 Coworkers 0\r\n
        LSG 2 Friends 0\r\n
        LSG 3 Family 0\r\n

        Shouldn't see more than one set of LSG messages per session
        i.e. only one 'LSG 0 blah' message.  If we do get more than
        one the new LSG is ignored to avoid trampling any data that
        may already be in the array.
        """
        

        #pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "LSG: %s" % self.cmdline)
        try:
            if self.contact_list_groups[self.words[1]]:
                #We already have LSG data for this list number.  Do nothing
                pass
        except KeyError:
            #Create a new entry for this group number and initialise with name of group
            self.contact_list_groups[self.words[1]]=newlist=[urllib.unquote(self.words[2])]
            
        self.state = "LSG"

    def LST(self):
        """Contact list members.  Sent by the server when target logs on.

        TODO: Modify to handle GUIDs used in current version of protocol

        LST principal1@passport.com principal1 4\r\n
        LST principal2@passport.com principal2 10\r\n
        LST principal3@passport.com principal3 11 1,3\r\n
        LST principal4@passport.com principal4 11 0\r\n

        # The first parameter is the account name.
        # The second parameter is the nickname. (For more information on nicknames, see the Names page)
        # The third parameter is a number representing the lists the person is in (discussed below)
        # If the person is in your FL, the fourth parameter is a comma-separated list of group numbers they belong to

        Each list has a numerical value:

        A principal's list number represents the sum of the lists the
        principal is in. For example, someone on your forward and
        allow lists but not your block or reverse lists would have a
        list number of 3.

        """
        
        
        #pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "LST: %s" % self.cmdline)

        self.list_table={}
        self.list_table['forward_list']=1
        self.list_table['allow_list']=2
        self.list_table['block_list']=4
        self.list_table['reverse_list']=8
        self.list_table['pending_list']=16

        for (listtype,listvalue) in self.list_table.items():
            #Do a bitwise and to figure out which lists this person is in.
            if ((listvalue & int(self.words[3]))>0):
                #add the nick to the relevant list
                #pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Inserting %s into list %s" % (self.words[1],listtype))
                self.add_unique_to_list(data=self.words[1],list=self.list_lookup[listtype])

        self.insert_user_data(nick=self.words[1],data_type='url_enc_display_name',data=urllib.unquote(self.words[2]))
        
        try:
            for group in self.words[4].split(","):
                self.add_unique_to_list(data=self.words[1],list=self.contact_list_groups[group])
        except IndexError:
            #This LST entry did not have a 4th parameter
            pass
        except KeyError,e:
            pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "No LSG entry for group specified in LST: %s. Exception: %s" % (self.cmdline.strip(),e))
            
        self.state = "LST:%s" % self.words[1]

    #Ignore these commands
    def ACK (self):
        pass
    def PNG (self):
        #Client ping
        pass
    def QNG (self):
        #Server ping reply
        pass
    def CHL(self):
        """
        Ignore
        
        CHL

        Server ping. Returns
        
        CHL 0 challengestring
        
        * 0 : unknown
        * challengestring : A string required for the response 
        """
        pass

    def QRY(self):
        """
        QRY
        
        Response to Server ping.
        
        QRY is a payload command.
        
        QRY trid idstring payload_length
        md5digest
        
        * trid : Transaction ID
        * idstring : See Notification:Challenges#Client_identification_information
        * payload_length : Size of the payload, always 32 because MD5 hashes are constant in length
        * md5digest : See Notification:Challenges#Client_identification_information
        
        """
        pass
    
    def VER (self):
        #More useful info in CVR
        pass
    def SYN(self):
        """
        Ignore?  Maybe TODO
        
        SYN

        Command to synchronize the client's buddy lists. The client should send this immediately after signon as the server wont send certain commands until this is done.
        
        SYN trid synchversion
        
        * trid : Transaction ID
        * synchversion : The last cached synchronization version number, the client should send 0 if none exists 
        
        A synchronization version that matches the server's Returns
        
        SYN trid synchversion
        
        * trid : Transaction ID
        * synchversion : The profile's synchronization version number 
        
        A synchronization version that doesn't match the server's Returns
        
        SYN trid synchversion numberbuddies numbergroups
        
        * trid : Transaction ID
        * synchversion : The profile's synchronization version number
        * numberbuddies : The number of people on the client's list
        * numbergroups : The number of groups on the client's list
        """
        
        pass
    
    def GTC (self):
        """
        Ignore?  Maybe TODO
    
        GTC
        
        Sent following a unmatched SYN's response. A value of 'A'
        indicates that whenever someone is 'added' to the Reverse
        List, the client should notify the user that someone has added
        him/her and ask the user about what to do. A value of 'N'
        means that inconsistancies in the contact list should be
        largely ignored..
        
        GTC gtcSetting
        
        * gtcSetting : A string value of either 'A' or 'N'
        """
        pass
    
    def BLP (self):
        """
        Ignore?  Maybe TODO
        
        BLP

        Sent following a unmatched SYN's response. A value of 'AL'
        indicates that users that are neither on the client's Allow
        List or Buddy List will be allowed to see the client's online
        status and open a switchboard session with the client. A value
        of 'BL' indicates that these users will see the client as
        offline and will not be allowed to open a switchboard session.
        
        BLP blpSetting
        
        * blpSetting : A string value of either 'AL' or 'BL'
        
        """
        pass

    def CHG(self):
        """
        CHG

        Target Changing status.  Everyone in the target's allow list will see this change in status.

        CHG trid statuscode clientid

            * trid : Transaction ID
            * statuscode : Three letter, case sensitive, code for the status you are changing to (NLN, BSY, IDL, BRB, AWY, PHN, LUN)
            * clientid : Your Client ID number 

        Returns The server will echo the command back if successful (ignored).

        CHG trid statuscode clientid

        """
        
        if self.state!="CHG":
            #ie. we didn't just process one.  This avoids storing the server's identical response.
            self.insert_session_data(sender="%s (Target)" % self.client_id,recipient="SWITCHBOARD SERVER",type="TARGET CHANGED ONLINE STATUS TO:%s" % self.words[2],tr_id=self.words[1],sessionid=-99)
            self.state = "CHG"

    def ILN(self):
        """

        ILN = Initial presence notification.  TO target FROM all on forward list.
        
        ILN trid statuscode account_name display_name clientid

        * trid : Transaction ID
        * statuscode : Principal's three letter status code (NLN, BSY, IDL, BRB, AWY, PHN, LUN)
        * account_name : Principal's Passport address
        * display_name : Principal's URL encoded display name
        * clientid : Principal's Client ID number 

        """
        
        self.insert_session_data(sender=self.words[3],recipient="%s (Target)" % self.client_id,type="USER INITIAL STATUS:%s" % self.words[2],tr_id=self.words[1],sessionid=-99)
        self.insert_user_data(nick=self.words[3],data_type='url_enc_display_name',data=urllib.unquote(self.words[4]),tr_id=self.words[1],sessionid=-99)
        self.add_unique_to_list(self.words[3],self.forward_list)
        self.state = "ILN"

    def FLN(self):
        """

        FLN - user on forward list signed off.

        Principal signed off Returns
        
        FLN account_name
        
        * account_name : Principal's Passport address 

        """
        
        self.insert_session_data(sender=self.words[1],recipient="%s (Target)" % self.client_id,type="USER LOGGED OFF",sessionid=-99)
        self.add_unique_to_list(self.words[1],self.forward_list)
        self.state = "FLN"

    def NLN(self):
        """
        NLN = Change of presence.

        Presence info received by target for everyone on his/her forward list.
        
        NLN statuscode account_name display_name clientid
        
        * statuscode : Principal's three letter status code (NLN, BSY, IDL, BRB, AWY, PHN, LUN)
        * account_name : Principal's Passport address
        * display_name : Principal's URL encoded display name
        * clientid : Principal's Client ID number

        NLN = Available
        BSY = Busy
        IDL = Idle
        BRB = Be right back
        AWY = Away
        PHN = On Phone
        LUN = Out to lunch
        
        """
        
        
        self.insert_session_data(sender=self.words[2],recipient="%s (Target)" % self.client_id,type="USER CHANGED ONLINE STATUS TO:%s" % self.words[1],sessionid=-99)
        self.add_unique_to_list(self.words[2],self.forward_list)
        self.insert_user_data(self.words[2],'url_enc_display_name',urllib.unquote(self.words[3]),sessionid=-99)
        
        self.state = "NLN"

    def REA(self):
        """
        REA
        
        The REA command is used to change your displayed name to something else.
        
        REA trid your_email newname\r\n
        
        * trid : Transaction ID
        * your_email : The email you use to sign on to MSN.
        * newname : The name that you now wish to use in a URL Encoded format. 
        
        If the rename has been successful, the server will respond with the following.
        
        REA trid number your_email newname\r\n
        
        * trid : Transaction ID
        * number : Purpose currently unknown.
        * your_email : The email you use to sign on to MSN.
        * newname : The name that you wished to use in plain text.
        
        
        """
        
        try:
            if int(self.words[2]):
                #This message is of type 2 above
                #Try and record the new display name in case we missed the original REA
                self.insert_user_data(nick=self.words[3],data_type='url_enc_display_name',data=urllib.unquote(self.words[4]))
                
        except ValueError:
            
            #This will not be recorded if a display name has already been recorded for this user in this session.
            self.insert_user_data(nick=self.words[2],data_type='url_enc_display_name',data=urllib.unquote(self.words[3]))
            
            #Store the change as session data, so we know it happenedd
            self.insert_session_data(sender=self.words[2],recipient="%s (Target)" % self.client_id,type="USER CHANGED DISPLAY NAME",data=urllib.unquote(self.words[3]))
        
        
    def ADD(self):
        """Adding people to your lists.

        Forward List (FL)
        
        The forward list, abbreviated as FL, is the list of principals
        whose presence you are subscribed to. You can expect to be
        notified about their on-line state, phone numbers, etc. This
        is what a layman would call their contact list.

        Everyone in your forward list belongs to one or more groups,
        identified by their group number. By default, they belong to
        group 0.

        Reverse List (RL)
        
        The reverse list, abbreviated as RL, is the list of principals
        that have you on their forward list. You cannot make
        modifications to it. If you attempt to add or remove people
        from this list, you will be immediately disconnected from the
        NS with no error message.  [edit]

        Allow List (AL)
        
        The allow list, abbreviated as AL, is the list of principals
        that you allow to see your online presence - as opposed to
        your reverse list, which is the list of people who request to
        see your online presence. If someone removes you from his or
        her contact list, he or she is automatically removed from your
        RL but not your AL. He or she no longer receives online
        presence from you, but if he or she adds you again, your
        client can act in the knowledge that you previously allowed
        him or her to see your presence.

        Block List (BL)

        The block list, abbreviated as BL, is the list
        of people that are blocked from seeing your online
        presence. They will never receive your status, and when they
        try to invite you to a switchboard session, they will be
        notified that you are offline. No-one can be on the AL and the
        BL at the same time, and if you try to add someone to both
        lists, you will receive error 219.

        The first parameter is the list you want to add the
        principal to.
        
        The second parameter is the principal's account name.

        The third parameter is a nickname you assign to the
        principal. The official client always uses the principal's
        account name as the nickname, and that is why when you add a
        principal, his or her name always shows as his or her
        account name until he or she logs on and you receive an
        updated display name.

        If you are adding a principal to your FL, there may be a
        fourth parameter specifying the group ID that you are adding
        the principal to. If you do not specify a group ID, zero is
        implied. You may add the same principal to your FL later
        specifying another group to have the principal in multiple
        groups.

        e.g.
        ADD 20 AL example@passport.com example@passport.com

        Note: interesting that you can have someone on your fl
        (ie. you receive notifications of their presence) and also on
        your block list (so they don't receive notifications about you
        and can't talk to you)

        """
        
        
        pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"ADD: %s" % self.cmdline)
        self.insert_user_data("%s (Target)" % self.client_id,'added_user_to_list',"list:%s,user:%s,nick:%s" % (self.words[2],self.words[3],self.words[4]),sessionid=-99)
        self.insert_session_data(sender="%s (Target)" % self.client_id,recipient="SWITCHBOARD SERVER",type="ADDED USER TO LIST",sessionid=-99)
        self.state = "ADD"
                         
    def plain_handler(self,content_type,sender,is_server):
        """ A handler for content type text/plain """

        self.insert_session_data(sender,recipient=self.recipient,type='MESSAGE',data=self.get_data())

    def control_msg_handler(self,content_type,sender,is_server):
        """ A handler for content type text/x-msmsgscontrol

        If this is the client sending a message out:

        This gives us another chance to set self.client_id
        (i.e. target username) for the stream, using the Typing User
        messages.  This means that if we miss the ANS, we can still
        identify who 'Target' is.

        If this is the server sending a message in:

        This gives us another chance to find out the participating
        users in the session.  This means if we miss one or all of the
        IRO statements, we still know who is in the session
        
        """
        if is_server:
            #Typing user message from server - way to identify participants!
            self.add_unique_to_list(self.headers['typinguser'],self.participants)
        else:
            self.client_id = self.headers['typinguser']
            #print "Typing user setting self.client_id to %s for inode %s" %(self.client_id,self.fd.inode)

    def profile_msg_handler(self,content_type,sender,is_server):
        """ A handler for content type text/x-msmsgsprofile

        These messages can potentially contain great info (providing
        the user has set the settings in the client)

        The profile messages look like this:
        
        MSG Hotmail Hotmail 999
        MIME-Version: 1.0
        Content-Type: text/x-msmsgsprofile; charset=UTF-8
        LoginTime: 1130000813
        EmailEnabled: 1
        MemberIdHigh: 98989
        MemberIdLow: 9898989898
        lang_preference: 1033
        preferredEmail:
        country: AU
        PostalCode:
        Gender:
        Kid: 0
        Age:
        BDayPre:
        Birthday:
        Wallet:
        Flags: 1073759303
        sid: 500
        kv: 7
        MSPAuth: 78vuxsrLuGBgVaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatdYDSaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$$
        ClientIP: 60.0.0.1
        ClientPort: 39620
        ABCHMigrated: 1
        
        """
        
        self.insert_user_data(nick="%s (Target)" % self.client_id,data_type="login_time",data=self.headers['logintime'])
        self.insert_user_data(nick="%s (Target)" % self.client_id,data_type="lang_pref",data=self.headers['lang_preference'])
        self.insert_user_data(nick="%s (Target)" % self.client_id,data_type="email_pref",data=self.headers['preferredemail'])
        self.insert_user_data(nick="%s (Target)" % self.client_id,data_type="country_code",data=self.headers['country'])
        self.insert_user_data(nick="%s (Target)" % self.client_id,data_type="post_code",data=self.headers['postalcode'])
        self.insert_user_data(nick="%s (Target)" % self.client_id,data_type="gender",data=self.headers['gender'])
        self.insert_user_data(nick="%s (Target)" % self.client_id,data_type="kid",data=self.headers['kid'])
        self.insert_user_data(nick="%s (Target)" % self.client_id,data_type="age",data=self.headers['age'])
        self.insert_user_data(nick="%s (Target)" % self.client_id,data_type="birthday",data=self.headers['birthday'])
        self.insert_user_data(nick="%s (Target)" % self.client_id,data_type="client_ip",data=self.headers['clientip'])

    def ignore_type(self,content_type,sender,is_server):
        #Nonexistent callback for ignored types.
        pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Ignoring message:%s.  Headers:%s. Data:%s" % (self.cmdline.strip(),self.headers,self.data.strip()))

    def p2p_handler(self,content_type,sender,is_server):
        """ Handle a p2p transfer """

        #print "content_type%s,sender%s,is_server%s"%(content_type,sender,is_server)
        def strip_username(p2pusername):
            # TO and FROM are of format <msnmsgr:name@hotmail.com> so strip the extra stuff out
            return p2pusername.replace('<msnmsgr:','').strip('>')
            
            
        data = self.get_data()
        ## Now we break out the header:
        ( channel_sid, id, offset, total_data_size, message_size ) = struct.unpack(
            "IIQQI",data[:4+4+8+8+4])

        ## MSN header is 48 bytes long
        data = data[48:48+message_size]
        
        ## When channel session id is 0 we are negotiating a transfer
        ## channel
        if channel_sid==0:
            fd = cStringIO.StringIO(data)
            request_type=fd.readline()
            if request_type.startswith("INVITE"):
                ## We parse out the invite headers here:
                headers = {}
                while 1:
                    line = fd.readline()
                    if not line: break
                    tmp = line.find(":")
                    key,value = line[:tmp],line[tmp+1:]
                    headers[key.lower()]=value.strip()

                context = safe_base64_decode(headers['context'])

                self.dbh.insert("msn_p2p",
                                session_id = self.session_id,
                                channel_id = headers['sessionid'],
                                to_user= headers['to'],
                                from_user= headers['from'],
                                context=context,
                                )
                
                ## Add a VFS entry for this file:
                new_inode = "CMSN%s-%s" % (headers['sessionid'],
                                           self.session_id)
                
                self.insert_session_data(sender=strip_username(headers['from']),recipient=strip_username(headers['to']),type="P2P FILE TRANSFER",p2pfile="%s|%s" % (self.fd.inode, new_inode))
                
                try:
                ## Parse the context line:
                    parser = ContextParser()
                    parser.feed(context)
                    filename = parser.context_meta_data['location']
                    if len(filename)<1: raise IOError
                except:
                    ## If the context line is not a valid xml line, we
                    ## just make a filename off its printables.
                    filename = ''.join([ a for a in context if a in allowed_file_chars ])

                try:
                    size=parser.context_meta_data['size']
                except: size = len(data)

                try:
                    mtime = self.fd.ts_sec
                except:
                    mtime = 0
                
                ## The filename and size is given in the context
                self.ddfs.VFSCreate(self.fd.inode, new_inode, "MSN/%s" %
                                    (filename) , mtime=mtime,
                                    size=size)

                self.inodes.append(new_inode)
                
        ## We have a real channel id so this is an actual file:
        else:
            filename = get_temp_path(self.dbh.case,"%s|CMSN%s-%s" % (self.fd.inode, channel_sid,self.session_id))
            fd=os.open(filename,os.O_RDWR | os.O_CREAT)
            os.lseek(fd,offset,0)
            bytes = os.write(fd,data)
            if bytes <message_size:
                pyflaglog.log(pyflaglog.WARNINGS,  "Unable to write as much data as needed into MSN p2p file. Needed %s, write %d." %(message_size,bytes))
            os.close(fd)
            
    ct_dispatcher = {
        #Ignore list:
        #text/x-msmsgscontrol are 'typing user' messages.
        
        'text/plain': plain_handler,
        'application/x-msnmsgrp2p': p2p_handler,
        'text/x-msmsgscontrol': control_msg_handler,
        'text/x-msmsgsprofile': profile_msg_handler
        }
            
    def MSG(self):
        """ Sends message to members of the current session

        There are two types of messages that may be sent:
        1) A message from the client to the message server. This does not contain the nick of the client, but does contain a transaction ID.  This message is sent to all users in the current session.
        2) A message from the Switchboard server to the client contains the nick of the sender.

        These two commands are totally different.

        1.

        MSG 1532 U 92
        MIME-Version: 1.0
        Content-Type: text/x-msmsgscontrol
        TypingUser: user@hotmail.com

        Format is: MSG <Transaction ID> <Type of ACK required> <length of message in bytes>

        Transaction ID is used to correlate server responses to client requests.

        2.

        MSG user2@hotmail.com I%20am%20so%20great 102
        MIME-Version: 1.0
        Content-Type: text/x-msmsgscontrol
        TypingUser: user2@hotmail.com

        Format is: MSG <Nick> <URL encoded displayname> <length of message in bytes>
        
        """
        ## Read the data for this MSG:
        if self.parse_mime():
        
            try:
                ## If the second word is a transaction id (int) its a message from client to server.  ie. FROM target to all users in session.
                tid = int(self.words[1])
                sender = "%s (Target)" % self.client_id
                #pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "participants:%s" % (",".join(self.participants)))
                self.recipient = ",".join(self.participants)
                server = False
            except ValueError:
                # Message TO target
                tid = 0
                sender = self.words[1]
                self.insert_user_data(sender,'url_enc_display_name',urllib.unquote(self.words[2]))
                server = True
                self.recipient = "%s (Target)" % self.client_id
            try:
                #Cater for "text/x-msmsgsprofile; charset=UTF-8" by stripping charset
                content_type = self.headers['content-type'].split(";")[0]

            except:
                content_type = "unknown/unknown"
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Couldn't figure out MIME type for this message: %s" % self.cmdline)

            ## Now dispatch the relevant handler according to the content
            ## type:
            try:
                ct = content_type.split(';')[0]
                self.ct_dispatcher[ct](self,content_type,sender,server)
            except KeyError,e:
                pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Unable to handle content-type %s(%s) - ignoring message %s " % (content_type,e,tid))
        self.state = "MSG"
	
from HTMLParser import HTMLParser

class ContextParser(HTMLParser):
    """ This is a simple parser to parse the MSN Context line """
    def handle_starttag(self, tag, attrs):
        self.context_meta_data = query_type(attrs)

class MSNScanner(StreamScannerFactory):
    """ Collect information about MSN Instant messanger traffic """
    default = True

    def __init__(self,fsfd):
        StreamScannerFactory.__init__(self,fsfd)

        #Should hit the reverse stream within 30 streams (usually it
        #is the very next one)
        
        self.processed=RingBuffer(30)

    def prepare(self):
        dbh=DB.DBO(self.case)
        dbh.execute(
            """ CREATE TABLE if not exists `msn_session` (
            `inode` VARCHAR(50) NOT NULL,
            `packet_id` INT NOT NULL,
            `session_id` BIGINT,
            `sender` VARCHAR(250),
            `recipient` VARCHAR( 250 ),
            `type` VARCHAR(50),
            `data` TEXT NULL,
            `p2p_file` VARCHAR( 250 ),
            `transaction_id`  INT
            )""")
        dbh.execute(
            """ CREATE TABLE if not exists `msn_p2p` (
            `inode` VARCHAR(250),
            `session_id` INT,
            `channel_id` INT,
            `to_user` VARCHAR(250),
            `from_user` VARCHAR(250),
            `context` TEXT
            )""")
        dbh.execute(
            """ CREATE TABLE if not exists `msn_users` (
            `inode` VARCHAR(50) NOT NULL,
            `packet_id`  INT NOT NULL,
            `session_id` INT NOT NULL,
            `transaction_id`  INT,
            `nick` VARCHAR(50) NOT NULL,
            `user_data_type` enum('target_msn_passport',
                                  'user_msn_passport',
                                  'display_name',
                                  'url_enc_display_name',
                                  'locale',
                                  'os',
                                  'client',
                                  'contact_list_groups',
                                  'home_phone',
                                  'work_phone',
                                  'mobile_phone',
                                  'msn_mobile_auth',
                                  'msn_mobile_device',
                                  'forward_list',
                                  'allow_list',
                                  'block_list',
                                  'reverse_list',
                                  'pending_list',
                                  'added_user_to_list',
                                  'login_time',
                                  'lang_pref',
                                  'email_pref',
                                  'country_code',
                                  'post_code',
                                  'gender',
                                  'kid',
                                  'age',
                                  'birthday',
                                  'client_ip',
                                  'personal_message'
                                  ) NOT NULL ,
            `user_data` TEXT NOT NULL,
            PRIMARY KEY (`inode`,`session_id`,`user_data_type`,`nick`)
            )""")
        self.msn_connections = {}

    def process_stream(self, stream, factories):
        ports = dissect.fix_ports("MSN")
        
        if stream.src_port in ports or stream.dest_port in ports:
            #Keep track of the streams we have combined so we don't process reverse again
            #self.processed is a ring buffer so it doesn't get too big
            if not self.processed.has_key(stream.con_id):
                #Haven't processed this one.
                #print "Processed:%s" % self.processed.data
                #This returns the forward and reverse stream associated with the MSN port (uses port numbers in .pyflagrc).
                forward_stream, reverse_stream = self.stream_to_server(stream, "MSN")
                
                #We need both streams otherwise this won't work
                if not reverse_stream or not forward_stream: return

                pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Opening Combined Stream S%s/%s for MSN" % (forward_stream, reverse_stream))

                #Create the combined inode
                combined_inode = "I%s|S%s/%s" % (stream.fd.name, forward_stream, reverse_stream)

                # Open the combined stream.
                fd = self.fsfd.open(inode=combined_inode)
                dbh=DB.DBO(stream.case)
                m=message(dbh, fd, self.fsfd)
                while 1:
                    try:
                        result=m.parse()
                        #pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Client:%s,Stream:%s,Inode:%s" % (m.client_id, m.session_id,combined_inode))
                    except IOError:

                        break

                #Scan p2p files we found
                for inode in m.inodes:
                    self.scan_as_file("%s|%s" % (combined_inode, inode), factories)

                #### Post Processing ####

                #Store each of fl,bl,al etc.
                for (thislistname,thislist) in m.list_lookup.items():
                    m.store_list(list=thislist,listname=thislistname)

                #Flatten contact list groups and store as one entry
                finallist=[]
                for (thislistname,thislist) in m.contact_list_groups.items():
                    finallist.append(thislistname+":"+",".join(thislist))
                m.store_list(list=finallist,listname='contact_list_groups')
                    
                #Fix up all the session IDs (=-1) that were stored before we figured out the session ID.
                if m.session_id==-1:
                    pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Couldn't figure out the MSN session ID for stream S%s/%s" % (forward_stream, reverse_stream))
                else:
                    dbh.execute("update msn_session set session_id=%r where session_id=-1 and inode=%r",(m.session_id,combined_inode))
                    try:
                        dbh.execute("update msn_users set session_id=%r where session_id=-1 and inode=%r",(m.session_id,combined_inode))
                    except Exception:
                        #We already have this identical row with a real session ID - will delete it below
                        pass
                    #We can delete everything with session id =-1 because we know we have an actual session id for this stream
                    dbh.execute("delete from msn_users where session_id=-1 and inode=%r",combined_inode)

                #Similarly go back and fix up all the Unknown (Target) entries with the actual target name
                if m.client_id=='Unknown':
                    pyflaglog.log(pyflaglog.VERBOSE_DEBUG,"Couldn't figure out target identity for stream S%s/%s" % (forward_stream, reverse_stream))
                else:
                    dbh.execute("update msn_session set recipient=%r where recipient='Unknown (Target)' and inode=%r",(m.client_id,combined_inode))
                    dbh.execute("update msn_session set sender=%r where sender='Unknown (Target)' and inode=%r",(m.client_id,combined_inode))

                self.processed.append(forward_stream)
                self.processed.append(reverse_stream)
                #pyflaglog.log(pyflaglog.VERBOSE_DEBUG, "Appending ids: %s, %s" % (forward_stream,reverse_stream))
                
class MSNFile(File):
    """ VFS driver for reading the cached MSN files """
    specifier = 'C'
        
class BrowseMSNSessions(Reports.report):
    """ This allows MSN sessions to be browsed.

    Note that to the left of each column there is an icon with an
    arrow pointing downwards. Clicking on this icon shows the full msn
    messages for all sessions from 60 seconds prior to this message.

    This is useful if you have isolated a specific message by
    searching for it, but want to see what messages were sent around
    the same time to get some context.
    """
    name = "Browse MSN Sessions"
    family = "Network Forensics"
    def form(self,query,result):
        try:
            result.case_selector()
            PCAPFS.draw_only_PCAPFS(query,result)
        except KeyError:
            pass

    def display(self,query,result):
        """ This callback renders an icon which when clicked shows the
        full msn messages for all sessions from 60 seconds prior to
        this message."""
        
        result.heading("MSN Chat sessions")

        def draw_prox_cb(value):
            tmp = result.__class__(result)
            tmp.link('Go To Approximate Time',
              target=query_type((),
                family=query['family'], report=query['report'],
                where_Prox = ">%s" % (int(value)-60),
                case = query['case'],
              ),
              icon = "stock_down-with-subpoints.png",
	                     )

            return tmp

        result.table(
            elements = [ TimestampType('Prox','pcap.ts_sec',
                                    callback = draw_prox_cb),
                         TimestampType('Timestamp','pcap.ts_sec'),
                         InodeType("Stream","inode",
                                   link = query_type(family="Disk Forensics",
                                                     case=query['case'],
                                                     report='View File Contents',
                                                     __target__='inode',
                                                     mode="Combined streams")),
                         IntegerType("Packet","packet_id",
                                    link = query_type(family="Network Forensics",
                                                      case=query['case'],
                                                      report='View Packet',
                                                      __target__='id')),
                         IntegerType("Session ID","session_id",
                                    link = query_type(family="Network Forensics",
                                                      case=query['case'],
                                                      report='BrowseMSNSessions', 
                                                      __target__='filter',
                                                      filter='"Session ID" = %s')),
                         StringType("Type","type"),
                         StringType("Sender","sender",
                                    link = query_type(family="Network Forensics",
                                                      case=query['case'],
                                                      report='BrowseMSNUsers',
                                                      filter='Nick = "%s"',
                                                      __target__='filter')),
                         StringType("Recipient","recipient",
                                    link = query_type(family="Network Forensics",
                                                      case=query['case'],
                                                      report='BrowseMSNUsers',
                                                      filter='Nick = "%s"',
                                                      __target__='filter')),

                         StringType("Data","data"),
                         IntegerType("Transaction ID","transaction_id"),
                         InodeType("P2P File","p2p_file", case=query['case']),
                         ],
            
            #TODO find a nice way to separate date and time (for exporting csv separate), but not have it as the default...
            #date: 'from_unixtime(pcap.ts_sec,"%Y-%m-%d")'
            #time: 'concat(from_unixtime(pcap.ts_sec,"%H:%i:%s"),".",pcap.ts_usec)'

            #We are displaying single inodes, not combined streams to make the linking work            
#            columns = ['pcap.ts_sec', 'concat(from_unixtime(pcap.ts_sec),".",pcap.ts_usec)', 'left(inode,instr(inode,"/")-1)', 'cast(packet_id as char)', 'session_id','type','sender','recipient','data','transaction_id','p2p_file'],
#            names = ['Prox','Timestamp','Stream', 'Packet', 'Session ID', 'Type','Sender','Recipient','Data','Transaction ID','P2P File'],
            table = "msn_session join pcap on packet_id=id",
            case = query['case'],
            hide_columns = ['Date']
            )

class BrowseMSNUsers(BrowseMSNSessions):
    """ This report shows the data known about MSN participants (users).
    """
    name = "Browse MSN Users"
    family = "Network Forensics"
    
    def display(self,query,result):
        result.heading("MSN User Information Captured")
        
        result.table(
            elements = [ InodeType("Stream","inode",
                                   link = query_type(family="Disk Forensics",
                                                     case=query['case'],
                                                     report='View File Contents',
                                                     __target__='inode',
                                                     mode="Combined streams")),
                         IntegerType("Session ID","session_id",
                                    link = query_type(family="Network Forensics",
                                                      case=query['case'],
                                                      report='BrowseMSNSessions', 
                                                      __target__='filter',
                                                      filter='"Session ID" = %s')),
                         TimestampType('Timestamp','pcap.ts_sec'),
                         StringType('Data Type', 'user_data_type'),
                         StringType('Nick', 'nick',
                                    link = query_type(family="Network Forensics",
                                                      case=query['case'],
                                                      report='BrowseMSNUsers',
                                                      filter='Nick = "%s"',
                                                      __target__='filter')),
                         IntegerType("Packet","packet_id",
                                    link = query_type(family="Network Forensics",
                                                      case=query['case'],
                                                      report='View Packet',
                                                      __target__='id')),
                         IntegerType("Transaction ID","transaction_id"),
                         ],
            table = "msn_users join pcap on packet_id=id",
            case = query['case'],
            )

if __name__ == "__main__":
    fd = open("/tmp/case_demo/S93-94")
    data = fd.read()
    parse_msg(data)
