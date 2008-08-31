#!/usr/bin/env python
#
# This library is free software, distributed under the terms of
# the GNU Lesser General Public License Version 2.
# See the COPYING file included in this archive
#
# The docstrings in this module contain epytext markup; API documentation
# may be created by processing this file with epydoc: http://epydoc.sf.net

""" MMS Data Unit structure encoding and decoding classes """

import os, array
import wsp_pdu
import message
from iterator import PreviewIterator

class MMSEncodingAssignments:
    fieldNames = {0x01 : ('Bcc', 'EncodedStringValue'),
                  0x02 : ('Cc', 'EncodedStringValue'),
                  0x03 : ('Content-Location', 'UriValue'),
                  0x04 : ('Content-Type','ContentTypeValue'),
                  0x05 : ('Date', 'DateValue'),
                  0x06 : ('Delivery-Report', 'BooleanValue'),
                  0x07 : ('Delivery-Time', None),
                  0x08 : ('Expiry', 'ExpiryValue'),
                  0x09 : ('From', 'FromValue'),
                  0x0a : ('Message-Class', 'MessageClassValue'),
                  0x0b : ('Message-ID', 'TextString'),
                  0x0c : ('Message-Type', 'MessageTypeValue'),
                  0x0d : ('MMS-Version', 'VersionValue'),
                  0x0e : ('Message-Size', 'LongInteger'),
                  0x0f : ('Priority', 'PriorityValue'),
                  0x10 : ('Read-Reply', 'BooleanValue'),
                  0x11 : ('Report-Allowed', 'BooleanValue'),
                  0x12 : ('Response-Status', 'ResponseStatusValue'),
                  0x13 : ('Response-Text', 'EncodedStringValue'),
                  0x14 : ('Sender-Visibility', 'SenderVisibilityValue'),
                  0x15 : ('Status', 'StatusValue'),
                  0x16 : ('Subject', 'EncodedStringValue'),
                  0x17 : ('To', 'EncodedStringValue'),
                  0x18 : ('Transaction-Id', 'TextString')}


class MMSDecoder(wsp_pdu.Decoder):
    """ A decoder for MMS messages """
    def __init__(self, filename=None):
        """ @param filename: If specified, decode the content of the MMS
                             message file with this name
            @type filename: str
        """
        self._mmsData = array.array('B')
        self._mmsMessage = message.MMSMessage()
        self._parts = []

    def decodeFile(self, filename):
        """ Load the data contained in the specified file, and decode it.
        
        @param filename: The name of the MMS message file to open
        @type filename: str
        
        @raises OSError: The filename is invalid
        
        @return: The decoded MMS data
        @rtype: MMSMessage
        """
        nBytes = os.stat(filename)[6]
        data = array.array('B')
        f = open(filename, 'rb')
        data.fromfile(f, nBytes)
        f.close()
        return self.decodeData(data)
        
    def decodeData(self, data):
        """ Decode the specified MMS message data
        
        @param data: The MMS message data to decode
        @type filename: array.array('B')
        
        @return: The decoded MMS data
        @rtype: MMSMessage
        """
        self._mmsMessage = message.MMSMessage()
        self._mmsData = data
        bodyIter = self.decodeMessageHeader()
        self.decodeMessageBody(bodyIter)
        return self._mmsMessage
    
    def decodeMessageHeader(self):
        """ Decodes the (full) MMS header data
        
        @note: This B{must} be called before C{_decodeBody()}, as it sets
        certain internal variables relating to data lengths, etc.
        """
        dataIter = PreviewIterator(self._mmsData)
        
        # First 3  headers (in order
        ############################
        # - X-Mms-Message-Type
        # - X-Mms-Transaction-ID
        # - X-Mms-Version
        # TODO: reimplement strictness - currently we allow these 3 headers 
        #       to be mixed with any of the other headers (this allows the
        #       decoding of "broken" MMSs, but is technically incorrect
           
        # Misc headers
        ##############
        # The next few headers will not be in a specific order, except for
        # "Content-Type", which should be the last header
        # According to [4], MMS header field names will be short integers
        contentTypeFound = False
        while contentTypeFound == False:
            header, value = self.decodeHeader(dataIter)
            if header == MMSEncodingAssignments.fieldNames[0x04][0]:
                contentTypeFound = True
            else:
                self._mmsMessage.headers[header] = value
                #print '%s: %s' % (header, str(value))
        
        cType = value[0]
        #print '%s: %s' % (header, cType)
        params = value[1]
        #for parameter in params:
        #    print '    %s: %s' % (parameter, str(params[parameter]))

        self._mmsMessage.headers[header] = (cType, params)
        return dataIter
    
            
    def decodeMessageBody(self, dataIter):
        """ Decodes the MMS message body
        
        @param dataIter: an iterator over the sequence of bytes of the MMS
                         body
        @type dataIteror: iter
        """
        ######### MMS body: headers ###########
        # Get the number of data parts in the MMS body
        nEntries = self.decodeUintvar(dataIter)
        #print 'Number of data entries (parts) in MMS body:', nEntries
        
        ########## MMS body: entries ##########
        # For every data "part", we have to read the following sequence:
        # <length of content-type + other possible headers>,
        # <length of data>,
        # <content-type + other possible headers>,
        # <data>
        for partNum in range(nEntries):
            #print '\nPart %d:\n------' % partNum
            headersLen = self.decodeUintvar(dataIter)
            dataLen = self.decodeUintvar(dataIter)
            
            # Prepare to read content-type + other possible headers
            ctFieldBytes = []
            for i in range(headersLen):
                ctFieldBytes.append(dataIter.next())
#            ctIter = iter(ctFieldBytes)
            ctIter = PreviewIterator(ctFieldBytes)
            # Get content type
            contentType, ctParameters = self.decodeContentTypeValue(ctIter)
            headers = {'Content-Type' : (contentType, ctParameters)}
            #print 'Content-Type:', contentType
            #for param in ctParameters:
            #    print '    %s: %s' % (param, str(ctParameters[param]))
                
            # Now read other possible headers until <headersLen> bytes have been read
            while True:
                try:
                    hdr, value = self.decodeHeader(ctIter)
                    headers[hdr] = value
                    #print '%s: %s' % (otherHeader, otherValue)
                except StopIteration:
                    break
            #print 'Data length:', dataLen, 'bytes'
            
            # Data (note: this is not null-terminated)
            data = array.array('B')
            for i in range(dataLen):
                data.append(dataIter.next())
            
            part = message.DataPart()
            part.setData(data, contentType)
            part.contentTypeParameters = ctParameters
            part.headers = headers
            self._mmsMessage.addDataPart(part)
            
            #extension = 'dump'
            #if contentType == 'image/jpeg':
            #    extension = 'jpg'
            #if contentType == 'image/gif':
            #    extension = 'gif'
            #elif contentType == 'audio/wav':
            #    extension = 'wav'
            #elif contentType == 'audio/midi':
            #    extension = 'mid'
            #elif contentType == 'text/plain':
            #    extension = 'txt'
            #elif contentType == 'application/smil':
            #    extension = 'smil'
            
            #f = open('part%d.%s' % (partNum, extension), 'wb')
            #data.tofile(f)
            #f.close()
    
    
    @staticmethod
    def decodeHeader(byteIter):
        """ Decodes a header entry from an MMS message, starting at the byte
        pointed to by C{byteIter.next()}
        
        From [4], section 7.1:
        C{Header = MMS-header | Application-header}
        
        @raise DecodeError: This uses C{decodeMMSHeader()} and
                            C{decodeApplicationHeader()}, and will raise this
                            exception under the same circumstances as
                            C{decodeApplicationHeader()}. C{byteIter} will
                            not be modified in this case.
        
        @note: The return type of the "header value" depends on the header
               itself; it is thus up to the function calling this to determine
               what that type is (or at least compensate for possibly
               different return value types).
        
        @return: The decoded header entry from the MMS, in the format:
                 (<str:header name>, <str/int/float:header value>)
        @rtype: tuple
        """
        header = ''
        value = ''
        try:
            header, value = MMSDecoder.decodeMMSHeader(byteIter)
        except wsp_pdu.DecodeError:
            header, value = wsp_pdu.Decoder.decodeHeader(byteIter) #MMSDecoder.decodeApplicationHeader(byteIter)
        return (header, value)
    
    @staticmethod
    def decodeMMSHeader(byteIter):
        """ From [4], section 7.1:
        MMS-header = MMS-field-name MMS-value
        MMS-field-name = Short-integer
        MMS-value = Bcc-value | Cc-value | Content-location-value |
                    Content-type-value | etc
        
        This method takes into account the assigned number values for MMS
        field names, as specified in [4], section 7.3, table 8.            
        
        @raise wsp_pdu.DecodeError: The MMS field name could not be parsed.
                                C{byteIter} will not be modified in this case.
        
        @return: The decoded MMS header, in the format:
                 (<str:MMS-field-name>, <str:MMS-value>)
        @rtype: tuple
        """
        # Get the MMS-field-name
        mmsFieldName = ''
        byte = wsp_pdu.Decoder.decodeShortIntegerFromByte(byteIter.preview())
        #byte = wsp_pdu.Decoder.decodeShortInteger(byteIter)
        if byte in MMSEncodingAssignments.fieldNames:
            byteIter.next()
            mmsFieldName = MMSEncodingAssignments.fieldNames[byte][0]
#            byteIter.next()
        else:
            byteIter.resetPreview()
            raise wsp_pdu.DecodeError, 'Invalid MMS Header: could not decode MMS field name'
        # Now get the MMS-value
        mmsValue = ''
        try:
            exec 'mmsValue = MMSDecoder.decode%s(byteIter)' % MMSEncodingAssignments.fieldNames[byte][1]
        except wsp_pdu.DecodeError, msg:
            raise wsp_pdu.DecodeError, 'Invalid MMS Header: Could not decode MMS-value: %s' % msg
        except:
            print 'A fatal error occurred, probably due to an unimplemented decoding operation. Tried to decode header: %s' % mmsFieldName
            raise
        return (mmsFieldName, mmsValue)

    @staticmethod
    def decodeEncodedStringValue(byteIter):
        """ From [4], section 7.2.9:
        C{Encoded-string-value = Text-string | Value-length Char-set Text-string}
        The Char-set values are registered by IANA as MIBEnum value.
        
        @note: This function is not fully implemented, in that it does not
               have proper support for the Char-set values; it basically just
               reads over that sequence of bytes, and ignores it (see code for
               details) - any help with this will be greatly appreciated.
        
        @return: The decoded text string
        @rtype: str
        """
        decodedString = ''
        try:
            # First try "Value-length Char-set Text-string"
            valueLength = wsp_pdu.Decoder.decodeValueLength(byteIter)
            #TODO: *probably* have to include proper support for charsets...
            try:
                charSetValue = wsp_pdu.Decoder.decodeWellKnownCharset(byteIter)
            except wsp_pdu.DecodeError, msg:
                raise Exception, 'EncodedStringValue decoding error: Could not decode Char-set value; %s' % msg
            decodedString = wsp_pdu.Decoder.decodeTextString(byteIter)
        except wsp_pdu.DecodeError:
            # Fall back on just "Text-string"
            decodedString = wsp_pdu.Decoder.decodeTextString(byteIter)
        return decodedString
    
    #TODO: maybe change this to boolean values
    @staticmethod
    def decodeBooleanValue(byteIter):
        """ From [4], section 7.2.6::
         Delivery-report-value = Yes | No
         Yes = <Octet 128>
         No = <Octet 129>
        
        A lot of other yes/no fields use this encoding (read-reply, 
        report-allowed, etc)
        
        @raise wsp_pdu.DecodeError: The boolean value could not be parsed.
                                C{byteIter} will not be modified in this case.
        
        @return The value for the field: 'Yes' or 'No'
        @rtype: str
        """
        value = ''
#        byteIter, localIter = itertools.tee(byteIter)
#        byte = localIter.next()
        byte = byteIter.preview()
        if byte not in (128, 129):
            byteIter.resetPreview()
            raise wsp_pdu.DecodeError, 'Error parsing boolean value for byte: %s' % hex(byte)
        else:
            byte = byteIter.next()
            if byte == 128:
                value = 'Yes'
            elif byte == 129:
                value = 'No'
        return value

    @staticmethod
    def decodeFromValue(byteIter):
        """ From [4], section 7.2.11:
        From-value = Value-length (Address-present-token Encoded-string-value | Insert-address-token )
        Address-present-token = <Octet 128>
        Insert-address-token = <Octet 129>
        
        @return: The "From" address value
        @rtype: str
        """
        fromValue = ''
        valueLength = wsp_pdu.Decoder.decodeValueLength(byteIter)
        # See what token we have
        byte = byteIter.next()
        if byte == 129: # Insert-address-token
            fromValue = '<not inserted>'
        else:
            fromValue = MMSDecoder.decodeEncodedStringValue(byteIter)
        return fromValue
    
    @staticmethod
    def decodeMessageClassValue(byteIter):
        """ From [4], section 7.2.12:
        Message-class-value = Class-identifier | Token-text
        Class-identifier = Personal | Advertisement | Informational | Auto
        Personal = <Octet 128>
        Advertisement = <Octet 129>
        Informational = <Octet 130>
        Auto = <Octet 131>
        The token-text is an extension method to the message class.
        
        @return: The decoded message class
        @rtype: str
        """
        classIdentifiers = {128 : 'Personal',
                            129 : 'Advertisement',
                            130 : 'Informational',
                            131 : 'Auto'}
        msgClass = ''
#        byteIter, localIter = itertools.tee(byteIter)
#        byte = localIter.next()
        byte = byteIter.preview()
        if byte in classIdentifiers:
            byteIter.next()
            msgClass = classIdentifiers[byte]
        else:
            byteIter.resetPreview()
            msgClass = wsp_pdu.Decoder.decodeTokenText(byteIter)
        return msgClass

    @staticmethod
    def decodeMessageTypeValue(byteIter):
        """ Defined in [4], section 7.2.14.

        @return: The decoded message type, or '<unknown>'
        @rtype: str
        """
        messageTypes = {0x80 : 'm-send-req',
                        0x81 : 'm-send-conf',
                        0x82 : 'm-notification-ind',
                        0x83 : 'm-notifyresp-ind',
                        0x84 : 'm-retrieve-conf',
                        0x85 : 'm-acknowledge-ind',
                        0x86 : 'm-delivery-ind'}
        byte = byteIter.preview()
        if byte in messageTypes:
            byteIter.next()
            return messageTypes[byte]
        else:
            byteIter.resetPreview()
            return '<unknown>'
    
    @staticmethod
    def decodePriorityValue(byteIter):
        """ Defined in [4], section 7.2.17
        
        @raise wsp_pdu.DecodeError: The priority value could not be decoded;
                                C{byteIter} is not modified in this case.
        
        @return: The decoded priority value
        @rtype: str
        """
        priorities = {128 : 'Low',
                      129 : 'Normal',
                      130 : 'High'}
#        byteIter, localIter = itertools.tee(byteIter)
        byte = byteIter.preview()
        if byte in priorities:
            byte = byteIter.next()
            return priorities[byte]
        else:
            byteIter.resetPreview()
            raise wsp_pdu.DecodeError, 'Error parsing Priority value for byte:',byte
        
    @staticmethod
    def decodeSenderVisibilityValue(byteIter):
        """ Defined in [4], section 7.2.22::
         Sender-visibility-value = Hide | Show
         Hide = <Octet 128>
         Show = <Octet 129>
        
        @raise wsp_pdu.DecodeError: The sender visibility value could not be
                                parsed.
                                C{byteIter} will not be modified in this case.
        
        @return: The sender visibility: 'Hide' or 'Show'
        @rtype: str
        """
        value = ''
#        byteIter, localIter = itertools.tee(byteIter)
#        byte = localIter.next()
        byte = byteIter.preview()
        if byte not in (128, 129):
            byteIter.resetPreview()
            raise wsp_pdu.DecodeError, 'Error parsing sender visibility value for byte: %s' % hex(byte)
        else:
            byte = byteIter.next()
            if byte == 128:
                value = 'Hide'
            elif byte == 129:
                value = 'Show'
        return value
    
    @staticmethod
    def decodeResponseStatusValue(byteIter):
        """ Defined in [4], section 7.2.20
        
        Used to decode the "Response Status" MMS header.
        
        @raise wsp_pdu.DecodeError: The sender visibility value could not be
                                parsed.
                                C{byteIter} will not be modified in this case.
        
        @return: The decoded Response-status-value
        @rtype: str
        """
        responseStatusValues = {0x80 : 'Ok',
                                0x81 : 'Error-unspecified',
                                0x82 : 'Error-service-denied',
                                0x83 : 'Error-message-format-corrupt',
                                0x84 : 'Error-sending-address-unresolved',
                                0x85 : 'Error-message-not-found',
                                0x86 : 'Error-network-problem',
                                0x87 : 'Error-content-not-accepted',
                                0x88 : 'Error-unsupported-message'}
        byte = byteIter.preview()
        if byte in responseStatusValues:
            byteIter.next()
            return responseStatusValues[byte]
        else:
            byteIter.next()
            # Return an unspecified error if the response is not recognized
            return responseStatusValues[0x81]
        
    @staticmethod
    def decodeStatusValue(byteIter):
        """ Defined in [4], section 7.2.23
        
        Used to decode the "Status" MMS header.
        
        @raise wsp_pdu.DecodeError: The sender visibility value could not be
                                parsed.
                                C{byteIter} will not be modified in this case.
        
        @return: The decoded Status-value
        @rtype: str
        """
        
        statusValues = {0x80 : 'Expired',
                        0x81 : 'Retrieved',
                        0x82 : 'Rejected',
                        0x83 : 'Deferred',
                        0x84 : 'Unrecognised'}
        
        byte = byteIter.preview()
        if byte in statusValues:
            byteIter.next()
            return statusValues[byte]
        else:
            byteIter.next()
            # Return an unrecognised state if it couldn't be decoded
            return statusValues[0x84]
    
    
    @staticmethod
    def decodeExpiryValue(byteIter):
        """ Defined in [4], section 7.2.10
        
        Used to decode the "Expiry" MMS header.
        
        From [4], section 7.2.10:
        Expiry-value = Value-length (Absolute-token Date-value | Relative-token Delta-seconds-value)
        Absolute-token = <Octet 128>
        Relative-token = <Octet 129>

        @raise wsp_pdu.DecodeError: The Expiry-value could not be decoded
        
        @return: The decoded Expiry-value, either as a date, or as a delta-seconds value
        @rtype: str or int
        """
        valueLength = MMSDecoder.decodeValueLength(byteIter)
        token = byteIter.next()
        
        if token == 0x80: # Absolute-token
            data = MMSDecoder.decodeDateValue(byteIter)
        elif token == 0x81: # Relative-token
            data = MMSDecoder.decodeDeltaSecondsValue(byteIter)
        else:
            raise wsp_pdu.DecodeError, 'Unrecognized token value: %s' % hex(token)
        return data
        
    
class MMSEncoder(wsp_pdu.Encoder):
    def __init__(self):
        self._mmsMessage = message.MMSMessage()
    
    def encode(self, mmsMessage):
        """ Encodes the specified MMS message
        
        @param mmsMessage: The MMS message to encode
        @type mmsMessage: MMSMessage
        
        @return: The binary-encoded MMS data, as a sequence of bytes
        @rtype: array.array('B')
        """
        self._mmsMessage = mmsMessage
        msgData = self.encodeMessageHeader()
        msgData.extend(self.encodeMessageBody())
        return msgData
    
    def encodeMessageHeader(self):
        """ Binary-encodes the MMS header data.
        
        @note: The encoding used for the MMS header is specified in [4].
               All "constant" encoded values found/used in this method
               are also defined in [4]. For a good example, see [2].
                
        @return: the MMS PDU header, as an array of bytes
        @rtype: array.array('B')
        """        
        # See [4], chapter 8 for info on how to use these
        fromTypes = {'Address-present-token' : 0x80,
                     'Insert-address-token'  : 0x81}
            
        contentTypes = {'application/vnd.wap.multipart.related' : 0xb3}
        
        # Create an array of 8-bit values
        messageHeader = array.array('B')
    
        headersToEncode = self._mmsMessage.headers
        
        # If the user added any of these to the message manually (X- prefix), rather use those
        for hdr in ('X-Mms-Message-Type', 'X-Mms-Transaction-Id', 'X-Mms-Version'):
            if hdr in headersToEncode:
                if hdr == 'X-Mms-Version':
                    cleanHeader = 'MMS-Version'
                else:
                    cleanHeader = hdr.replace('X-Mms-', '', 1)
                headersToEncode[cleanHeader] = headersToEncode[hdr]
                del headersToEncode[hdr]
                
         # First 3  headers (in order), according to [4]:
        ################################################
        # - X-Mms-Message-Type
        # - X-Mms-Transaction-ID
        # - X-Mms-Version
        
        ### Start of Message-Type verification
        if 'Message-Type' not in headersToEncode:
            # Default to 'm-retrieve-conf'; we don't need a To/CC field for this
            # (see WAP-209, section 6.3, table 5)
            headersToEncode['Message-Type'] = 'm-retrieve-conf'
        
        # See if the chosen message type is valid, given the message's other headers
        # NOTE: we only distinguish between 'm-send-req' (requires a destination number)
        #       and 'm-retrieve-conf' (requires no destination number)
        #       - if "Message-Type" is something else, we assume the message creator 
        #       knows what he/she is doing...
        if headersToEncode['Message-Type'] == 'm-send-req':
            foundDestAddress = False
            for addressType in ('To', 'Cc', 'Bc'):
                if addressType in headersToEncode:
                    foundDestAddress = True
                    break
            if not foundDestAddress:
                headersToEncode['Message-Type'] = 'm-retrieve-conf'
        ### End of Message-Type verification
        
        ### Start of Transaction-Id verification
        if 'Transaction-Id' not in headersToEncode:
            import random
            headersToEncode['Transaction-Id'] = str(random.randint(1000, 9999))
        ### End of Transaction-Id verification
        
        ### Start of MMS-Version verification
        if 'MMS-Version' not in headersToEncode:
            headersToEncode['MMS-Version'] = '1.0'
        
        # Encode the first three headers, in correct order
        for hdr in ('Message-Type', 'Transaction-Id', 'MMS-Version'):
            messageHeader.extend(MMSEncoder.encodeHeader(hdr, headersToEncode[hdr]))
            del headersToEncode[hdr]
    
        # Encode all remaining MMS message headers, except "Content-Type"
        # -- this needs to be added last, according [2] and [4]
        for hdr in headersToEncode:
            if hdr == 'Content-Type':
                continue
            messageHeader.extend(MMSEncoder.encodeHeader(hdr, headersToEncode[hdr]))
        
        # Ok, now only "Content-type" should be left
        ctType = headersToEncode['Content-Type'][0]
        ctParameters = headersToEncode['Content-Type'][1]
        messageHeader.extend(MMSEncoder.encodeMMSFieldName('Content-Type'))
        messageHeader.extend(MMSEncoder.encodeContentTypeValue(ctType, ctParameters))

        return messageHeader
    
    def encodeMessageBody(self):
        """ Binary-encodes the MMS body data.
        
        @note: The MMS body is of type C{application/vnd.wap.multipart}
        (C{mixed} or C{related}).
        As such, its structure is divided into a header, and the data entries/parts::
        
            [ header ][ entries ]
            ^^^^^^^^^^^^^^^^^^^^^
                  MMS Body
        
        The MMS Body header consists of one entry[5]::
         name          type          purpose
         -------      -------        -----------
         nEntries     Uintvar        number of entries in the multipart entity
        
        The MMS body's multipart entries structure::
         name             type                   purpose
         -------          -----                  -----------
         HeadersLen       Uintvar                length of the ContentType and 
                                                 Headers fields combined
         DataLen          Uintvar                length of the Data field
         ContentType      Multiple octets        the content type of the data
         Headers          (<HeadersLen> 
                           - length of 
                          <ContentType>) octets  the part's headers
         Data             <DataLen> octets       the part's data
        
        @note: The MMS body's header should not be confused with the actual
               MMS header, as returned by C{_encodeHeader()}.
        
        @note: The encoding used for the MMS body is specified in [5], section 8.5.
               It is only referenced in [4], however [2] provides a good example of
               how this ties in with the MMS header encoding.
               
        @return: The binary-encoded MMS PDU body, as an array of bytes
        @rtype: array.array('B')
        """

        messageBody = array.array('B')
        
        #TODO: enable encoding of MMSs without SMIL file
        ########## MMS body: header ##########
        # Parts: SMIL file + <number of data elements in each slide>
        nEntries = 1
        for page in self._mmsMessage._pages:
            nEntries += page.numberOfParts()
        for dataPart in self._mmsMessage._dataParts:
            nEntries += 1
            
        messageBody.extend(self.encodeUintvar(nEntries))
        
        ########## MMS body: entries ##########
        # For every data "part", we have to add the following sequence:
        # <length of content-type + other possible headers>,
        # <length of data>,
        # <content-type + other possible headers>,
        # <data>.

        # Gather the data parts, adding the MMS message's SMIL file
        smilPart = message.DataPart()
        smil = self._mmsMessage.smil()
        smilPart.setData(smil, 'application/smil')
        #TODO: make this dynamic....
        smilPart.headers['Content-ID'] = '<0000>'
        parts = [smilPart]
        for slide in self._mmsMessage._pages:
            for partTuple in (slide.image, slide.audio, slide.text):
                if partTuple != None:
                    parts.append(partTuple[0])
    
        for part in parts:
            partContentType = self.encodeContentTypeValue(part.headers['Content-Type'][0], part.headers['Content-Type'][1])
            
            encodedPartHeaders = []
            for hdr in part.headers:
                if hdr == 'Content-Type':
                    continue
                encodedPartHeaders.extend(wsp_pdu.Encoder.encodeHeader(hdr, part.headers[hdr]))
        
            # HeadersLen entry (length of the ContentType and Headers fields combined)
            headersLen = len(partContentType) + len(encodedPartHeaders)
            messageBody.extend(self.encodeUintvar(headersLen))
            # DataLen entry (length of the Data field)
            messageBody.extend(self.encodeUintvar(len(part)))
            # ContentType entry
            messageBody.extend(partContentType)
            # Headers
            messageBody.extend(encodedPartHeaders)
            # Data (note: we do not null-terminate this)
            for char in part.data:
                messageBody.append(ord(char))
        return messageBody

    
    @staticmethod
    def encodeHeader(headerFieldName, headerValue):
        """ Encodes a header entry for an MMS message
        
        From [4], section 7.1:
        C{Header = MMS-header | Application-header}
        C{MMS-header = MMS-field-name MMS-value}
        C{MMS-field-name = Short-integer}
        C{MMS-value = Bcc-value | Cc-value | Content-location-value |
                      Content-type-value | etc}
                    
        @raise DecodeError: This uses C{decodeMMSHeader()} and
                            C{decodeApplicationHeader()}, and will raise this
                            exception under the same circumstances as
                            C{decodeApplicationHeader()}. C{byteIter} will
                            not be modified in this case.
        
        @note: The return type of the "header value" depends on the header
               itself; it is thus up to the function calling this to determine
               what that type is (or at least compensate for possibly
               different return value types).
        
        @return: The decoded header entry from the MMS, in the format:
                 (<str:header name>, <str/int/float:header value>)
        @rtype: tuple
        """
        encodedHeader = []
        # First try encoding the header as a "MMS-header"...
        for assignedNumber in MMSEncodingAssignments.fieldNames:
            if MMSEncodingAssignments.fieldNames[assignedNumber][0] == headerFieldName:
                encodedHeader.extend(wsp_pdu.Encoder.encodeShortInteger(assignedNumber))
                # Now encode the value
                expectedType = MMSEncodingAssignments.fieldNames[assignedNumber][1]
                try:
                    exec 'encodedHeader.extend(MMSEncoder.encode%s(headerValue))' % expectedType
                except wsp_pdu.EncodeError, msg:
                    raise wsp_pdu.EncodeError, 'Error encoding parameter value: %s' % msg
                except:
                    print 'A fatal error occurred, probably due to an unimplemented encoding operation'
                    raise
                break
        # See if the "MMS-header" encoding worked
        if len(encodedHeader) == 0:
            # ...it didn't. Use "Application-header" encoding
            encodedHeaderName = wsp_pdu.Encoder.encodeTokenText(headerFieldName)
            encodedHeader.extend(encodedHeaderName)
            # Now add the value
            encodedHeader.extend(wsp_pdu.Encoder.encodeTextString(headerValue))
        return encodedHeader
    
    @staticmethod
    def encodeMMSFieldName(fieldName):
        """ Encodes an MMS header field name, using the "assigned values" for
        well-known MMS headers as specified in [4].
        
        From [4], section 7.1:
        C{MMS-field-name = Short-integer}
        
        @raise EncodeError: The specified header field name is not a
                            well-known MMS header.
        
        @param fieldName: The header field name to encode
        @type fieldName: str
        
        @return: The encoded header field name, as a sequence of bytes
        @rtype: list
        """
        encodedMMSFieldName = []
        for assignedNumber in MMSEncodingAssignments.fieldNames:
            if MMSEncodingAssignments.fieldNames[assignedNumber][0] == fieldName:
                encodedMMSFieldName.extend(wsp_pdu.Encoder.encodeShortInteger(assignedNumber))
                break
        if len(encodedMMSFieldName) == 0:
            raise wsp_pdu.EncodeError, 'The specified header field name is not a well-known MMS header field name'
        return encodedMMSFieldName
    
    @staticmethod
    def encodeFromValue(fromValue=''):
        """ From [4], section 7.2.11:
        From-value = Value-length (Address-present-token Encoded-string-value | Insert-address-token )
        Address-present-token = <Octet 128>
        Insert-address-token = <Octet 129>
        
        @param fromValue: The "originator" of the MMS message. This may be an
                          empty string, in which case a token will be encoded
                          informing the MMSC to insert the address of the
                          device that sent this message (default).
        @type fromValue: str
        
        @return: The encoded "From" address value, as a sequence of bytes
        @rtype: list
        """
        encodedFromValue = []
        if len(fromValue) == 0:
            valueLength = wsp_pdu.Encoder.encodeValueLength(1)
            encodedFromValue.extend(valueLength)
            encodedFromValue.append(129) # Insert-address-token
        else:
            encodedAddress = MMSEncoder.encodeEncodedStringValue(fromValue)
            length = len(encodedAddress) + 1 # the "+1" is for the Address-present-token
            valueLength = wsp_pdu.Encoder.encodeValueLength(length)
            encodedFromValue.extend(valueLength)
            encodedFromValue.append(128) # Address-present-token
            encodedFromValue.extend(encodedAddress)
        return encodedFromValue

    @staticmethod
    def encodeEncodedStringValue(stringValue):
        """ From [4], section 7.2.9:
        C{Encoded-string-value = Text-string | Value-length Char-set Text-string}
        The Char-set values are registered by IANA as MIBEnum value.
        
        @param stringValue: The text string to encode
        @type stringValue: str
        
        @note: This function is currently a simple wrappper to
               C{encodeTextString()}
        
        @return: The encoded string value, as a sequence of bytes
        @rtype: list
        """
        return wsp_pdu.Encoder.encodeTextString(stringValue)
    
    @staticmethod
    def encodeMessageTypeValue(messageType):
        """ Defined in [4], section 7.2.14.
        
        @note: Unknown message types are discarded; thus they will be encoded
               as 0x80 ("m-send-req") by this function
        
        @param messageType: The MMS message type to encode
        @type messageType: str

        @return: The encoded message type, as a sequence of bytes
        @rtype: list
        """
        messageTypes = {'m-send-req' : 0x80, 
                        'm-send-conf' : 0x81,
                        'm-notification-ind' : 0x81,
                        'm-notifyresp-ind' : 0x83,
                        'm-retrieve-conf' : 0x84,
                        'm-acknowledge-ind' : 0x85,
                        'm-delivery-ind' : 0x86}
        if messageType in messageTypes:
            return [messageTypes[messageType]]
        else:
            return [0x80]
