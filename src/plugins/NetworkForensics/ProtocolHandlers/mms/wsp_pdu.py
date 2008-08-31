#!/usr/bin/env python
#
# This library is free software, distributed under the terms of
# the GNU Lesser General Public License Version 2.
# See the COPYING file included in this archive
#
# The docstrings in this module contain epytext markup; API documentation
# may be created by processing this file with epydoc: http://epydoc.sf.net

""" WSP Data Unit structure encoding and decoding classes

Throughout the classes defined in this module, the following "primitive data
type" terminology applies, as specified in [5], section 8.1.1::

    Data Type     Definition
    bit           1 bit of data
    octet         8 bits of opaque data
    uint8         8-bit unsigned integer
    uint16        16-bit unsigned integer
    uint32        32-bit unsigned integer
    uintvar       variable length unsigned integer

This Encoder and Decoder classes provided in this module firstly provides
public methods for decoding and encoding each of these data primitives (where
needed).

Next, they provide methods encapsulating the basic WSP Header encoding rules
as defined in section 8.4.2.1 of [5].

Finally, the classes defined here provide methods for decoding/parsing
specific WSP header fields.

@author: Francois Aucamp C{<faucamp@csir.co.za>}
@license:  GNU Lesser General Public License, version 2
@note: This is part of the PyMMS library

@note: References used in the code and this document:
    5. Wap Forum/Open Mobile Alliance, "WAP-230 Wireless Session Protocol Specification"
    U{http://www.openmobilealliance.org/tech/affiliates/LicenseAgreement.asp?DocName=/wap/wap-230-wsp-20010705-a.pdf}
"""

import array
from iterator import PreviewIterator
#import itertools


     

class WSPEncodingAssignments:
    """ Static class containing the constant values defined in [5] for
    well-known content types, parameter names, etc.
    
    It also defines some function for combining assigned number-tables for
    specific WSP encoding versions, where appropriate.
    
    This is used by both the Encoder and Decoder classes during well-known
    assigned number lookups (usually these functions have the string
    C{WellKnown} in their names).
    
        - Assigned parameters are stored in a dictionary, C{wkParameters},
          containing all assigned values for WSP encoding versions 1.1 - 1.4,
          in the format:
          C{{<int>assigned number: (<str>name, <str>expected value type)}}
          A "encoding versioned"-version of this dictionary can be retrieved
          by calling the C{wellKnowParameters()} function with an appropriate
          WSP encoding version as parameter.
        - Assigned content types are stored in a list, C{wkContentTypes}, in
          order; thus, their index in the list is equal to their assigned
          value.
    
    """
    wspPDUTypes = {0x01: 'Connect',
                   0x02: 'ConnectReply',
                   0x03: 'Redirect',
                   0x04: 'Reply',
                   0x05: 'Disconnect',
                   0x06: 'Push',
                   0x07: 'ConfirmedPush',
                   0x08: 'Suspend',
                   0x09: 'Resume',
                   0x40: 'Get',
                   0x60: 'Post'}

    # Well-known parameter assignments ([5], table 38)
    wkParameters = {0x00: ('Q', 'QValue'),
                    0x01: ('Charset', 'WellKnownCharset'),
                    0x02: ('Level', 'VersionValue'),
                    0x03: ('Type', 'IntegerValue'),
                    0x05: ('Name', 'TextString'),
                    0x06: ('Filename', 'TextString'),
                    0x07: ('Differences', 'Field-name'),
                    0x08: ('Padding', 'ShortInteger'),
                    0x09: ('Type', 'ConstrainedEncoding'), # encoding version 1.2
                    0x0a: ('Start', 'TextString'),
                    0x0b: ('Start-info', 'TextString'),
                    0x0c: ('Comment', 'TextString'), # encoding version 1.3
                    0x0d: ('Domain', 'TextString'),
                    0x0e: ('Max-Age', 'DeltaSecondsValue'),
                    0x0f: ('Path', 'TextString'),
                    0x10: ('Secure', 'NoValue'),
                    0x11: ('SEC', 'ShortInteger'), # encoding version 1.4
                    0x12: ('MAC', 'TextValue'),
                    0x13: ('Creation-date', 'DateValue'),
                    0x14: ('Modification-date', 'DateValue'),
                    0x15: ('Read-date', 'DateValue'),
                    0x16: ('Size', 'IntegerValue'),
                    0x17: ('Name', 'TextValue'),
                    0x18: ('Filename', 'TextValue'),
                    0x19: ('Start', 'TextValue'),
                    0x1a: ('Start-info', 'TextValue'),
                    0x1b: ('Comment', 'TextValue'),
                    0x1c: ('Domain', 'TextValue'),
                    0x1d: ('Path', 'TextValue')}
    
    # Content type assignments ([5], table 40)
    wkContentTypes = ['*/*', 'text/*', 'text/html', 'text/plain',
                      'text/x-hdml', 'text/x-ttml', 'text/x-vCalendar',
                      'text/x-vCard', 'text/vnd.wap.wml',
                      'text/vnd.wap.wmlscript', 'text/vnd.wap.wta-event',
                      'multipart/*', 'multipart/mixed', 'multipart/form-data',
                      'multipart/byterantes', 'multipart/alternative',
                      'application/*', 'application/java-vm',
                      'application/x-www-form-urlencoded',
                      'application/x-hdmlc', 'application/vnd.wap.wmlc',
                      'application/vnd.wap.wmlscriptc',
                      'application/vnd.wap.wta-eventc',
                      'application/vnd.wap.uaprof',
                      'application/vnd.wap.wtls-ca-certificate',
                      'application/vnd.wap.wtls-user-certificate',
                      'application/x-x509-ca-cert',
                      'application/x-x509-user-cert',
                      'image/*', 'image/gif', 'image/jpeg', 'image/tiff',
                      'image/png', 'image/vnd.wap.wbmp', 
                      'application/vnd.wap.multipart.*', 
                      'application/vnd.wap.multipart.mixed', 
                      'application/vnd.wap.multipart.form-data', 
                      'application/vnd.wap.multipart.byteranges', 
                      'application/vnd.wap.multipart.alternative', 
                      'application/xml', 'text/xml', 
                      'application/vnd.wap.wbxml', 
                      'application/x-x968-cross-cert', 
                      'application/x-x968-ca-cert', 
                      'application/x-x968-user-cert', 
                      'text/vnd.wap.si', 
                      'application/vnd.wap.sic', 
                      'text/vnd.wap.sl', 
                      'application/vnd.wap.slc', 
                      'text/vnd.wap.co', 
                      'application/vnd.wap.coc', 
                      'application/vnd.wap.multipart.related',
                      'application/vnd.wap.sia', 
                      'text/vnd.wap.connectivity-xml', 
                      'application/vnd.wap.connectivity-wbxml', 
                      'application/pkcs7-mime', 
                      'application/vnd.wap.hashed-certificate', 
                      'application/vnd.wap.signed-certificate', 
                      'application/vnd.wap.cert-response',
                      'application/xhtml+xml',
                      'application/wml+xml',
                      'text/css', 
                      'application/vnd.wap.mms-message',
                      'application/vnd.wap.rollover-certificate', 
                      'application/vnd.wap.locc+wbxml', 
                      'application/vnd.wap.loc+xml', 
                      'application/vnd.syncml.dm+wbxml', 
                      'application/vnd.syncml.dm+xml', 
                      'application/vnd.syncml.notification', 
                      'application/vnd.wap.xhtml+xml', 
                      'application/vnd.wv.csp.cir', 
                      'application/vnd.oma.dd+xml', 
                      'application/vnd.oma.drm.message', 
                      'application/vnd.oma.drm.content', 
                      'application/vnd.oma.drm.rights+xml',
                      'application/vnd.oma.drm.rights+wbxml']
    
    
    # Well-known character sets (table 42 of [5])
    # Format {<assinged_number> : <charset>}
    # Note that the assigned number is the same as the IANA MIBEnum value
    # "gsm-default-alphabet" is not included, as it is not assigned any value in [5]
    # Also note, this is by no means a complete list
    wkCharSets = {0x07EA: 'big5',
                  0x03E8: 'iso-10646-ucs-2',
                  0x04: 'iso-8859-1',    
                  0x05: 'iso-8859-2',
                  0x06: 'iso-8859-3',
                  0x07: 'iso-8859-4',
                  0x08: 'iso-8859-5',
                  0x09: 'iso-8859-6',
                  0x0A: 'iso-8859-7',
                  0x0B: 'iso-8859-8',
                  0x0C: 'iso-8859-9',
                  0x11: 'shift_JIS',
                  0x03: 'us-ascii',
                  0x6A: 'utf-8'}
    
    # Header Field Name assignments ([5], table 39)
    hdrFieldNames = ['Accept', 'Accept-Charset', 'Accept-Encoding',
                     'Accept-Language', 'Accept-Ranges', 'Age',
                     'Allow', 'Authorization', 'Cache-Control',
                     'Connection', 'Content-Base', 'Content-Encoding',
                     'Content-Language', 'Content-Length',
                     'Content-Location', 'Content-MD5', 'Content-Range',
                     'Content-Type', 'Date', 'Etag', 'Expires', 'From',
                     'Host', 'If-Modified-Since', 'If-Match',
                     'If-None-Match', 'If-Range', 'If-Unmodified-Since',
                     'Location', 'Last-Modified', 'Max-Forwards', 'Pragma',
                     'Proxy-Authenticate', 'Proxy-Authorization', 'Public',
                     'Range', 'Referer', 'Retry-After', 'Server',
                     'Transfer-Encoding', 'Upgrade', 'User-Agent',
                     'Vary', 'Via', 'Warning', 'WWW-Authenticate',
                     'Content-Disposition',
                     # encoding version 1.2
                     'X-Wap-Application-Id', 'X-Wap-Content-URI', 
                     'X-Wap-Initiator-URI', 'Accept-Application',
                     'Bearer-Indication', 'Push-Flag', 'Profile',
                     'Profile-Diff', 'Profile-Warning',
                     # encoding version 1.3
                     'Expect', 'TE', 'Trailer', 'Accept-Charset',
                     'Accept-Encoding', 'Cache-Control',
                     'Content-Range', 'X-Wap-Tod', 'Content-ID',
                     'Set-Cookie', 'Cookie', 'Encoding-Version',
                     # encoding version 1.4
                     'Profile-Warning', 'Content-Disposition',
                     'X-WAP-Security', 'Cache-Control']

    #TODO: combine this dict with the hdrFieldNames table (same as well known parameter assignments)
    # Temporary fix to allow different types of header field values to be dynamically decoded
    hdrFieldEncodings = {'Accept': 'AcceptValue',
                         'Pragma': 'PragmaValue'}

    @staticmethod
    def wellKnownParameters(encodingVersion = '1.2'):
        """ Formats list of assigned values for well-known parameter names,
        for the specified WSP encoding version.
        
        @param encodingVersion: The WSP encoding version to use. This defaults
                                to "1.2", but may be "1.1", "1.2", "1.3" or
                                "1.4" (see table 38 in [5] for details).
        @type encodingVersion: str
        
        @raise ValueError: The specified encoding version is invalid.
        
        @return: A dictionary containing the well-known parameters with
                 assigned numbers for the specified encoding version (and
                 lower). Entries in this dict follow the format:
                 C{{<int:assigned_number> : (<str:param_name>, <str:expected_type>)}}
        @rtype: dict
        """
        if encodingVersion not in ('1.1', '1.2', '1.3', '1.4'):
            raise ValueError, 'encodingVersion must be "1.1", "1.2", "1.3" or "1.4"'
        else:
            version = int(encodingVersion.split('.')[1])
        wkVersionedParameters = dict(WSPEncodingAssignments.wkParameters)
        if version <= 3:
            for assignedNumber in range(0x11, 0x1e):
                del wkVersionedParameters[assignedNumber]
        if version <= 2:
            for assignedNumber in range(0x0c, 0x11):
                del wkVersionedParameters[assignedNumber]
        if version == 1:
            for assignedNumber in range(0x09, 0x0c):
                del wkVersionedParameters[assignedNumber]
        return wkVersionedParameters
    
    @staticmethod
    def headerFieldNames(encodingVersion = '1.2'):
        """ Formats list of assigned values for header field names, for the
        specified WSP encoding version.
        
        @param encodingVersion: The WSP encoding version to use. This defaults
                                to "1.2", but may be "1.1", "1.2", "1.3" or
                                "1.4" (see table 39 in [5] for details).
        @type encodingVersion: str
        
        @raise ValueError: The specified encoding version is invalid.
        
        @return: A list containing the WSP header field names with assigned
                 numbers for the specified encoding version (and lower).
        @rtype: list
        """
        if encodingVersion not in ('1.1', '1.2', '1.3', '1.4'):
            raise ValueError, 'encodingVersion must be "1.1", "1.2", "1.3" or "1.4"'
        else:
            version = int(encodingVersion.split('.')[1])
        versionedHdrFieldNames = list(WSPEncodingAssignments.hdrFieldNames)
        if version == 3:
            versionedHdrFieldNames = versionedHdrFieldNames[:0x44]
        elif version == 2:
            versionedHdrFieldNames = versionedHdrFieldNames[:0x38]
        elif version == 1:
            versionedHdrFieldNames = versionedHdrFieldNames[:0x2f]
        return versionedHdrFieldNames


class DecodeError(Exception):
    """ The decoding operation failed; most probably due to an invalid byte in
    the sequence provided for decoding """
    
class EncodeError(Exception):
    """ The encoding operation failed; most probably due to an invalid value
    provided for encoding """

class Decoder:
    """ A WSP Data unit decoder """
    @staticmethod
    def decodeUint8(byteIter):
        """ Decodes an 8-bit unsigned integer from the byte pointed to by
        C{byteIter.next()}
    
        @note: this function will move the iterator passed as C{byteIter} one
               byte forward.
        
        @param byteIter: an iterator over a sequence of bytes
        @type byteIteror: iter
        
        @return: the decoded 8-bit unsigned integer
        @rtype: int
        """
        # Make the byte unsigned
        return byteIter.next() & 0xff
 
    @staticmethod
    def decodeUintvar(byteIter):
        """ Decodes the variable-length unsigned integer starting at the
        byte pointed to by C{byteIter.next()}
        
        See C{wsp.Encoder.encodeUintvar()} for a detailed description of the
        encoding scheme used for C{Uintvar} sequences.
       
        @note: this function will move the iterator passed as C{byteIter} to
               the last octet in the uintvar sequence; thus, after calling
               this, that iterator's C{next()} function will return the first
               byte B{after}the uintvar sequence.
        
        @param byteIter: an iterator over a sequence of bytes
        @type byteIteror: iter
        
        @return: the decoded unsigned integer
        @rtype: int
        """
        uint = 0 
        byte = byteIter.next()
        while (byte >> 7) == 0x01:
            uint = uint << 7
            uint |= byte & 0x7f
            byte = byteIter.next()
        uint = uint << 7
        uint |= byte & 0x7f
        return uint


    @staticmethod
    def decodeShortInteger(byteIter):
        """ Decodes the short-integer value starting at the byte pointed to
        by C{byteIter.next()}.
        
        The encoding for a long integer is specified in [5], section 8.4.2.1:
            C{Short-integer = OCTET
            Integers in range 0-127 shall be encoded as a one octet value with
            the most significant bit set to one (1xxx xxxx) and with the value
            in the remaining least significant bits.}
        
        @raise DecodeError: Not a valid short-integer; the most significant
                            isn't set to 1.
                            C{byteIter} will not be modified if this is raised
        
        @return: The decoded short integer
        @rtype: int
        """
        byte = byteIter.preview()
        if not byte & 0x80:
            byteIter.resetPreview()
            raise DecodeError, 'Not a valid short-integer: most significant bit not set'
        byte = byteIter.next()
        return byte & 0x7f
    
    @staticmethod
    def decodeShortIntegerFromByte(byte):
        """ Decodes the short-integer value contained in the specified byte
        value
        
        @param byte: the byte value to decode
        @type byte: int
        
        @raise DecodeError: Not a valid short-integer; the most significant
                            isn't set to 1.
        @return: The decoded short integer
        @rtype: int
        """
        if not byte & 0x80:
            raise DecodeError, 'Not a valid short-integer: most significant bit not set'
        return byte & 0x7f

    @staticmethod
    def decodeLongInteger(byteIter):
        """ Decodes the long integer value starting at the byte pointed to
        by C{byteIter.next()}.
        
        The encoding for a long integer is specified in [5], section 8.4.2.1,
        and follows the form::
        
         Long-integer = [Short-length] [Multi-octet-integer]
                            ^^^^^^     ^^^^^^^^^^^^^^^^^^^^^
                            1 byte     <Short-length> bytes
        
         The Short-length indicates the length of the Multi-octet-integer.

        @raise DecodeError: The byte pointed to by C{byteIter.next()} does
                            not indicate the start of a valid long-integer
                            sequence (short-length is invalid). If this is
                            raised, the iterator passed as C{byteIter} will
                            not be modified.
    
        @note: If this function returns successfully, it will move the
               iterator passed as C{byteIter} to the last octet in the encoded
               long integer sequence; thus, after calling this, that
               iterator's C{next()} function will return the first byte
               B{after}the encoded long integer sequence.
               
        @param byteIter: an iterator over a sequence of bytes
        @type byteIteror: iter
        
        @return: The decoded long integer
        @rtype: int
        """
        try:
            shortLength = Decoder.decodeShortLength(byteIter)
        except DecodeError:
            raise DecodeError, 'Not a valid long-integer: short-length byte is invalid'
        longInt = 0
        # Decode the Multi-octect-integer
        for i in range(shortLength):
            longInt = longInt << 8
            longInt |= byteIter.next()
        return longInt

    @staticmethod
    def decodeTextString(byteIter):
        """ Decodes the null-terminated, binary-encoded string value starting
        at the byte pointed to by C{dataIter.next()}.
        
        This follows the basic encoding rules specified in [5], section
        8.4.2.1
        
        @note: this function will move the iterator passed as C{byteIter} to
               the last octet in the encoded string sequence; thus, after
               calling this, that iterator's C{next()} function will return
               the first byte B{after}the encoded string sequence.
               
        @param byteIter: an iterator over a sequence of bytes
        @type byteIteror: iter
        
        @return: The decoded text string
        @rtype: str
        """
        decodedString = ''
        byte = byteIter.next()
        # Remove Quote character (octet 127), if present
        if byte == 127:
            byte = byteIter.next()
        while byte != 0x00:
            decodedString += chr(byte)
            byte = byteIter.next()
        return decodedString
    
    @staticmethod
    def decodeQuotedString(byteIter):
        """ From [5], section 8.4.2.1:
        Quoted-string = <Octet 34> *TEXT End-of-string
        The TEXT encodes an RFC2616 Quoted-string with the enclosing
        quotation-marks <"> removed
        
        @return: The decoded text string
        @rtype: str
        """
#        byteIter, localIter = itertools.tee(byteIter)
        # look for the quote character
        byte = byteIter.preview()
        if byte != 34:
            byteIter.resetPreview()
            raise DecodeError, 'Invalid quoted string; must start with <octect 34>'
        else:
            byteIter.next()
            #CHECK: should the quotation chars be pre- and appended before returning/
            # *technically* we should not check for quote characters. oh well.
            return Decoder.decodeTextString(byteIter)

    
    @staticmethod
    def decodeTokenText(byteIter):
        """ From [5], section 8.4.2.1:
        Token-text = Token End-of-string
        
        @raise DecodeError: invalid token; in this case, byteIter is not modified
                 
        @return: The token string if successful, or the byte that was read if not
        @rtype: str or int
        """
        separators = (11, 32, 40, 41, 44, 47, 58, 59, 60, 61, 62, 63, 64, 91,
                      92, 93, 123, 125)
        token = ''
#        byteIter, localIter = itertools.tee(byteIter)
#        byte = localIter.next()
        byte = byteIter.preview()
        if byte <= 31 or byte in separators:
            byteIter.resetPreview()
            raise DecodeError, 'Invalid token'
        byte = byteIter.next()
        while byte > 31 and byte not in separators:
            token += chr(byte)
            byte = byteIter.next()
        return token
    
    @staticmethod
    def decodeExtensionMedia(byteIter):
        """ From [5], section 8.4.2.1:
        Extension-media = *TEXT End-of-string
        This encoding is used for media values, which have no well-known
        binary encoding
        
        @raise DecodeError: The TEXT started with an invalid character.
                            C{byteIter} is not modified if this happens.
        
        @return: The decoded media type value
        @rtype: str
        """
        mediaValue = ''
#        byteIter, localIter = itertools.tee(byteIter)
#        byte = localIter.next()
        byte = byteIter.preview()
        if byte < 32 or byte == 127:
            byteIter.resetPreview()
            raise DecodeError, 'Invalid Extension-media: TEXT starts with invalid character: %d' % byte
        byte = byteIter.next()
        while byte != 0x00:
            mediaValue += chr(byte)
            byte = byteIter.next()
        return mediaValue


    @staticmethod
    def decodeConstrainedEncoding(byteIter):
        """ Constrained-encoding = Extension-Media  --or--  Short-integer
        This encoding is used for token values, which have no well-known
        binary encoding, or when the assigned number of the well-known
        encoding is small enough to fit into Short-integer.
        
        @return: The decoding constrained-encoding token value
        @rtype: str or int
        """
        result = None
        #backupIter, localIter = itertools.tee(byteIter)
        try:
            #byteIter, localIter = itertools.tee(byteIter)
            # First try and see if this is just a short-integer
            result = Decoder.decodeShortInteger(byteIter)
            #byteIter = localIter
        except DecodeError, msg:
            # Ok, it should be Extension-Media then
            try:
                #backupIter, localIter = itertools.tee(byteIter)
                result = Decoder.decodeExtensionMedia(byteIter)
            except DecodeError, msg:
                # Give up
                #fakeByte =localIter.next()
                #fakeByte= localIter.next()
                #fakeByte = localIter.next()
                #byte = byteIter.next()
                #byte = byteIter.next()
                raise DecodeError, 'Not a valid Constrained-encoding sequence'
        #byteIter = localIter
        return result

    @staticmethod
    def decodeShortLength(byteIter):
        """ From [5], section 8.4.2.2:
        Short-length = <Any octet 0-30>
        
        @raise DecodeError: The byte is not a valid short-length value;
                            it is not in octet range 0-30. In this case, the
                            iterator passed as C{byteIter} is not modified.
        
        @note: If this function returns successfully, the iterator passed as
               C{byteIter} is moved one byte forward.
        
        @return The decoded short-length
        @rtype: int
        """
#        byteIter, localIter = itertools.tee(byteIter)
        # Make sure it's a valid short-length
#        byte = localIter.next()
        byte = byteIter.preview()
        if byte > 30:
            byteIter.resetPreview()
            raise DecodeError, 'Not a valid short-length; should be in octet range 0-30'
        else:
            return byteIter.next()

    @staticmethod
    def decodeValueLength(byteIter):
        """ Decodes the value length indicator starting at the byte pointed to
        by C{byteIter.next()}.
        
        "Value length" is used to indicate the length of a value to follow, as
        used in the C{Content-Type} header in the MMS body, for example.
        
        The encoding for a value length indicator is specified in [5],
        section 8.4.2.2, and follows the form::
        
         Value-length = [Short-length]  --or--  [Length-quote] [Length]
                            ^^^^^^                  ^^^^^^      ^^^^^^
                            1 byte                  1 byte      x bytes
                       <Any octet 0-30>          <Octet 31>   Uintvar-integer
                       
        @raise DecodeError: The ValueLength could not be decoded. If this
                            happens, C{byteIter} is not modified.
        
        @return: The decoded value length indicator
        @rtype: int
        """
        lengthValue = 0      
        # Check for short-length
        try:
            lengthValue = Decoder.decodeShortLength(byteIter)
        except DecodeError:
            byte = byteIter.preview()
            #CHECK: this strictness MAY cause issues, but it is correct
            if byte == 31:
                byteIter.next() # skip past the length-quote
                lengthValue = Decoder.decodeUintvar(byteIter)
            else:
                byteIter.resetPreview()
                raise DecodeError, 'Invalid Value-length: not short-length, and no length-quote present'
        return lengthValue
    
    @staticmethod
    def decodeIntegerValue(byteIter):
        """ From [5], section 8.4.2.3:
        Integer-Value = Short-integer | Long-integer
        
        @raise DecodeError: The sequence of bytes starting at
                            C{byteIter.next()} does not contain a valid
                            integervalue. If this is raised, the iterator
                            passed as C{byteIter} is not modified.
        
        @note: If successful, this function will move the iterator passed as
               C{byteIter} to the last octet in the integer value sequence;
               thus, after calling this, that iterator's C{next()} function
               will return the first byte B{after}the integer value sequence.
        
        @return: The decoded integer value
        @rtype: int
        """
        integer = 0
        # First try and see if it's a short-integer
        try:
            integer = Decoder.decodeShortInteger(byteIter)
        except DecodeError:
            try:
                integer = Decoder.decodeLongInteger(byteIter)
            except DecodeError:
                raise DecodeError, 'Not a valid integer value'
        return integer
    
    @staticmethod
    def decodeContentTypeValue(byteIter):
        """ Decodes an encoded content type value.

        From [5], section 8.4.2.24:
        C{Content-type-value = Constrained-media | Content-general-form}
        
        The short form of the Content-type-value MUST only be used when the
        well-known media is in the range of 0-127 or a text string. In all
        other cases the general form MUST be used.
        
        @return: The media type (content type), and a dictionary of
                 parameters to this content type (which is empty if there
                 are no parameters). This parameter dictionary is in the
                 format:
                 C{{<str:parameter_name>: <str/int/float:parameter_value>}}.
                 The final returned tuple is in the format:
                 (<str:media_type>, <dict:parameter_dict>)
        @rtype: tuple
        """
        # First try do decode it as Constrained-media
        contentType = ''
        parameters = {}
        try:
            contentType = Decoder.decodeConstrainedMedia(byteIter)
        except DecodeError:
            # Try the general form
            contentType, parameters = Decoder.decodeContentGeneralForm(byteIter)
        return (contentType, parameters)


    @staticmethod
    def decodeWellKnownMedia(byteIter):
        """ From [5], section 8.4.2.7:
        Well-known-media = Integer-value
        It is encoded using values from the "Content Type Assignments" table
        (see [5], table 40).
        
        @param byteIter: an iterator over a sequence of bytes
        @type byteIteror: iter
        
        @raise DecodeError: This is raised if the integer value representing
                            the well-known media type cannot be decoded
                            correctly, or the well-known media type value
                            could not be found in the table of assigned
                            content types.
                            If this exception is raised, the iterator passed
                            as C{byteIter} is not modified.
        
        @note: If successful, this function will move the iterator passed as
               C{byteIter} to the last octet in the content type value
               sequence; thus, after calling this, that iterator's C{next()}
               function will return the first byte B{after}the content type
               value sequence.
        
        @return: the decoded MIME content type name
        @rtype: str
        """
#        byteIter, localIter = itertools.tee(byteIter)
        try:
#            wkContentTypeValue = Decoder.decodeIntegerValue(localIter)
            wkContentTypeValue = Decoder.decodeIntegerValue(byteIter)
        except DecodeError:
            raise DecodeError, 'Invalid well-known media: could not read integer value representing it' 
  
        if wkContentTypeValue in range(len(WSPEncodingAssignments.wkContentTypes)):
            decodedContentType = WSPEncodingAssignments.wkContentTypes[wkContentTypeValue]
#            # Only iterate the main iterator now that everything is ok
#            byteIter.next()
        else:
            raise DecodeError, 'Invalid well-known media: could not find content type in table of assigned values'
        return decodedContentType


    @staticmethod
    def decodeMediaType(byteIter):
        """ From [5], section 8.2.4.24:
        Media-type = (Well-known-media | Extension-Media) *(Parameter)
        
        @param byteIter: an iterator over a sequence of bytes
        @type byteIteror: iter
        
        @note: Used by C{decodeContentGeneralForm()}
        
        @return: The decoded media type
        @rtype: str
        """
        try:
            mediaType = Decoder.decodeWellKnownMedia(byteIter)
        except DecodeError:
            mediaType = Decoder.decodeExtensionMedia(byteIter)
        return mediaType

    @staticmethod
    def decodeConstrainedMedia(byteIter):
        """ From [5], section 8.4.2.7:
        Constrained-media = Constrained-encoding
        It is encoded using values from the "Content Type Assignments" table.
        
        @raise DecodeError: Invalid constrained media sequence
        
        @return: The decoded media type
        @rtype: str
        """
        constrainedMedia = ''
        try:
            constrainedMediaValue = Decoder.decodeConstrainedEncoding(byteIter)
        except DecodeError, msg:
            #byte = byteIter.next()
            raise DecodeError, 'Invalid Constrained-media: %s' % msg
        if type(constrainedMediaValue) == int:
            if constrainedMediaValue in range(len(WSPEncodingAssignments.wkContentTypes)):
                constrainedMedia = WSPEncodingAssignments.wkContentTypes[constrainedMediaValue]
            else:
                raise DecodeError, 'Invalid constrained media: could not find well-known content type'
        else:
            constrainedMedia = constrainedMediaValue
        return constrainedMedia

    @staticmethod
    def decodeContentGeneralForm(byteIter):
        """ From [5], section 8.4.2.24:
        Content-general-form = Value-length Media-type
        
        @note Used in decoding Content-type fields and their parameters;
              see C{decodeContentTypeValue}
        
        @note: Used by C{decodeContentTypeValue()}
        
        @return: The media type (content type), and a dictionary of
                 parameters to this content type (which is empty if there
                 are no parameters). This parameter dictionary is in the
                 format:
                 C{{<str:parameter_name>: <str/int/float:parameter_value>}}.
                 The final returned tuple is in the format:
                 (<str:media_type>, <dict:parameter_dict>)
        @rtype: tuple
        """
        # This is the length of the (encoded) media-type and all parameters
        #try:
        valueLength = Decoder.decodeValueLength(byteIter)
        #except DecodeError:
            #CHECK: this is being very leniet, based on real-world tests (specs don't mention this):
        #    valueLength = Decoder.decodeIntegerValue(byteIter)

        # Read parameters, etc, until <valueLength> is reached
        ctFieldBytes = array.array('B')
        for i in range(valueLength):
            ctFieldBytes.append(byteIter.next())
#        contentTypeIter = iter(ctFieldBytes)
        ctIter = PreviewIterator(ctFieldBytes)
        # Now, decode all the bytes read
        mediaType = Decoder.decodeMediaType(ctIter)
        # Decode the included paramaters (if any)
        parameters = {}
        while True:
            try:
                parameter, value = Decoder.decodeParameter(ctIter)
                parameters[parameter] = value
            except StopIteration:
                break
        return (mediaType, parameters)
            
    @staticmethod
    def decodeParameter(byteIter):
        """ From [5], section 8.4.2.4:
        Parameter = Typed-parameter | Untyped-parameter
        
        @return: The name of the parameter, and its value, in the format:
                 (<parameter name>, <parameter value>)
        @rtype: tuple
        """
        try:
            parameter, value = Decoder.decodeTypedParameter(byteIter)
        except DecodeError:
            parameter, value = Decoder.decodeUntypedParameter(byteIter)
        return (parameter, value)

    @staticmethod
    def decodeTypedParameter(byteIter):
        """ From [5], section 8.4.2.4:
        C{Typed-parameter = Well-known-parameter-token Typed-value}
        The actual expected type of the value is implied by the well-known
        parameter.
        
        @note: This is used in decoding parameters; see C{decodeParameter}
        
        @return: The name of the parameter, and its value, in the format:
                 (<parameter name>, <parameter value>)
        @rtype: tuple
        """
        parameterToken, expectedValueType = Decoder.decodeWellKnownParameter(byteIter)
        typedValue = ''
        try:
            # Split the iterator; sometimes the exec call seems to mess up with itertools if this not done here
            # (to replicate: trace the program from here to decodeShortInteger(); the itertools.tee command there
            # doesn't copy the iterator as it should - it creates pointers to the same memory)
            #byteIter, execIter = itertools.tee(byteIter)
            exec 'typedValue = Decoder.decode%s(byteIter)' % expectedValueType
        except DecodeError, msg:
            raise DecodeError, 'Could not decode Typed-parameter: %s' % msg
        except:
            print 'A fatal error occurred, probably due to an unimplemented decoding operation'
            raise
        return (parameterToken, typedValue)
    
    @staticmethod
    def decodeUntypedParameter(byteIter):
        """ From [5], section 8.4.2.4:
        C{Untyped-parameter = Token-text Untyped-value}
        The type of the value is unknown, but it shall be encoded as an
        integer, if that is possible.
        
        @note: This is used in decoding parameters; see C{decodeParameter}
        
        @return: The name of the parameter, and its value, in the format:
                 (<parameter name>, <parameter value>)
        @rtype: tuple 
        """
        parameterToken = Decoder.decodeTokenText(byteIter)
        parameterValue = Decoder.decodeUntypedValue(byteIter)
        return (parameterToken, parameterValue)

    @staticmethod
    def decodeUntypedValue(byteIter):
        """ From [5], section 8.4.2.4:
        Untyped-value = Integer-value | Text-value
        
        @note: This is used in decoding parameter values; see
               C{decodeUntypedParameter}
        @return: The decoded untyped-value
        @rtype: int or str
        """
        try:
            value = Decoder.decodeIntegerValue(byteIter)
        except DecodeError:
            value = Decoder.decodeTextValue(byteIter)
        return value

    @staticmethod
    def decodeWellKnownParameter(byteIter, encodingVersion='1.2'):
        """ Decodes the name and expected value type of a parameter of (for
        example) a "Content-Type" header entry, taking into account the WSP
        short form (assigned numbers) of well-known parameter names, as
        specified in section 8.4.2.4 and table 38 of [5].
        
        From [5], section 8.4.2.4:
        Well-known-parameter-token = Integer-value
        The code values used for parameters are specified in [5], table 38
        
        @raise ValueError: The specified encoding version is invalid.
        
        @raise DecodeError: This is raised if the integer value representing
                            the well-known parameter name cannot be decoded
                            correctly, or the well-known paramter token value
                            could not be found in the table of assigned
                            content types.
                            If this exception is raised, the iterator passed
                            as C{byteIter} is not modified.

        @param encodingVersion: The WSP encoding version to use. This defaults
                                to "1.2", but may be "1.1", "1.2", "1.3" or
                                "1.4" (see table 39 in [5] for details).
        @type encodingVersion: str
        
        @return: the decoded parameter name, and its expected value type, in
                 the format (<parameter name>, <expected type>)
        @rtype: tuple
        """
        decodedParameterName = ''
        expectedValue = ''
#        byteIter, localIter = itertools.tee(byteIter)
        try:
#            wkParameterValue = Decoder.decodeIntegerValue(localIter)
             wkParameterValue = Decoder.decodeIntegerValue(byteIter)
        except DecodeError:
            raise DecodeError, 'Invalid well-known parameter token: could not read integer value representing it'
                
        wkParameters = WSPEncodingAssignments.wellKnownParameters(encodingVersion)
        if wkParameterValue in wkParameters:
            decodedParameterName, expectedValue = wkParameters[wkParameterValue]
            # Only iterate the main iterator now that everything is ok
#            byteIter.next()
        else:
            #If this is reached, the parameter isn't a WSP well-known one
            raise DecodeError, 'Invalid well-known parameter token: could not find in table of assigned numbers (encoding version %s)' % encodingVersion
        return (decodedParameterName, expectedValue)

    #TODO: somehow this should be more dynamic; we need to know what type is EXPECTED (hence the TYPED value)
    @staticmethod
    def decodeTypedValue(byteIter):
        """ From [5], section 8.4.2.4:
        Typed-value = Compact-value | Text-value
        In addition to the expected type, there may be no value.
        If the value cannot be encoded using the expected type, it shall be
        encoded as text.
        
        @note This is used in decoding parameters, see C{decodeParameter()}
        
        @return: The decoded Parameter Typed-value
        @rtype: str
        """
        typedValue = ''
        try:
            typedValue = Decoder.decodeCompactValue(byteIter)
        except DecodeError:
            try:
                typedValue = Decoder.decodeTextValue(byteIter)
            except DecodeError:
                raise DecodeError, 'Could not decode the Parameter Typed-value'
        return typedValue
    
    #TODO: somehow this should be more dynamic; we need to know what type is EXPECTED
    @staticmethod
    def decodeCompactValue(byteIter):
        """ From [5], section 8.4.2.4:
        Compact-value = Integer-value | Date-value | Delta-seconds-value
        | Q-value | Version-value | Uri-value
        
        @raise DecodeError: Failed to decode the Parameter Compact-value;
                            if this happens, C{byteIter} is unmodified

        @note This is used in decoding parameters, see C{decodeTypeValue()}
        """
        compactValue = None
        try:
            # First, see if it's an integer value
            # This solves the checks for: Integer-value, Date-value, Delta-seconds-value, Q-value, Version-value
            compactValue = Decoder.decodeIntegerValue(byteIter)
        except DecodeError:
            try:
                # Try parsing it as a Uri-value
                compactValue = Decoder.decodeUriValue(byteIter)
            except DecodeError:
                raise DecodeError, 'Could not decode Parameter Compact-value'
        return compactValue 

    #TODO: the string output from this should be in the MMS format..?
    @staticmethod
    def decodeDateValue(byteIter):
        """ From [5], section 8.4.2.3:
        Date-value = Long-integer
        The encoding of dates shall be done in number of seconds from
        1970-01-01, 00:00:00 GMT.

        @raise DecodeError: This method uses C{decodeLongInteger}, and thus
                            raises this under the same conditions.

        @return The date, in a format such as: C{Tue Nov 27 16:12:21 2007}
        @rtype: str
        """
        import time
        return time.ctime(Decoder.decodeLongInteger(byteIter))
    
    @staticmethod
    def decodeDeltaSecondsValue(byteIter):
        """ From [5], section 8.4.2.3:
        Delta-seconds-value = Integer-value
        @raise DecodeError: This method uses C{decodeIntegerValue}, and thus
                            raises this under the same conditions.
        @return the decoded delta-seconds-value
        @rtype: int
        """
        return Decoder.decodeIntegerValue(byteIter)

    @staticmethod
    def decodeQValue(byteIter):
        """ From [5], section 8.4.2.1:
        The encoding is the same as in Uintvar-integer, but with restricted
        size. When quality factor 0 and quality factors with one or two
        decimal digits are encoded, they shall be multiplied by 100 and
        incremented by one, so that they encode as a one-octet value in
        range 1-100, ie, 0.1 is encoded as 11 (0x0B) and 0.99 encoded as
        100 (0x64). Three decimal quality factors shall be multiplied with
        1000 and incremented by 100, and the result shall be encoded as a
        one-octet or two-octet uintvar, eg, 0.333 shall be encoded as 0x83 0x31.
        Quality factor 1 is the default value and shall never be sent.
        
        @return: The decode quality factor (Q-value)
        @rtype: float
        """
        qValue = 0.0
        qValueInt = Decoder.decodeUintvar(byteIter)
        #TODO: limit the amount of decimal points
        if qValueInt > 100:
            qValue = float(qValueInt - 100) / 1000.0
        else:
            qValue = float(qValueInt - 1) / 100.0
        return qValue


    @staticmethod
    def decodeVersionValue(byteIter):
        """ Decodes the version-value. From [5], section 8.4.2.3:
        Version-value = Short-integer | Text-string
        
        @return: the decoded version value in the format, usually in the
                 format: "<major_version>.<minor_version>"
        @rtype: str
        """
        version = ''
        try:
            byteValue = Decoder.decodeShortInteger(byteIter)
            major = (byteValue & 0x70) >> 4
            minor = byteValue & 0x0f
            version = '%d.%d' % (major, minor)
        except DecodeError:
            version = Decoder.decodeTextString(byteIter)        
        return version

    @staticmethod
    def decodeUriValue(byteIter):
        """ Stub for Uri-value decoding; this is a wrapper to C{decodeTextString} """
        return Decoder.decodeTextString(byteIter)

    @staticmethod
    def decodeTextValue(byteIter):
        """ Stub for Parameter Text-value decoding.
        From [5], section 8.4.2.3:
        Text-value = No-value | Token-text | Quoted-string
        
        This is used when decoding parameter values; see C{decodeTypedValue()}
        
        @return: The decoded Parameter Text-value
        @rtype: str
        """
        textValue = ''
        try:
            textValue = Decoder.decodeTokenText(byteIter)
        except DecodeError:
            try:
                textValue = Decoder.decodeQuotedString(byteIter)
            except DecodeError:
                # Ok, so it's a "No-value"
                pass
        return textValue

    @staticmethod
    def decodeNoValue(byteIter):
        """ Basically verifies that the byte pointed to by C{byteIter.next()}
        is 0x00.
        
        @note: If successful, this function will move C{byteIter} one byte
               forward.
        
        @raise DecodeError: If 0x00 is not found; C{byteIter} is not modified
                            if this is raised.
        
        @return: No-value, which is 0x00
        @rtype: int
        """
        byteIter, localIter = byteIter.next()
        if localIter.next() != 0x00:
            raise DecodeError, 'Expected No-value'
        else:
            byteIter.next()
        return 0x00
    
    @staticmethod
    def decodeAcceptValue(byteIter):
        """ From [5], section 8.4.2.7:
        Accept-value = Constrained-media | Accept-general-form
        Accept-general-form = Value-length Media-range [Accept-parameters]
        Media-range = (Well-known-media | Extension-Media) *(Parameter)
        Accept-parameters = Q-token Q-value *(Accept-extension)
        Accept-extension = Parameter
        Q-token = <Octet 128>

        @note: most of these things are currently decoded, but discarded (e.g
               accept-parameters); we only return the media type

        @raise DecodeError: The decoding failed. C{byteIter} will not be
                            modified in this case.
        @return the decoded Accept-value (media/content type)
        @rtype: str
        """
        acceptValue = ''
        # Try to use Constrained-media encoding
        try:
            acceptValue = Decoder.decodeConstrainedMedia(byteIter)
        except DecodeError:
            # ...now try Accept-general-form
            valueLength = Decoder.decodeValueLength(byteIter)
            try:
                media = Decoder.decodeWellKnownMedia(byteIter)
            except DecodeError:
                media = Decoder.decodeExtensionMedia(byteIter)
            # Check for the Q-Token (to see if there are Accept-parameters)
            if byteIter.preview() == 128:
                byteIter.next()
                qValue = Decoder.decodeQValue(byteIter)
                try:
                    acceptExtension = Decoder.decodeParameter(byteIter)
                except DecodeError:
                    # Just set an empty iterable
                    acceptExtension = []
            byteIter.resetPreview()
            acceptValue = media
        return acceptValue
    
    @staticmethod
    def decodePragmaValue(byteIter):
        """ Defined in [5], section 8.4.2.38:
        
            Pragma-value = No-cache | (Value-length Parameter)
        
        From [5], section 8.4.2.15:
        
            No-cache = <Octet 128> 
        
        @raise DecodeError: The decoding failed. C{byteIter} will not be
                            modified in this case.
        @return: the decoded Pragma-value, in the format:
                 (<parameter name>, <parameter value>)
        @rtype: tuple
        """
        byte = byteIter.preview()
        if byte == 0x80: # No-cache
            byteIter.next()
            #TODO: Not sure if this parameter name (or even usage) is correct
            parameterName = 'Cache-control'
            parameterValue = 'No-cache'
        else:
            byteIter.resetPreview()
            valueLength = Decoder.decodeValueLength(byteIter)
            parameterName, parameterValue = Decoder.decodeParameter(byteIter)
        return parameterName, parameterValue
    
    @staticmethod
    def decodeWellKnownCharset(byteIter):
        """ From [5], section 8.4.2.8:
        C{Well-known-charset = Any-charset | Integer-value}
        It is encoded using values from "Character Set Assignments" table.
        C{Any-charset = <Octet 128>}
        Equivalent to the special RFC2616 charset value "*"
        """
        decodedCharSet = ''
        # Look for the Any-charset value
        byte = byteIter.preview()
        byteIter.resetPreview()
        if byte == 127:
            byteIter.next()
            decodcedCharSet = '*'
        else:
            charSetValue = Decoder.decodeIntegerValue(byteIter)
            if charSetValue in WSPEncodingAssignments.wkCharSets:
                decodedCharSet = WSPEncodingAssignments.wkCharSets[charSetValue]
            else:
                # This charset is not in our table... so just use the value (at least for now)
                decodedCharSet = str(charSetValue)
        return decodedCharSet

    @staticmethod
    def decodeWellKnownHeader(byteIter):
        """ From [5], section 8.4.2.6:
        C{Well-known-header = Well-known-field-name Wap-value}
        C{Well-known-field-name = Short-integer}
        C{Wap-value = <many different headers value, most not implemented>}
        
        @todo: Currently, "Wap-value" is decoded as a Text-string in most cases
        
        @return: The header name, and its value, in the format:
                 (<str:header_name>, <str:header_value>)
        @rtype: tuple
        """
        decodedHeaderFieldName = ''
        hdrFieldValue = Decoder.decodeShortInteger(byteIter)
        hdrFields = WSPEncodingAssignments.headerFieldNames()
        #TODO: *technically* this can fail, but then we have already read a byte... should fix?
        if hdrFieldValue in range(len(hdrFields)):
            decodedHeaderFieldName = hdrFields[hdrFieldValue]
        else:
            raise DecodeError, 'Invalid Header Field value: %d' % hdrFieldValue
        #TODO: make this flow better, and implement it in decodeApplicationHeader also
        # Currently we decode most headers as TextStrings, except where we have a specific decoding algorithm implemented
        if decodedHeaderFieldName in WSPEncodingAssignments.hdrFieldEncodings:
            wapValueType = WSPEncodingAssignments.hdrFieldEncodings[decodedHeaderFieldName]
            try:
                exec 'decodedValue = Decoder.decode%s(byteIter)' % wapValueType
            except DecodeError, msg:
                raise DecodeError, 'Could not decode Wap-value: %s' % msg
            except:
                print 'An error occurred, probably due to an unimplemented decoding operation. Tried to decode header: %s' % decodedHeaderFieldName
                raise
        else:
            decodedValue = Decoder.decodeTextString(byteIter)
        return (decodedHeaderFieldName, decodedValue)

    @staticmethod
    def decodeApplicationHeader(byteIter):
        """ From [5], section 8.4.2.6:
        C{Application-header = Token-text Application-specific-value}
        
        From [4], section 7.1:
        C{Application-header = Token-text Application-specific-value}
        C{Application-specific-value = Text-string}
        
        @note: This is used when decoding generic WSP headers;
               see C{decodeHeader()}.
        @note: We follow [4], and decode the "Application-specific-value"
               as a Text-string
        
        @return: The application-header, and its value, in the format:
                 (<str:application_header>, <str:application_specific_value>)
        @rtype: tuple
        """
        try:
            appHeader = Decoder.decodeTokenText(byteIter)
        #FNA: added for brute-forcing
        except DecodeError:
            appHeader = Decoder.decodeTextString(byteIter)
        appSpecificValue = Decoder.decodeTextString(byteIter)
        return (appHeader, appSpecificValue)
    
    @staticmethod
    def decodeHeader(byteIter):
        """ Decodes a WSP header entry
        
        From [5], section 8.4.2.6:
        C{Header = Message-header | Shift-sequence}
        C{Message-header = Well-known-header | Application-header}
        C{Well-known-header = Well-known-field-name Wap-value}
        C{Application-header = Token-text Application-specific-value}

        @note: "Shift-sequence" encoding has not been implemented
        @note: Currently, almost all header values are treated as text-strings

        @return: The decoded headername, and its value, in the format:
                 (<str:header_name>, <str:header_value>)
        @rtype: tuple
        """
        header = ''
        value = ''
        # First try decoding the header as a well-known-header
        try:
            header, value = Decoder.decodeWellKnownHeader(byteIter)
        except DecodeError:
            # ...now try Application-header encoding
            header, value = Decoder.decodeApplicationHeader(byteIter)
        return (header, value)


class Encoder:
    """ A WSP Data unit decoder """
    
    #@staticmethod
    #def encodeUint8(uint):
    #    """ Encodes an 8-bit unsigned integer
    #
    #    @param uint: The integer to encode
    #    @type byteIteror: int
    #    
    #    @return: the encoded Uint8, as a sequence of bytes
    #    @rtype: list
    #    """
    #    # Make the byte unsigned
    #    return [uint & 0xff]
    
    
    @staticmethod
    def encodeUintvar(uint):
        """ Variable Length Unsigned Integer encoding algorithm
        
        This binary-encodes the given unsigned integer number as specified
        in section 8.1.2 of [5]. Basically, each encoded byte has the
        following structure::
        
            [0][ Payload ]
             |   ^^^^^^^
             |   7 bits (actual data)
             |
            Continue bit
        
        The uint is split into 7-bit segments, and the "continue bit" of each
        used octet is set to '1' to indicate more is to follow; the last used
        octet's "continue bit" is set to 0.
        
        @return: the binary-encoded Uintvar, as a list of byte values
        @rtype: list
        """
        uintVar = []
        # Since this is the lowest entry, we do not set the continue bit to 1
        uintVar.append(uint & 0x7f) 
        uint = uint >> 7
        # ...but for the remaining octets, we have to
        while uint > 0:
            uintVar.insert(0, 0x80 | (uint & 0x7f))
            uint = uint >> 7
        return uintVar
    
    @staticmethod
    def encodeTextString(string):
        """ Encodes a "Text-string" value.
        
        This follows the basic encoding rules specified in [5], section
        8.4.2.1

        @param string: The text string to encode
        @type string: str
        
        @return: the null-terminated, binary-encoded version of the
                     specified Text-string, as a list of byte values
        @rtype: list
        """
        encodedString = []
        for char in string:
            encodedString.append(ord(char))
        encodedString.append(0x00)
        return encodedString
    
    @staticmethod
    def encodeShortInteger(integer):
        """ Encodes the specified short-integer value
        
        The encoding for a long integer is specified in [5], section 8.4.2.1:
            C{Short-integer = OCTET}
            Integers in range 0-127 shall be encoded as a one octet value with
            the most significant bit set to one (1xxx xxxx) and with the value
            in the remaining least significant bits.
        
        @param Integer: The short-integer value to encode
        @type Integer: int
        
        @raise EncodeError: Not a valid short-integer; the integer must be in
                            the range of 0-127
        
        @return: The encoded short integer, as a list of byte values
        @rtype: list
        """
        if integer < 0 or integer > 127:
            raise EncodeError, 'Short-integer value must be in range 0-127: %d' % integer
        encodedInteger = []
        # Make sure the most significant bit is set
        byte = 0x80 | integer
        encodedInteger.append(byte)
        return encodedInteger
    
    @staticmethod
    def encodeLongInteger(integer):
        """ Encodes a Long-integer value 
        
        The encoding for a long integer is specified in [5], section 8.4.2.1;
        for a description of this encoding scheme, see
        C{wsp.Decoder.decodeLongIntger()}.
        
        Basically:      
        From [5], section 8.4.2.2:
        Long-integer = Short-length Multi-octet-integer
        Short-length = <Any octet 0-30>
        
        @raise EncodeError: <integer> is not of type "int"
        
        @param integer: The integer value to encode
        @type integer: int
        
        @return: The encoded Long-integer, as a sequence of byte values
        @rtype: list
        """
        if type(integer) != int:
            raise EncodeError, '<integer> must be of type "int"'
        encodedLongInt = []
        longInt = integer
        # Encode the Multi-octect-integer
        while longInt > 0:
            byte = 0xff & longInt
            encodedLongInt.append(byte)
            longInt = longInt >> 8
        # Now add the SHort-length value, and make sure it's ok
        shortLength = len(encodedLongInt)
        if shortLength > 30:
            raise EncodeError, 'Cannot encode Long-integer value: Short-length is too long; should be in octet range 0-30'
        encodedLongInt.insert(0, shortLength)       
        return encodedLongInt

    @staticmethod
    def encodeVersionValue(version):
        """ Encodes the version-value. From [5], section 8.4.2.3:
        Version-value = Short-integer | Text-string
        
        Example: An MMS version of "1.0" consists of a major version of 1 and a
        minor version of 0, and would be encoded as 0x90. However, a version
        of "1.2.4" would be encoded as the Text-string "1.2.4".
        
        @param version: The version number to encode, e.g. "1.0"
        @type version: str
        
        @raise TypeError: The specified version value was not of type C{str}
        
        @return: the encoded version value, as a list of byte values
        @rtype: list
        """
        if type(version) != str:
            raise TypeError, 'Parameter must be of type "str"'
        encodedVersionValue = []
        # First try short-integer encoding
        try:
            if len(version.split('.')) <= 2:
                majorVersion = int(version.split('.')[0])
                if majorVersion < 1 or majorVersion > 7:
                    raise ValueError, 'Major version must be in range 1-7'
                major = majorVersion << 4                            
                if len(version.split('.')) == 2:
                    minorVersion = int(version.split('.')[1])
                    if minorVersion < 0 or minorVersion > 14:
                        raise ValueError, 'Minor version must be in range 0-14'
                else:
                    minorVersion = 15
                minor = minorVersion
                encodedVersionValue = Encoder.encodeShortInteger(major|minor)
        except:
            # The value couldn't be encoded as a short-integer; use a text-string instead
            encodedVersionValue = Encoder.encodeTextString(version)
        return encodedVersionValue

    @staticmethod
    def encodeMediaType(contentType):
        """ Encodes the specified MIME content type ("Media-type" value)
        
        From [5], section 8.2.4.24:
        Media-type = (Well-known-media | Extension-Media) *(Parameter)
        
        "Well-known-media" takes into account the WSP short form of well-known
        content types, as specified in section 8.4.2.24 and table 40 of [5].
        
        @param contentType: The MIME content type to encode
        @type contentType: str
        
        @return: The binary-encoded content type, as a list of (integer) byte
                 values
        @rtype: list
        """
        encodedContentType = []
        if contentType in WSPEncodingAssignments.wkContentTypes:
            # Short-integer encoding
            encodedContentType.extend(Encoder.encodeShortInteger(WSPEncodingAssignments.wkContentTypes.index(contentType)))
        else:
            encodedContentType.extend(Encoder.encodeTextString(contentType))
        return encodedContentType

    @staticmethod
    def encodeParameter(parameterName, parameterValue, encodingVersion='1.2'):
        """ Binary-encodes the name of a parameter of (for example) a
        "Content-Type" header entry, taking into account the WSP short form of
        well-known parameter names, as specified in section 8.4.2.4 and table
        38 of [5].
        
        From [5], section 8.4.2.4:
        C{Parameter = Typed-parameter | Untyped-parameter}
        C{Typed-parameter = Well-known-parameter-token Typed-value}
        C{Untyped-parameter = Token-text Untyped-value}
        C{Untyped-value = Integer-value | Text-value}

        @param parameterName: The name of the parameter to encode
        @type parameterName: str
        @param parameterValue: The value of the parameter
        @type parameterValue: str or int
        
        @param encodingVersion: The WSP encoding version to use. This defaults
                                to "1.2", but may be "1.1", "1.2", "1.3" or
                                "1.4" (see table 38 in [5] for details).
        @type encodingVersion: str
        
        @raise ValueError: The specified encoding version is invalid.
        
        @return: The binary-encoded parameter name, as a list of (integer)
                 byte values
        @rtype: list
        """
        wkParameters = WSPEncodingAssignments.wellKnownParameters(encodingVersion)
        encodedParameter = []
        # Try to encode the parameter using a "Typed-parameter" value
        wkParamNumbers = wkParameters.keys().sort(reverse=True)
        for assignedNumber in wkParamNumbers:
            if wkParameters[assignedNumber][0] == parameterName:
                # Ok, it's a Typed-parameter; encode the parameter name
                encodedParameter.extend(Encoder.encodeShortInteger(assignedNumber))
                # ...and now the value
                expectedType = wkParameters[assignedNumber][1]
                try:
                    exec 'encodedParameter.extend(Encoder.encode%s(parameterValue))' % expectedType
                except EncodeError, msg:
                    raise EncodeError, 'Error encoding parameter value: %s' % msg
                except:
                    print 'A fatal error occurred, probably due to an unimplemented encoding operation'
                    raise
                break
        # See if the "Typed-parameter" encoding worked
        if len(encodedParameter) == 0:
            # ...it didn't. Use "Untyped-parameter" encoding
            encodedParameter.extend(Encoder.encodeTokenText(parameterName))
            value = []
            # First try to encode the untyped-value as an integer
            try:
                value = Encoder.encodeIntegerValue(parameterValue)
            except EncodeError:
                value = Encoder.encodeTextString(parameterValue)
            encodedParameter.extend(value)
        return encodedParameter    

    #TODO: check up on the encoding/decoding of Token-text, in particular, how does this differ from text-string? does it have 0x00 at the end?
    @staticmethod
    def encodeTokenText(text):
        """ From [5], section 8.4.2.1:
        Token-text = Token End-of-string
        
        @raise EncodeError: Specified text cannot be encoding as a token
                 
        @return: The encoded token string, as a list of byte values
        @rtype: list
        """
        separators = (11, 32, 40, 41, 44, 47, 58, 59, 60, 61, 62, 63, 64, 91,
                      92, 93, 123, 125)
        # Sanity check
        for char in separators:
            if chr(char) in text:
                raise EncodeError, 'Char "%s" in text string; cannot encode as Token-text' % chr(char)
        encodedToken = Encoder.encodeTextString(text)
        return encodedToken

    @staticmethod
    def encodeIntegerValue(integer):
        """ Encodes an integer value
        
        From [5], section 8.4.2.3:
        Integer-Value = Short-integer | Long-integer
        
        This function will first try to encode the specified integer value
        into a short-integer, and failing that, will encode into a
        long-integer value.
        
        @param integer: The integer to encode
        @type integer: int
        
        @raise EncodeError: The <integer> parameter is not of type C{int}
        
        @return: The encoded integer value, as a list of byte values
        @rtype: list
        """
        if type(integer) != int:
            raise EncodeError, '<integer> must be of type "int"'
        encodedInteger = []
        # First try and see if it's a short-integer
        try:
            encodedInteger = Encoder.encodeShortInteger(integer)
        except EncodeError:
            encodedInteger = Encoder.encodeLongInteger(integer)
        return encodedInteger

    @staticmethod
    def encodeTextValue(text):
        """ Stub for encoding Text-values; this is equivalent to
        C{encodeTextString} """
        return Encoder.encodeTextString(text)

    @staticmethod
    def encodeNoValue(value=None):
        """ Encodes a No-value, which is 0x00
        
        @note: This function mainly exists for use by automatically-selected
               encoding routines (see C{encodeParameter()} for an example.
        
        @param value: This value is ignored; it is present so that this
                      method complies with the format of the other C{encode}
                      methods.
        
        @return: A list containing a single "No-value", which is 0x00
        @rtype: list
        """
        return [0x00]
 
    @staticmethod
    def encodeHeader(headerFieldName, headerValue):
        """ Encodes a WSP header entry, and its value
        
        From [5], section 8.4.2.6:
        C{Header = Message-header | Shift-sequence}
        C{Message-header = Well-known-header | Application-header}
        C{Well-known-header = Well-known-field-name Wap-value}
        C{Application-header = Token-text Application-specific-value}

        @note: "Shift-sequence" encoding has not been implemented
        @note: Currently, almost all header values are encoded as text-strings

        @return: The encoded header, and its value, as a sequence of byte
                 values
        @rtype: list
        """
        encodedHeader = []
        # First try encoding the header name as a "well-known-header"...
        wkHdrFields = WSPEncodingAssignments.headerFieldNames()
        if headerFieldName in wkHdrFields:
            headerFieldValue = Encoder.encodeShortInteger(wkHdrFields.index(headerFieldName))
            encodedHeader.extend(headerFieldValue)
        else:
            # ...otherwise, encode it as an "application header"
            encodedHeaderName = Encoder.encodeTokenText(headerFieldName)
            encodedHeader.extend(encodedHeaderName)
        # Now add the value
        #TODO: make this flow better (see also Decoder.decodeHeader)
        # most header values are encoded as TextStrings, except where we have a specific Wap-value encoding implementation
        if headerFieldName in WSPEncodingAssignments.hdrFieldEncodings:
            wapValueType = WSPEncodingAssignments.hdrFieldEncodings[headerFieldName]
            try:
                exec 'encodedHeader.extend(Encoder.encode%s(headerValue))' % wapValueType
            except EncodeError, msg:
                raise EncodeError, 'Error encoding Wap-value: %s' % msg
            except:
                print 'A fatal error occurred, probably due to an unimplemented encoding operation'
                raise
        else:
            encodedHeader.extend(Encoder.encodeTextString(headerValue))
        return encodedHeader
    
    @staticmethod
    def encodeContentTypeValue(mediaType, parameters):
        """ Encodes a content type, and its parameters

        From [5], section 8.4.2.24:
        C{Content-type-value = Constrained-media | Content-general-form}
        
        The short form of the Content-type-value MUST only be used when the
        well-known media is in the range of 0-127 or a text string. In all
        other cases the general form MUST be used.
        
        @return: The encoded Content-type-value (including parameters, if
                 any), as a sequence of bytes
        @rtype: list
        """
        encodedContentTypeValue = []
        # First try do encode it using Constrained-media encoding
        try:
            if len(parameters) > 0:
                raise EncodeError, 'Need to use Content-general-form for parameters'
            else:
                encodedContentTypeValue = Encoder.encodeConstrainedMedia(mediaType)
        except EncodeError:
            # Try the general form
            encodedContentTypeValue = Encoder.encodeContentGeneralForm(mediaType, parameters)
        return encodedContentTypeValue
    
    @staticmethod
    def encodeConstrainedMedia(mediaType):
        """ From [5], section 8.4.2.7:
        Constrained-media = Constrained-encoding
        It is encoded using values from the "Content Type Assignments" table.
        
        @param mediaType: The media type to encode
        @type mediaType: str
        
        @raise EncodeError: Media value is unsuitable for Constrained-encoding
        
        @return: The encoded media type, as a sequence of bytes
        @rtype: list
        """
        encodedMediaType = []
        mediaValue = ''
        # See if this value is in the table of well-known content types
        if mediaType in WSPEncodingAssignments.wkContentTypes:
            mediaValue = WSPEncodingAssignments.wkContentTypes.index(mediaType)
        else:
            mediaValue = mediaType
        encodedMediaType = Encoder.encodeConstrainedEncoding(mediaValue)    
        return encodedMediaType

    @staticmethod
    def encodeConstrainedEncoding(value):
        """ Constrained-encoding = Extension-Media  --or--  Short-integer
        This encoding is used for token values, which have no well-known
        binary encoding, or when the assigned number of the well-known
        encoding is small enough to fit into Short-integer.
        
        @param value: The value to encode
        @type value: int or str
        
        @raise EncodeError: <value> cannot be encoded as a
                            Constrained-encoding sequence
        
        @return: The encoded constrained-encoding token value, as a sequence
                 of bytes
        @rtype: list
        """
        encodedValue = None
        if type(value) == int:
            # First try and encode the value as a short-integer
            encodedValue = Encoder.encodeShortInteger(value)
        else:
            # Ok, it should be Extension-Media then
            try:
                encodedValue = Encoder.encodeExtensionMedia(value)
            except EncodeError:
                # Give up
                raise EncodeError, 'Cannot encode %s as a Constrained-encoding sequence' % str(value)
        return encodedValue

    @staticmethod
    def encodeExtensionMedia(mediaValue):
        """ From [5], section 8.4.2.1:
        Extension-media = *TEXT End-of-string
        This encoding is used for media values, which have no well-known
        binary encoding
        
        @param mediaValue: The media value (string) to encode
        @type mediaValue: str
        
        @raise EncodeError: The value cannot be encoded as TEXT; probably it 
                            starts with/contains an invalid character
        
        @return: The encoded media type value, as a sequence of bytes
        @rtype: str
        """
        encodedMediaValue = ''
        if type(mediaValue) != str:
            try:
                mediaValue = str(mediaValue)
            except:
                raise EncodeError, 'Invalid Extension-media: Cannot convert value to text string'    
        char = mediaValue[0]
        if ord(char) < 32 or ord(char) == 127:
            raise EncodeError, 'Invalid Extension-media: TEXT starts with invalid character: %s' % ord(char)
        encodedMediaValue = Encoder.encodeTextString(mediaValue)
        return encodedMediaValue

    @staticmethod
    def encodeContentGeneralForm(mediaType, parameters):
        """ From [5], section 8.4.2.24:
        Content-general-form = Value-length Media-type
        
        @note Used in decoding Content-type fields and their parameters;
              see C{decodeContentTypeValue}
        
        @note: Used by C{decodeContentTypeValue()}
        
        @return: The encoded Content-general-form, as a sequence of bytes
        @rtype: list
        """
        encodedContentGeneralForm = []
        encodedMediaType = []
        encodedParameters = []
        # Encode the actual content type
        encodedMediaType = Encoder.encodeMediaType(mediaType)
        # Encode all parameters
        for paramName in parameters:
            encodedParameters.extend(Encoder.encodeParameter(paramName, parameters[paramName]))
        valueLength = len(encodedMediaType) + len(encodedParameters)
        encodedValueLength = Encoder.encodeValueLength(valueLength)
        encodedContentGeneralForm.extend(encodedValueLength)
        encodedContentGeneralForm.extend(encodedMediaType)
        encodedContentGeneralForm.extend(encodedParameters)
        return encodedContentGeneralForm

    @staticmethod
    def encodeValueLength(length):
        """ Encodes the specified length value as a value length indicator
        
        "Value length" is used to indicate the length of a value to follow, as
        used in the C{Content-Type} header in the MMS body, for example.
        
        The encoding for a value length indicator is specified in [5],
        section 8.4.2.2, and follows the form::
        
         Value-length = [Short-length]  --or--  [Length-quote] [Length]
                            ^^^^^^                  ^^^^^^      ^^^^^^
                            1 byte                  1 byte      x bytes
                       <Any octet 0-30>          <Octet 31>   Uintvar-integer
                       
        @raise EncodeError: The ValueLength could not be encoded.
        
        @return: The encoded value length indicator, as a sequence of bytes
        @rtype: list
        """
        encodedValueLength = []
        # Try and encode it as a short-length
        try:
            encodedValueLength = Encoder.encodeShortLength(length)
        except EncodeError:
            # Encode it with a Length-quote and Uintvar
            encodedValueLength.append(31) # Length-quote
            encodedValueLength.extend(Encoder.encodeUintvar(length))
        return encodedValueLength

    @staticmethod
    def encodeShortLength(length):
        """ From [5], section 8.4.2.2:
        Short-length = <Any octet 0-30>
        
        @raise EmcodeError: The specified <length> cannot be encoded as a
                            short-length value; it is not in octet range 0-30.
        
        @return The encoded short-length, as a sequence of bytes
        @rtype: list
        """
        if length < 0 or length > 30:
            raise EncodeError, 'Cannot encode short-length; length should be in range 0-30'
        else:
            return [length]

    @staticmethod
    def encodeAcceptValue(acceptValue):
        """ From [5], section 8.4.2.7:
        Accept-value = Constrained-media | Accept-general-form
        Accept-general-form = Value-length Media-range [Accept-parameters]
        Media-range = (Well-known-media | Extension-Media) *(Parameter)
        Accept-parameters = Q-token Q-value *(Accept-extension)
        Accept-extension = Parameter
        Q-token = <Octet 128>

        @note: This implementation does not currently support encoding of
               "Accept-parameters".
               
        @param acceptValue: The Accept-value to encode (media/content type)
        @type acceptValue: str

        @raise EncodeError: The encoding failed.

        @return The encoded Accept-value, as a sequence of bytes
        @rtype: list
        """
        encodedAcceptValue = []
        # Try to use Constrained-media encoding
        try:
            encodedAcceptValue = Encoder.encodeConstrainedMedia(acceptValue)
        except EncodeError:
            # ...now try Accept-general-form
            try:
                encodedMediaRange = Encoder.encodeMediaType(acceptValue)
            except EncodeError, msg:
                raise EncodeError, 'Cannot encode Accept-value: %s' % msg
            valueLength = Encoder.encodeValueLength(len(encodedMediaRange))
            encodedAcceptValue = valueLength
            encodedAcceptValue.extend(encodedMediaRange)
        return encodedAcceptValue
