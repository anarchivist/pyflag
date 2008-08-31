#!/usr/bin/env python
#
# This library is free software, distributed under the terms of
# the GNU Lesser General Public License Version 2.
# See the COPYING file included in this archive
#
# The docstrings in this module contain epytext markup; API documentation
# may be created by processing this file with epydoc: http://epydoc.sf.net

""" High-level MMS-message creation/manipulation classes """

import xml.dom.minidom
import os
import mimetypes
import array

class MMSMessage:
    """ An MMS message
    
    @note: References used in this class: [1][2][3][4][5]
    """
    def __init__(self):
        self._pages = []
        self._dataParts = []
        self._metaTags = {}
        self.headers = {'Message-Type' : 'm-send-req',
                        'Transaction-Id' : '1234',
                        'MMS-Version' : '1.0',
                        'Content-Type' : ('application/vnd.wap.multipart.mixed', {})}
        self.width = 176
        self.height = 220
        self.transactionID = '12345'
        self.subject = 'test'
        
    # contentType property
    @property
    def contentType(self):
        """ Returns the string representation of this data part's
        "Content-Type" header. No parameter information is returned;
        to get that, access the "Content-Type" header directly (which has a
        tuple value)from the message's C{headers} attribute.
        
        This is equivalent to calling DataPart.headers['Content-Type'][0]
        """
        return self.headers['Content-Type'][0]

    def addPage(self, page):
        """ Adds a single page/slide (MMSMessagePage object) to the message 
        
        @param page: The message slide/page to add
        @type page: MMSMessagPage
        """
        if self.contentType != 'application/vnd.wap.multipart.related':
            self.headers['Content-Type'] = ('application/vnd.wap.multipart.related', {})
        self._pages.append(page)
    
    @property
    def pages(self):
        """ Returns a list of all the pages in this message """
        return self._pages
        
    def addDataPart(self, dataPart):
        """ Adds a single data part (DataPart object) to the message, without
        connecting it to a specific slide/page in the message.
        
        A data part encapsulates some form of attachment, e.g. an image, audio
        etc.
        
        @param dataPart: The data part to add
        @type dataPart: DataPart
        
        @note: It is not necessary to explicitly add data parts to the message
               using this function if "addPage" is used; this method is mainly
               useful if you want to create MMS messages without SMIL support,
               i.e. messages of type "application/vnd.wap.multipart.mixed"
        """
        self._dataParts.append(dataPart)
    
    @property
    def dataParts(self):
        """ Returns a list of all the data parts in this message, including
        data parts that were added to slides in this message """
        parts = []
        if len(self._pages) > 0:
            parts.append(self.smil())        
            for slide in self._mmsMessage._pages:
                parts.extend(slide.dataParts())
        parts.extend(self._dataParts)
        return parts
        
    
    def smil(self):
        """ Returns the text of the message's SMIL file """
        impl = xml.dom.minidom.getDOMImplementation()
        smilDoc = impl.createDocument(None, "smil", None)
  
        # Create the SMIL header
        headNode = smilDoc.createElement('head')
        # Add metadata to header
        for tagName in self._metaTags:
            metaNode = smilDoc.createElement('meta')
            metaNode.setAttribute(tagName, self._metaTags[tagName])
            headNode.appendChild(metaNode)
        # Add layout info to header
        layoutNode = smilDoc.createElement('layout')
        rootLayoutNode = smilDoc.createElement('root-layout')
        rootLayoutNode.setAttribute('width', str(self.width))
        rootLayoutNode.setAttribute('height', str(self.height))
        layoutNode.appendChild(rootLayoutNode)
        for regionID, left, top, width, height in (('Image', '0', '0', '176', '144'), ('Text', '176', '144', '176', '76')):
            regionNode = smilDoc.createElement('region')
            regionNode.setAttribute('id', regionID)
            regionNode.setAttribute('left', left)
            regionNode.setAttribute('top', top)
            regionNode.setAttribute('width', width)
            regionNode.setAttribute('height', height)
            layoutNode.appendChild(regionNode)
        headNode.appendChild(layoutNode)
        smilDoc.documentElement.appendChild(headNode)
        
        # Create the SMIL body
        bodyNode = smilDoc.createElement('body')
        # Add pages to body
        for page in self._pages:
            parNode = smilDoc.createElement('par')
            parNode.setAttribute('duration', str(page.duration))
            # Add the page content information
            if page.image != None:
                #TODO: catch unpack exception
                part, begin, end = page.image
                if 'Content-Location' in part.headers:
                    src = part.headers['Content-Location']
                elif 'Content-ID' in part.headers:
                    src = part.headers['Content-ID']
                else:
                    src = part.data
                imageNode = smilDoc.createElement('img')
                imageNode.setAttribute('src', src)
                imageNode.setAttribute('region', 'Image')
                if begin > 0 or end > 0:
                    if end > page.duration:
                        end = page.duration
                    imageNode.setAttribute('begin', str(begin))
                    imageNode.setAttribute('end', str(end))
                parNode.appendChild(imageNode)
            if page.text != None:
                part, begin, end = page.text
                src = part.data
                textNode = smilDoc.createElement('text')
                textNode.setAttribute('src', src)
                textNode.setAttribute('region', 'Text')
                if begin > 0 or end > 0:
                    if end > page.duration:
                        end = page.duration
                    textNode.setAttribute('begin', str(begin))
                    textNode.setAttribute('end', str(end))
                parNode.appendChild(textNode)
            if page.audio != None:
                part, begin, end = page.audio
                if 'Content-Location' in part.headers:
                    src = part.headers['Content-Location']
                elif 'Content-ID' in part.headers:
                    src = part.headers['Content-ID']
                else:
                    src = part.data
                audioNode = smilDoc.createElement('audio')
                audioNode.setAttribute('src', src)
                if begin > 0 or end > 0:
                    if end > page.duration:
                        end = page.duration
                    audioNode.setAttribute('begin', str(begin)) 
                    audioNode.setAttribute('end', str(end))
                parNode.appendChild(textNode)
                parNode.appendChild(audioNode)
            bodyNode.appendChild(parNode)
        smilDoc.documentElement.appendChild(bodyNode)
        
        return smilDoc.documentElement.toprettyxml()


    def encode(self):
        """ Convenience funtion that binary-encodes this MMS message
        
        @note: This uses the C{mms_pdu.MMSEncoder} class internally
        
        @return: The binary-encode MMS data, as an array of bytes
        @rtype array.array('B')
        """
        import mms_pdu
        encoder = mms_pdu.MMSEncoder()
        return encoder.encode(self)


    def toFile(self, filename):
        """ Convenience funtion that writes this MMS message to disk in 
        binary-encoded form.
        
        @param filename: The name of the file in which to store the message
                         data
        @type filename: str
    
        @note: This uses the C{mms_pdu.MMSEncoder} class internally
        
        @return: The binary-encode MMS data, as an array of bytes
        @rtype array.array('B')
        """
        f = open(filename, 'wb')
        self.encode().tofile(f)
        f.close()
    
    @staticmethod
    def fromFile(filename):
        """ Convenience static funtion that loads the specified MMS message
        file from disk, decodes its data, and returns a new MMSMessage object,
        which can then be manipulated and re-encoded, for instance.
        
        @param filename: The name of the file to load
        @type filename: str
    
        @note: This uses the C{mms_pdu.MMSDecoder} class internally
        """
        import mms_pdu
        decoder = mms_pdu.MMSDecoder()
        return decoder.decodeFile(filename)


class MMSMessagePage:
    """ A single page (or "slide") in an MMS Message. 
    
    In order to ensure that the MMS message can be correctly displayed by most
    terminals, each page's content is limited to having 1 image, 1 audio clip
    and 1 block of text, as stated in [1].
    
    @note: The default slide duration is set to 4 seconds; use setDuration()
           to change this.
    
    @note: References used in this class: [1]
    """
    def __init__(self):
        self.duration = 4000
        self.image = None
        self.audio = None
        self.text = None
    
    @property
    def dataParts(self):
        """ Returns a list of the data parst in this slide """
        parts = []
        for part in (self.image, self.audio, self.text):
            if part != None:
                parts.append(part)
        return parts

    def numberOfParts(self):
        """ This function calculates the amount of data "parts" (or elements)
        in this slide.
            
        @return: The number of data parts in this slide
        @rtype: int
        """
        numParts = 0
        for item in (self.image, self.audio, self.text):
            if item != None:
                numParts += 1
        return numParts
        
    #TODO: find out what the "ref" element in SMIL does (seen in conformance doc)
    
    #TODO: add support for "alt" element; also make sure what it does
    def addImage(self, filename, timeBegin=0, timeEnd=0):
        """ Adds an image to this slide.
        @param filename: The name of the image file to add. Supported formats
                         are JPEG, GIF and WBMP.
        @type filename: str
        @param timeBegin: The time (in milliseconds) during the duration of
                          this slide to begin displaying the image. If this is
                          0 or less, the image will be displayed from the
                          moment the slide is opened.
        @type timeBegin: int
        @param timeEnd: The time (in milliseconds) during the duration of this
                        slide at which to stop showing (i.e. hide) the image.
                        If this is 0 or less, or if it is greater than the
                        actual duration of this slide, it will be shown until
                        the next slide is accessed.
        @type timeEnd: int
        
        @raise TypeError: An inappropriate variable type was passed in of the
                          parameters
        """
        if type(filename) != str or type(timeBegin) != type(timeEnd) != int:
            raise TypeError
        if not os.path.isfile(filename):
            raise OSError
        if timeEnd > 0 and timeEnd < timeBegin:
            raise ValueError, 'timeEnd cannot be lower than timeBegin'
        self.image = (DataPart(filename), timeBegin, timeEnd)
    
    def addAudio(self, filename, timeBegin=0, timeEnd=0):
        """ Adds an audio clip to this slide.
        @param filename: The name of the audio file to add. Currently the only
                         supported format is AMR.
        @type filename: str
        @param timeBegin: The time (in milliseconds) during the duration of 
                          this slide to begin playback of the audio clip. If
                          this is 0 or less, the audio clip will be played the
                          moment the slide is opened.
        @type timeBegin: int
        @param timeEnd: The time (in milliseconds) during the duration of this
                        slide at which to stop playing (i.e. mute) the audio
                        clip. If this is 0 or less, or if it is greater than
                        the actual duration of this slide, the entire audio
                        clip will be played, or until the next slide is
                        accessed.
        @type timeEnd: int
        
        @raise TypeError: An inappropriate variable type was passed in of the
                          parameters
        """
        if type(filename) != str or type(timeBegin) != type(timeEnd) != int:
            raise TypeError
        if not os.path.isfile(filename):
            raise OSError
        if timeEnd > 0 and timeEnd < timeBegin:
            raise ValueError, 'timeEnd cannot be lower than timeBegin'
        self.audio = (DataPart(filename), timeBegin, timeEnd)
    
    def addText(self, text, timeBegin=0, timeEnd=0):
        """ Adds a block of text to this slide.
        @param text: The text to add to the slide.
        @type text: str
        @param timeBegin: The time (in milliseconds) during the duration of
                          this slide to begin displaying the text. If this is
                          0 or less, the text will be displayed from the
                          moment the slide is opened.
        @type timeBegin: int
        @param timeEnd: The time (in milliseconds) during the duration of this
                        slide at which to stop showing (i.e. hide) the text.
                        If this is 0 or less, or if it is greater than the
                        actual duration of this slide, it will be shown until
                        the next slide is accessed.
        @type timeEnd: int
        
        @raise TypeError: An inappropriate variable type was passed in of the
                          parameters
        """
        if type(text) != str or type(timeBegin) != type(timeEnd) != int:
            raise TypeError
        if timeEnd > 0 and timeEnd < timeBegin:
            raise ValueError, 'timeEnd cannot be lower than timeBegin'
        tData = DataPart()
        tData.setText(text)
        self.text = (tData, timeBegin, timeEnd)
    
    def setDuration(self, duration):
        """ Sets the maximum duration of this slide (i.e. how long this slide
        should be displayed)
        
        @param duration: the maxium slide duration, in milliseconds
        @type duration: int
        
        @raise TypeError: <duration> must be an integer
        @raise ValueError: the requested duration is invalid (must be a
                           non-zero, positive integer)
        """
        if type(duration) != int:
            raise TypeError
        elif duration < 1:
            raise ValueError, 'duration may not be 0 or negative'
        self.duration = duration

class DataPart:
    """ This class represents a data entry in the MMS body.
    
    A DataPart objectencapsulates any data content that is to be added to the
    MMS (e.g. an image file, raw image data, audio clips, text, etc).
    
    A DataPart object can be queried using the Python built-in C{len()}
    function.
    
    This encapsulation allows custom header/parameter information to be set
    for each data entry in the MMS. Refer to [5] for more information on
    these.
    """
    def __init__(self, srcFilename=None):
        """ @param srcFilename: If specified, load the content of the file
                                with this name
            @type srcFilename: str
        """
        #self.contentTypeParameters = {}
        self.headers = {'Content-Type': ('application/octet-stream', {})}
        self._filename = None
        self._data = None
        if srcFilename != None:
            self.fromFile(srcFilename)
    
    # contentType property
    def _getContentType(self):
        """ Returns the string representation of this data part's
        "Content-Type" header. No parameter information is returned;
        to get that, access the "Content-Type" header directly (which has a
        tuple value)from this part's C{headers} attribute.
        
        This is equivalent to calling DataPart.headers['Content-Type'][0]
        """
        return self.headers['Content-Type'][0]
    def _setContentType(self, value):
        """ Convenience method that sets the content type string, with no
        parameters """
        self.headers['Content-Type'] = (value, {})
    contentType = property(_getContentType, _setContentType) 
    
    def fromFile(self, filename):
        """ Load the data contained in the specified file
        
        @note: This function clears any previously-set header entries.
        
        @param filename: The name of the file to open
        @type filename: str
        
        @raises OSError: The filename is invalid
        """
        if not os.path.isfile(filename):
            raise OSError, 'The file "%s" does not exist.' % filename
        # Clear any headers that are currently set
        self.headers = {}
        self._data = None
        self.headers['Content-Location'] = os.path.basename(filename) 
        #self.contentType = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        self.headers['Content-Type'] = (mimetypes.guess_type(filename)[0] or 'application/octet-stream', {})
        self._filename = filename
    
    def setData(self, data, contentType, ctParameters={}):
        """ Explicitly set the data contained by this part
        
        @note: This function clears any previously-set header entries.
        
        @param data: The data to hold
        @type data: str
        @param contentType: The MIME content type of the specified data
        @type contentType: str
        @param ctParameters: A dictionary containing any content type header
                             parmaters to add, in the format:
                             C{{<parameter_name> : <parameter_value>}}
        @type ctParameters: dict
        """
        self.headers = {}
        self._filename = None
        self._data = data
        self.headers['Content-Type'] = (contentType, ctParameters)
        
    def setText(self, text):
        """ Convenience wrapper method for setData()
        
        This method sets the DataPart object to hold the specified text
        string, with MIME content type "text/plain".
        
        @param text: The text to hold
        @type text: str
        """
        self.setData(text, 'text/plain')
    
    def __len__(self):
        """ Provides the length of the data encapsulated by this object """
        if self._filename != None:
            return int(os.stat(self._filename)[6])
        else:
            return len(self.data)
    
    @property
    def data(self):
        """ @return: the data of this part
        @rtype: str
        """
        if self._data != None:
            if type(self._data) == array.array:
                self._data = self._data.tostring()
            return self._data
        elif self._filename != None:
            f = open(self._filename, 'r')
            self._data = f.read()
            f.close()
            return self._data
        else:
            return ''
