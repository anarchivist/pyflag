# -*- coding: utf-8 -*-
## Python bindings for GNU libextractor
## 
## Copyright (C) 2006 Bader Ladjemi <bader@tele2.fr>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; see the file COPYING. If not, write to the
## Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139,
## USA.
##
"""
Python bindings for GNU libextractor

libextractor is a simple library for keyword extraction.  libextractor
does not support all formats but supports a simple plugging mechanism
such that you can quickly add extractors for additional formats, even
without recompiling libextractor. libextractor typically ships with a
dozen helper-libraries that can be used to obtain keywords from common
file-types.  

libextractor is a part of the GNU project (http://www.gnu.org/).     
"""
from ctypes import *
#fake cdll import
try:
    #loading shared object file
    libextractor = cdll.LoadLibrary('libextractor.so.1')
except OSError:
    libextractor = cdll.extractor
 
__all__ = ['Extractor', 'isBinaryType', 'EXTRACTOR_ENCODING', 'DEFAULT_LIBRARIES', 'EXTRACTOR_THUMBNAIL_DATA']
__version__ = "0.5"
__licence__ = "GNU GPL"

"""
keyword's charset encoding
"""
EXTRACTOR_ENCODING = "utf-8"

KeywordType = c_int
Keywords_p = POINTER('Keywords')
class Keywords(Structure):
    """
    EXTRACTOR_Keywords struct
    """
    _fields_ = [('keyword', c_char_p),
		('keywordType', KeywordType),
		('next', Keywords_p)]	
SetPointerType(Keywords_p, Keywords)

KEYWORDS = POINTER(Keywords)

libextractor.EXTRACTOR_getKeywords.restype = KEYWORDS
libextractor.EXTRACTOR_getKeywords2.restype = KEYWORDS
libextractor.EXTRACTOR_removeDuplicateKeywords.restype = KEYWORDS
libextractor.EXTRACTOR_getKeywordTypeAsString.restype = c_char_p

libextractor.EXTRACTOR_getDefaultLibraries.restype = c_char_p

"""
thumbnail keyword type (binary)
"""
EXTRACTOR_THUMBNAIL_DATA = 70

def isBinaryType(keyword_type):
    """
    returns if the given keyword_type is binary

    @param keyword_type: keyword type (int)
    """
    return keyword_type == EXTRACTOR_THUMBNAIL_DATA

"""
default loaded libraries
"""
DEFAULT_LIBRARIES = libextractor.EXTRACTOR_getDefaultLibraries().split(':')

class Extractor(object):
    """
    Main class for extracting meta-data with GNU libextractor.

    You may create multiple instances of Extractor to use
    different sets of library.  Initially each Extractor
    will start with the default set of libraries.

    Use the extract method to obtain keywords from a file.

    Use the add and remove libraries methods to change the list of
    libraries that should be used.
    """
    
    def __init__(self, defaults=True, libraries=None, lang=None, languages=None, hash=None, use_filename=False, split_keywords=False):
	"""
	Initialize Extractor's instance
	
	@param extractors: list of strings that contains extractor's name (supported types)
	@param defaults: load default plugins
	@param lang: use the generic plaintext extractor for the language with the 2-letter language code LANG
	@param languages: list of lang
	@param hash: compute hash using the given algorithm (currently 'sha1' or 'md5')
	@param use_filename: use the filename as a keyword (add filename-extractor library)
	@param split_keywords: use keyword splitting (add split-extractor library)

	>>> Extractor() #doctest: +ELLIPSIS
	<__main__.Extractor object at 0x...>
	
	>>> extractor = Extractor(defaults=False)
	>>> extractor.libraries
	()

	>>> extractor = Extractor()
	>>> sorted(extractor.libraries) == sorted(tuple(DEFAULT_LIBRARIES))
	True

	>>> extractor = Extractor(hash='md5')
	>>> found = False
	>>> for library in extractor.libraries:
	...     if 'md5' in library:
	...        found = True
	...        break
	>>> found
	True

	>>> extractor = Extractor(use_filename=True)
	>>> found = False
	>>> for library in extractor.libraries:
	...     if 'filename' in library:
	...        found = True
	...        break
	>>> found
	True

	>>> extractor = Extractor(split_keywords=True)
	>>> found = False
	>>> for library in extractor.libraries:
	...     if 'split' in library:
	...        found = True
	...        break
	>>> found
	True

	"""
	self._libraries = {}
	self.extractors = None
	if defaults:
	    self.extractors = libextractor.EXTRACTOR_loadDefaultLibraries()
	    self._libraries = dict([(library, None) for library in DEFAULT_LIBRARIES])
	if use_filename:
	    self.addLibrary("libextractor_filename")
	if libraries:
	    self.extractors = libextractor.EXTRACTOR_loadConfigLibraries(self.extractors, libraries)
	    self._libraries.update(dict([(library, None) for library in libraries.split(':')]))
	if isinstance(lang, str):
	    self.addLibraryLast("libextractor_printable_%s" % lang)
	if isinstance(hash, str):
	    self.addLibraryLast("libextractor_hash_%s" % hash)
	if languages:
	    [self.addLibraryLast("libextractor_printable_%s" % language) for language in languages]
	if split_keywords:
	    self.addLibraryLast("libextractor_split")
    
    def extract(self, filename=None, data=None, size=None):
	"""Extract keywords from a file, or from its data.

	@param filename: filename string
	@param data: data contents
	@param size: data size
	
        This function returns a list of tuples. Its first value is keyword type
	and its second value is keyword value. If the file cannot be opened
	or cannot be found, the list will be empty.  The list can
	also be empty if no keyword was found for the file.

	If you give data, size had to be given too.

        """
	if not filename and not (data and size):
	    return None
	elif filename:
	    return self.extractFromFile(filename)
	else:
	    return self.extractFromData(data, size)
	
    def extractFromFile(self, filename):
	"""Extract keywords from a file using its filename.

	@param filename: filename string
	
        This function returns a list of tuples. Its first value is keyword type
	and its second value is keyword value. If the file cannot be opened
	or cannot be found, the list will be empty.  The list can
	also be empty if no keyword was found for the file.

	>>> import os
    	>>> extractor = Extractor()
	>>> filename = os.tmpnam()
	>>> f = file(filename, 'w')
	>>> extractor.extract(filename)
	[]

	>>> import os
    	>>> extractor = Extractor()
	>>> filename = '../Extractor/test/test.png'
	>>> extractor.extract(filename)
	[(u'comment', u'Testing keyword extraction\\n'), (u'resource-identifier', u'dc6c58c971715e8043baef058b675eec'), (u'size', u'4x4'), (u'mimetype', u'image/png')]

	>>> import os, glob
    	>>> extractor = Extractor()
	>>> filename = glob.glob('dist/*.gz')[0]
	>>> extracted = extractor.extract(filename)
	>>> filename_count = 0
	>>> for keyword_type, keyword in extracted:
        ...     if keyword_type == 'filename':
	...        filename_count += 1
	>>> filename_count > 1
	True

        """
	self.keywords_p = libextractor.EXTRACTOR_getKeywords(self.extractors, filename)
	return self._extract()

    def extractFromData(self, data, size):
	"""Extract keywords using its data.

	@param data: data contents
	@param size: data size
	
        This function returns a list of tuples. Its first value is keyword type
	and its second value is keyword value. If the file cannot be opened
	or cannot be found, the list will be empty.  The list can
	also be empty if no keyword was found for the file.

        """
	self.keywords_p = libextractor.EXTRACTOR_getKeywords2(self.extractors, data, size)
	return self._extract()
    
    def _extract(self):
	self.extracted = []

	if not self.keywords_p:
	    return self.extracted

	try:
	    self.keywords = self.keywords_p.contents
	except ValueError:
	    return self.extracted

	while True:
	    keyword_type = libextractor.EXTRACTOR_getKeywordTypeAsString(self.keywords.keywordType)
	    keyword = self.keywords.keyword
		
	    self.extracted.append((keyword_type, keyword))
	    try:
		self.keywords = self.keywords.next.contents
	    except ValueError:
		libextractor.EXTRACTOR_freeKeywords(self.keywords_p)
		self.keywords_p = None
		return self.extracted
	    
    def addLibrary(self, library):
	"""
        Add given library to the extractor. Invoke with a string with the name
        of the library that should be added.  For example,
        
        'libextractor_filename'

        will prepend the extractor that just adds the filename as a
        keyword.

        No errors are reported if the library is not
        found.

	@param library: library's name
        """	
	self._libraries[library] = None

	self.extractors = libextractor.EXTRACTOR_addLibrary(self.extractors, library)

    def addLibraryLast(self, library):
	"""
	Same as addLibrary but the library is added at the last.

	@param library: library's name
	"""
	self._libraries[library] = None
	
	self.extractors = libextractor.EXTRACTOR_addLibraryLast(self.extractors, library)

    def removeLibrary(self, library):
	"""      
        Remove a library.  Pass the name of the library that is to
        be removed.  Only one library can be removed at a time.
        For example,

        'libextractor_pdf'

        removes the PDF extractor (if added).
	ValueError will be thrown if no library match.

	@param library: library's name
	"""
	try:
	    del self._libraries[library]
	except KeyError:
	    raise ValueError, "No such loaded library"
	
	self.extractors = libextractor.EXTRACTOR_removeLibrary(self.extractors, library)

    def addLibraries(self, libraries):
	"""
	Add given libraries. 
	Same as addLibary but libraries is a list of library's names.

	@param libraries: list of libraries names
	"""
	for library in libraries:
	    if isinstance(library, str):
		self.addLibrary(library)

    def removeAllLibraries(self):
	"""
	Remove all libraries.

	>>> extractor = Extractor()
	>>> extractor.removeAllLibraries()
	>>> extractor.libraries
	()
	"""
	self._libraries = {}
        self.extractors = None
	
    def keywordTypes(self):
	"""
	Returns the list of all keywords types.
	@return: list of all keywords types

	>>> extractor = Extractor()
	>>> extractor.keywordTypes()
	('unknown', 'filename', 'mimetype', 'title', 'author', 'artist', 'description', 'comment', 'date', 'publisher', 'language', 'album', 'genre', 'location', 'version', 'organization', 'copyright', 'subject', 'keywords', 'contributor', 'resource-type', 'format', 'resource-identifier', 'source', 'relation', 'coverage', 'software', 'disclaimer', 'warning', 'translated', 'creation date', 'modification date', 'creator', 'producer', 'page count', 'page orientation', 'paper size', 'used fonts', 'page order', 'created for', 'magnification', 'release', 'group', 'size', 'summary', 'packager', 'vendor', 'license', 'distribution', 'build-host', 'os', 'dependency', 'MD4', 'MD5', 'SHA-0', 'SHA-1', 'RipeMD160', 'resolution', 'category', 'book title', 'priority', 'conflicts', 'replaces', 'provides', 'conductor', 'interpreter', 'owner', 'lyrics', 'media type', 'contact', 'binary thumbnail data', 'publication date', 'camera make', 'camera model', 'exposure', 'aperture', 'exposure bias', 'flash', 'flash bias', 'focal length', 'focal length (35mm equivalent)', 'iso speed', 'exposure mode', 'metering mode', 'macro mode', 'image quality', 'white balance', 'orientation')
	"""
	i = 0
	keyword_types = []
	
	while True:
	    keyword_type = libextractor.EXTRACTOR_getKeywordTypeAsString(i)
	    if not keyword_type:
		break
	    keyword_types.append(keyword_type)
	    i += 1
	    
	return tuple(keyword_types)
    
    def _get_libraries(self):
	"""
	Return current libraries
	@return: current libraries
	"""
	return tuple(self._libraries.keys())

    def _set_libraries(self, libraries):
	"""
	Add libraries to load (don't replace current ones)

	@param libraries: list of libraries
	
	>>> extractor = Extractor()
	>>> extractor.libraries = ('libextractor_filename', )
	>>> 'libextractor_filename' in extractor.libraries
	True
	>>> len(extractor.libraries) == len(DEFAULT_LIBRARIES)+1
	True
	
	"""
	self.addLibraries(libraries)

    libraries = property(fget=_get_libraries, fset=_set_libraries, fdel=removeAllLibraries, doc='tuple of loaded libraries')

    def __del__(self):
	"""
	>>> extractor = Extractor()
	>>> del extractor
	"""
	if self.extractors:
	    self.removeAllLibraries()

if __name__ == "__main__":
    import doctest
    doctest.testmod()
