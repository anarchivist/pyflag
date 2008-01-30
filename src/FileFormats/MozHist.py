# ******************************************************
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.86RC1 Date: Thu Jan 31 01:21:19 EST 2008$
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
""" A Parser for the mozilla database format (Its called Mork). This
is mostly used to store Mozilla history and saved forms.

The format specification can be found here
http://www.mozilla.org/mailnews/arch/mork/primer.txt
"""

import pyflag.lexer as lexer
import sys

class MozHist(lexer.SelfFeederMixIn, lexer.Lexer):
    def __init__(self, fd, verbose = 0):
        self.tokens = [
            ## Comments are C++ style and occur at any place
            [ '.', '//[^\n]+', "COMMENT", None ],

            ## Sections are delimited by < > (< > can appear in other
            ## states like within the VALUE)
            [ '(INITIAL|SECTION)', '<', 'START_SECTION,PUSH_STATE', 'SECTION' ],
            [ 'SECTION', '>', 'END_SECTION,POP_STATE', None],

            ## properties are delimited by () and are followed by property = value
            [ 'SECTION', r'\(([^=\s]+)(\s+)?=', 'PROPERTY,PUSH_STATE', 'VALUE'],
            ## Values are sometimes broken across lines:
            [ 'VALUE', r'\\\n', 'SPACE', None],

            ## In VALUEs some characters are escaped with \
            [ 'VALUE', r'\\([\$\)\\])', 'VALUE_FRAGMENT', None],

            ## And others are escaped using a hex escape e.g. $00
            [ 'VALUE', r'\$(..)', 'ENCODED_VALUE_FRAGMENT', None],

            ## Otherwise value fragments are just emitted
            [ 'VALUE', r'([^\)\$\\]+)', 'VALUE_FRAGMENT', None],

            ## A single ) delimits this value
            [ 'VALUE', r'\)', 'VALUE,POP_STATE', None],

            ## Event lists are delimited by {}. We actually ignore the
            ## whole first line here because I dont really know what
            ## that line means.
            [ 'INITIAL', '{[^\n]+', 'EVENT_LIST_START,PUSH_STATE', 'EVENT_LIST'],
            [ '(EVENT_LIST|INITIAL)', r'\@\$\$.+\@', 'SECTION_DELIMITER', 'INITIAL'],

            ## Events start with [id within the EVENT_LIST
            [ '(EVENT_LIST|INITIAL)', '\[([^\(]+)', 'EVENT_START', 'EVENT'],
            [ 'EVENT_LIST', '\}', 'POP_STATE', None],
            
            ## Events contain attributes like (^xx^yy)
            [ 'EVENT', r'\(\^([^\^=]+)\^([^\^\)]+)\)', 'EVENT_ATTRIBUTE', None],

            ## Sometimes Events contain attributes with direct value
            ## (^xx=yy) or they can be missing like (^xx=)
            [ 'EVENT', r'\(\^([^=]+)=([^\^\)]*)\)', 'LITERAL_EVENT_ATTRIBUTE', None],

            ## Events are delimited by ]
            [ 'EVENT', '\]', 'EVENT_END', 'EVENT_LIST'],
            
            ## Whitespace everywhere will be ignored
            [ '.', r'\s+', 'SPACE', None],
            ]
        lexer.Lexer.__init__(self, verbose=verbose, fd=fd)
        self.properties = {}
        self.types = None

    def PROPERTY(self, t, m):
        self.property_id = m.group(1)
        self.value = ''
        
    def VALUE_FRAGMENT(self, t,m):
        self.value += m.group(1)

    def ENCODED_VALUE_FRAGMENT(self, t, m):
        self.value += chr(int(m.group(1),16))
        
    def VALUE(self, t, m):
        ## We save our property/value:
        self.properties[self.property_id] = self.value

    def END_SECTION(self, t, m):
        ## This first section is always the type definitions:
        if not self.types:
            self.types = self.properties
            self.properties = {}

        ## Im not sure what this is <(a=c)>
        if self.types.has_key('a'): self.types = None

    def EVENT_START(self, t, m):
        self.event = {"id": m.group(1)}

    def EVENT_ATTRIBUTE(self, t, m):
        field = self.types[m.group(1)]
        value = self.properties[m.group(2)]
        self.event[field] = value

    def LITERAL_EVENT_ATTRIBUTE(self, t, m):
        field = self.types[m.group(1)]
        self.event[field] = m.group(2)

    def EVENT_END(self, t, m):
        ## Some of the fields are given in UTF 16 we convert them
        ## here.
        for k in ('Name','Value'):
            try:
                self.event[k] = self.event[k].decode('utf16')
            except: pass

if __name__=="__main__":
    fd = open(sys.argv[1])
    h = MozHist(verbose = 0, fd = fd)
    while 1:
        token = h.next_token()
        if not token: break

        if token=='EVENT_END':
            ## We do something with the event
            print h.event
