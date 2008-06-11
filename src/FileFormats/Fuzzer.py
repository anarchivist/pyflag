# ******************************************************
# Copyright 2006
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
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
"""
This is a proof of concept utility for generating variations on a
template. This is commonly known as fuzzing.
"""
from plugins.FileFormats.BasicFormats import *
import pyflag.FlagFramework as FlagFramework
import format
import StringIO

class Fuzzer:
    """ This class generates a sequence of fuzzed strings based on a
    data template.
    """
    def __init__(self, template, generator, args):
        """
        template is a DataType which will be used as the generated
        template.

        generator is a generator which will produce a tuple or tuples:
        ((field, value), (field,value)). The Fuzzer will replace all
        the fields with the values in the template.

        args is a dict which will be used as args to the generator
        function to start it.
        """
        self.template = template
        self.generator = generator
        self.args = args

    def __iter__(self):
        for step in self.generator(**self.args):
            backup = {}
            for field,value in step:
                backup[field]=self.template[field]
                self.template[field] = value

            output = StringIO.StringIO()
            self.template.write(output)
            yield output.getvalue()

            ## Return things to how they were:
            for field,value in backup.items():
                self.template[field]=value

if __name__ == "__main__":
    print " This is a demonstration of fuzzers "

    class TestStruct(SimpleStruct):
        def init(self):
            self.fields = [
                ['s', STRING, dict(length=5)],
                ['number1', WORD],
                ['number2', WORD],
                ['string', LPSTR]
                ]

    # Parse some data
    template=TestStruct('hello\x01\x02\x03\x04\x05\x00\x00\x00hello')

    ## Lets have a look at the template
    print template

    def Fuzzer_cartesian_WORD_counter(field1='', field2='',start=0, end=255, step=1):
        for i in range(start,end,step):
            for j in range(start,end,step):
                yield ((field1,WORD('',value=i)),(field2,WORD('',value=j)))

    def Fuzzer_LPSTR_generator(field='', char='x', start=0, end=255,step=1):
        for i in range(start,end,step):
            yield ((field,LPSTR(None,value=char * i)),)

    ## And fuzz them
    f = Fuzzer(template, Fuzzer_LPSTR_generator, dict(field='string',end=20))
    for data in f:
        print "%r" % ("%s" % data)
