#!/usr/bin/env python
import pyflag.HTMLUI as HTMLUI
import pyflag.DB as DB
import pyflag.conf
import pyflag.pyflaglog as pyflaglog
import pyflag.FlagFramework as FlagFramework
config=pyflag.conf.ConfObject()
import time,re
import pyflag.TableObj as TableObj
import pyflag.parser as parser

class XMLUI(HTMLUI.HTMLUI):
    def display(self):
        return self.__str__()

    def heading(self, string):
        self.result += "<heading>%s</heading>" % string

    def para(self, string, **options):
        self.result += "<para>%s</para>" % string

    
