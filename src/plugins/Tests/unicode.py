""" This module implements some tests specific for unicode handling """
# -*- coding=utf-8 -*-
import pyflag.tests
import pyflag.DB as DB

import pyflag.Reports as Reports
class UnicodeTree(Reports.report):
    """ A Tree with unicode in it - tests the ability of the tree
    widget to convey arbitrary chars
    """
    name = "Unicode Tree"
    family = 'Test'
    
    def display(self, query, result):
        
        tree = { 'level 1': { 'level 1': {"leaf 1":1},
                              'level 2': {"leaf 2":1}},
                 'Weird Chars': { 'L$%@!#\\a': {"leaf 1":1},
                              'Th#2*3?&': {"leaf 2":1}},
                 'Arabic': { "level 1": {u'شاستاثس':1},
			     "level 2": {u"فاهسهس":1},
                             }}
        
        def pane_cb(branch, result):
            result.heading(DB.expand("You selected %s",branch))

        def tree_cb(path):
            print "Path is %r" % path
            levels = path.split("/")
            tmp = tree
            for x in levels:
                if x:
                    try:
                        tmp = tmp[x]
                    except: break
            
            try:
                for x in tmp.keys():
                    yield (x,x,'branch')
            except:
                yield (x,x,'leaf')

        result.tree(tree_cb = tree_cb, pane_cb = pane_cb)
    
class UnicodeTest(pyflag.tests.ScannerTest):
    """ Test Unicode handling """
    test_case = "PyFlagTestCase"
    test_file = "unicode.E01"
    subsystem = "EWF"
