""" This file contains magic classes to identify files from their
headers more accurately
"""
import pyflag.Magic as Magic
import pyflag.Registry as Registry
import pyflag.DB as DB
import pyflag.FlagFramework as FlagFramework

class HTML(Magic.Magic):
    type = "HTML Document"
    mime = "text/html"
    default_score = 30
    
    literal_rules = [
        ( "<html", (0,500)),
        ( "<body", (0,500)),
        ( "<div", (0,500)),
        ( "<title", (0,500)),
        ( "<table", (0,500)),
        ( "<tr", (0,500)),
        ( "<td", (0,500)),
        ( "<th", (0,500)),
        ]

    samples = [ (60, """<html>
<body>
</body></html>"""), (120, """<table><tr><th>From</th><th>""")
                ]

import magic
import pyflag.conf
config=pyflag.conf.ConfObject()

class LibMagic(Magic.Magic):
    """ A Generic handler which uses libmagic """
    magic = None
    mimemagic = None

    def __init__(self):
        if not LibMagic.magic:
            LibMagic.magic = magic.open(magic.MAGIC_CONTINUE)
            if magic.load(LibMagic.magic, config.MAGICFILE) < 0:
                raise IOError("Could not open magic file %s" % config.MAGICFILE)

        if not LibMagic.mimemagic:
            LibMagic.mimemagic=magic.open(magic.MAGIC_MIME | magic.MAGIC_CONTINUE)
            if magic.load(LibMagic.mimemagic,config.MAGICFILE) < 0:
                raise IOError("Could not open magic file %s" % config.MAGICFILE)

    def score(self, data, case, inode_id):
        ## The Magic library expects a byte string and does not look
        ## at encoding at all. We need to provide it a utf8 encoded
        ## string.
        data = FlagFramework.smart_str(data, errors='ignore')
        self.type = magic.buffer(LibMagic.magic, data)
        self.mime = magic.buffer(LibMagic.mimemagic, data)
        
        return 20

    samples = [(20,'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\xe6\x00\xe6\x00\x00')]

class FSStates(Magic.Magic):
    """ A Magic handler to identify filesystem objects (like links and directories) """
    def score(self, data, case, inode_id):
        if case:
            dbh = DB.DBO(case)
            dbh.execute("select * from file where inode_id=%r", inode_id)
            row = dbh.fetch()
            
            if row and row['mode']=='d/d':
                self.type = "Directory"
                return 100

        return 0
    
import unittest

class MagicTest(unittest.TestCase):
    """ Magic tests """
    def test01Magic(self):
        """ Test that common headers are correctly identified """
        m = Magic.MagicResolver()
        for cls in Registry.MAGIC_HANDLERS.classes:
            print "\nTesting %s" % cls
            for sample_score, sample in cls.samples:
                print "Best match %s" % m.get_type(sample,None,None)[0]

                max_score, scores = m.estimate_type(sample, None, None)
                print "scores: "
                for k,v in scores.items():
                    if v>0:
                        print "      %s, %s (%s)" %( k.__class__, k.type_str(), v)

                self.assertEqual(max_score[1].__class__, cls,
                                 "Sample matched %s better than %s" % (
                    max_score[1].__class__, cls))
                    
                self.assertEqual(sample_score, max_score[0],
                                 "Unexpected score %s, expected %s" % (
                    max_score[0], sample_score) )
                    
