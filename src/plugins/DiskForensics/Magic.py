""" This file contains magic classes to identify files from their
headers more accurately
"""
import pyflag.Magic as Magic
import pyflag.Registry as Registry
import pyflag.DB as DB

class RFC2822(Magic.Magic):
    type = "RFC2822 Mime message"
    mime = "message/rfc2822"
    default_score = 20

    literal_rules = [
        ( "\nmime-version:", (0,1000)),
        ( "\nreceived:", (0,1000)),
        ( "\nfrom:", (0,1000)),
        ( "\nmessage_id:",(0,1000)),
        ( "\nto:", (0,1000)),
        ( "\nsubject:", (0,1000)),
        ( "\nreturn-path:", (0,1000))
        ]

    samples = [ (80, """Message-ID: <42BE76A2.8090608@users.sourceforge.net>
Date: Sun, 26 Jun 2005 19:34:26 +1000
From: scudette <scudette@users.sourceforge.net>
User-Agent: Debian Thunderbird 1.0.2 (X11/20050602)
X-Accept-Language: en-us, en
MIME-Version: 1.0
To:  scudette@users.sourceforge.net
Subject: The Queen
Content-Type: multipart/mixed;
boundary="-.-----------020606020801030004000306"
"""
                 ) ]

class HTML(Magic.Magic):
    type = "HTML Document"
    mime = "text/html"
    default_score = 60
    
    literal_rules = [
        ( "<html", (0,500)),
        ( "<div", (0,500)),
        ( "<title", (0,500)),
        ( "<table", (0,500)),
        ( "<tr", (0,500)),
        ( "<td", (0,500)),
        ( "<th", (0,500)),
        ]

    samples = [ (60, """<html>
<body>
</body></html>"""), (100, """<table><tr><th>From</th><th>""")
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
        ## Fixme - this is a race: this class instance is used by all
        ## callers. This needs to be fixed by locking the Resolver class.
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
            print "\nTesting %s" % cls,
            for sample_score, sample in cls.samples:
                max_score, scores = m.estimate_type(sample, None, None)
                print "scores: "
                for k,v in scores.items():
                    if v>0:
                        print "      %s, %s (%s)" %( k.__class__, k.type_str(), v)
                    
                for x in scores.keys():
                    if x.__class__ == cls:
                        print x.type_str(),
                        self.assertEqual(scores[x], sample_score)
                        print "OK"
