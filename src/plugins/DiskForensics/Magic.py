""" This file contains magic classes to identify files from their
headers more accurately
"""
import pyflag.Magic as Magic
import pyflag.Registry as Registry
import pyflag.FlagFramework as FlagFramework

class RFC2822(Magic.Magic):
    type = "RFC2822 Mime message"
    mime = "message/rfc822"
    literal_rules = [
        ( "\nmime-version:", (0,1000)),
        ]

    sample_score = 100
    sample = """Message-ID: <42BE76A2.8090608@users.sourceforge.net>
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

class Text(RFC2822):
    type = "ASCII Text"
    mime = "text/plain"
    regex_rules = [
        ( "[\t\n\r!@#$%^&*(),.<>+_/;=\"\'\- 0-9a-zA-Z:]{900,1000}", (0, 1000)),
        ]

    sample_score = 20
    def score_hit(self,data, match, pending):
        pending.remove(match[0])
        ## Only a weak indication if it matches
        return 20

class HTML(Magic.Magic):
    type = "HTML Document"
    mime = "text/html"
    literal_rules = [
        ( "<html", (0,500)),
        ( "<div", (0,500))
        ]

    sample_score = 100
    sample = """<html>
<body>
</body></html>"""


class LibMagic(Magic.Magic):
    """ A Generic handler which uses libmagic """
    magic_handler = FlagFramework.Magic()
    
    def type_str(self):
        return self.type

    def score(self, data):
        ## Fixme - this is a race: this class instance is used by all
        ## callers.
        self.type = self.magic_handler.buffer(data)

        return 20

    sample_score = 20
    sample = '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\xe6\x00\xe6\x00\x00'
    
import unittest

class MagicTest(unittest.TestCase):
    """ Magic tests """
    def test01Magic(self):
        """ Test that common headers are correctly identified """
        m = Magic.Magic()
        m.prepare()
        
        for cls in Registry.MAGIC_HANDLERS.classes:
            print "Testing %s" % cls,
            if cls.sample:
                max_score, scores = m.estimate_type(cls.sample)
                print scores
                for x in scores.keys():
                    if x.__class__ == cls:
                        print x.type_str(),
                        self.assertEqual(scores[x], cls.sample_score)
                        print "OK"
