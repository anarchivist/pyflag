""" This is an implementation of a HTML parser using the pyflag lexer. 

We concentrate on robustness here - we detect errors and flag them, but we try
to keep going as much as possible. The parser is designed to be a feed parser -
i.e. data is fed in arbitrary chunks.

"""

import lexer
import sys

class HTMLParser(lexer.Lexer):
    state = "CDATA"
    tokens = [
        [ "CDATA", '[^<]+', "CDATA", "CDATA"],
        [ "CDATA", "<", "TAG_START", "TAG" ],

        ## Skip white spaces within a TAG
        [ "TAG", " +", "SPACE", "TAG" ],
        [ "TAG", ">", "END_TAG", "CDATA" ],

        ## Identify DTDs: (We dont bother parsing DTDs, just skip
        ## them:
        [ "TAG", "![^-]", "DTD_START", "DTD" ],
        [ 'DTD', '[^>]+>', "DTD", "CDATA" ],

        ## Detect HTML comments
        [ "TAG", "!--", "COMMENT_START", "COMMENT" ],
        [ "COMMENT", "(.*?)-->", "COMMENT", "CDATA" ],

        ## Identify a self closing tag (e.g. one that ends in />):
        [ "TAG", "/", "CLOSING_TAG", "TAG" ],

        ## Identify the tag name
        [ "TAG", "[^ /<>]+ ?", "TAG_NAME", "ATTRIBUTE LIST"],

        ## An attribute list is a list of key=value pairs within a tag
        [ "ATTRIBUTE LIST", "([-a-z0-9A-Z]+) *=", "ATTRIBUTE_NAME", "ATTRIBUTE VALUE"],
        [ "ATTRIBUTE LIST", ">", "END_TAG","CDATA"],
        
        ## Swallow spaces
        [ "ATTRIBUTE LIST", " +", "SPACE", "ATTRIBUTE LIST"],

        ## End tag:
        [ "ATTRIBUTE LIST", "/>", "CLOSING_TAG", "CDATA" ],

        ## Attribute without a value - we look ahead after the name to
        ## confirm that there is no =. The lookahead is important to
        ## ensure we dont match an attribute with a value but the
        ## "=value" is just not here yet but will be in the next feed
        [ "ATTRIBUTE LIST", r"([-a-z0=9A-Z]+)(?=( [^\s]|[/>]))", "ATTRIBUTE_NAME", "ATTRIBUTE LIST"],

        ## Quoted attribute values
        [ "ATTRIBUTE VALUE", "'([^']+)'|\"([^\"]+)\"", "ATTRIBUTE_VALUE", "ATTRIBUTE LIST" ],
        
        ## Non quoted attribute value
        [ "ATTRIBUTE VALUE", " *([^ <>]+) ?", "ATTRIBUTE_VALUE", "ATTRIBUTE LIST" ],
        ]

    def CDATA(self, token, match):
        print "CDATA: %r" % match.group(0)

    def CLOSING_TAG(self, token, match):
        self.tag['type'] = 'close'

    def TAG_NAME(self, token,match):
        self.tag['name'] = match.group(0)

    def ATTRIBUTE_NAME(self, token, match):
        self.current_attribute = match.group(1)
        self.tag[self.current_attribute] = ''

    def END_TAG(self, token, match):
        ## Show use the full tag
        print self.tag

    def TAG_START(self, token, match):
        self.tag = {}

    def ATTRIBUTE_VALUE(self, token, match):
        self.tag[self.current_attribute] = match.group(1) or match.group(2)

if __name__ == '__main__':
    l = HTMLParser()

    if len(sys.argv)==1:
        l.feed("foobar");

        ## Get as many tokens as possible
        while l.next_token(False): pass

        # This one has an error in the <
        l.feed("<<a> here <bo< ld> sdfd");

        while l.next_token(True): pass

        # Split input - space between the < and / for closing tags
        l.feed(" sfsfd < /bold attr1");

        while 1:
            t=l.next_token(False)
            print "Got token %s" % t
            if not t: break

        # A late fed attribute value. A spurious > within cdata:
        l.feed("= value1> This is cdata > ");

        # Unbalanced tags
        l.feed("<table><tr><b> <a href=http://www.google.com/>sfsfd </b></tr></table>");

        l.feed("foobar here< b attr='hi there' att2 = foobar>hello</b>");

        ## Get as many tokens as possible
        while l.next_token(True): pass

    else:
        fd = open(sys.argv[1])
        for line in fd:
            l.feed(line)
            
            ## Get all the tokens
            while l.next_token(True): pass
        print "Total error rate %s" % l.error
