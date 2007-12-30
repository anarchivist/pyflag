""" This is an implementation of a HTML parser using the pyflag lexer. 

We concentrate on robustness here - we detect errors and flag them, but we try
to keep going as much as possible. The parser is designed to be a feed parser -
i.e. data is fed in arbitrary chunks.

"""

import lexer
import sys,re

def decode_entity(string):
    return re.sub("&#(\d+);", lambda x: chr(int(x.group(1))), string)

class HTMLParser(lexer.Lexer):
    state = "CDATA"
    tokens = [
        ## Detect HTML comments
        [ "CDATA", "<!--", "COMMENT_START", "COMMENT" ],
        [ "COMMENT", "(.*?)-->", "COMMENT", "CDATA" ],
        [ "COMMENT", ".+", "COMMENT", "COMMENT" ],

        [ "CDATA", '[^<]+', "CDATA", "CDATA"],
        [ "CDATA", "<", "TAG_START", "TAG" ],

        ## Skip white spaces within a TAG
        [ "TAG", " +", "SPACE", "TAG" ],
        [ "TAG", ">", "END_TAG", "CDATA" ],

        ## Scripts can actually contain lots of <> which confuse us so
        ## we need to ignore all the dat until the </script>
        [ "SCRIPT", "(.*?)</script[^>]*>", "SCRIPT", "CDATA" ],
        [ "SCRIPT", "(.+)", "SCRIPT", "SCRIPT" ],

        ## Identify DTDs: (We dont bother parsing DTDs, just skip
        ## them:
        [ "TAG", "![^-]", "DTD_START", "DTD" ],
        [ 'DTD', '[^>]+>', "DTD", "CDATA" ],

        ## Identify a self closing tag (e.g. one that ends in />):
        [ "TAG", "/", "CLOSING_TAG", "TAG" ],

        ## Identify the tag name
        [ "TAG", "[^ /<>]+", "TAG_NAME", "ATTRIBUTE LIST"],

        ## An attribute list is a list of key=value pairs within a tag
        [ "ATTRIBUTE LIST", "([-a-z0-9A-Z]+)\s*=", "ATTRIBUTE_NAME", "ATTRIBUTE VALUE"],
        [ "ATTRIBUTE LIST", ">", "END_TAG", "CDATA"],
        
        ## Swallow spaces
        [ "ATTRIBUTE LIST", " +", "SPACE", "ATTRIBUTE LIST"],

        ## End tag:
        [ "ATTRIBUTE LIST", "/>", "SELF_CLOSING_TAG,END_TAG", "CDATA" ],

        ## Attribute without a value - we look ahead after the name to
        ## confirm that there is no =. The lookahead is important to
        ## ensure we dont match an attribute with a value but the
        ## "=value" is just not here yet but will be in the next feed
        [ "ATTRIBUTE LIST", r"([-a-z0=9A-Z]+)(?=( [^\s]|[/>]))", "ATTRIBUTE_NAME", "ATTRIBUTE LIST"],

        ## Quoted attribute values
        [ "ATTRIBUTE VALUE", "(?ms)'([^']+)'|\"([^\"]+)\"", "ATTRIBUTE_VALUE", "ATTRIBUTE LIST" ],
        
        ## Non quoted attribute value
        [ "ATTRIBUTE VALUE", " *([^ <>]+) ?", "ATTRIBUTE_VALUE", "ATTRIBUTE LIST" ],
        ]

    def __init__(self, verbose = 0):
        lexer.Lexer.__init__(self, verbose)
        self.TAG_START(None, None)
        self.root = self.tag
        self.stack = [self.root,]

    def CDATA(self, token, match):
        self.tag['_cdata'] += match.group(0)

    def CLOSING_TAG(self, token, match):
        self.tag['_type'] = 'close'

    def SELF_CLOSING_TAG(self, token, match):
        self.tag['_type'] = 'selfclose'

    def TAG_NAME(self, token,match):
        self.tag['_name'] = match.group(0).lower()

    def SCRIPT(self, token, match):
        self.tag['_cdata'] += match.group(1)

    def ATTRIBUTE_NAME(self, token, match):
        self.current_attribute = match.group(1)
        self.tag[self.current_attribute] = ''

    def END_TAG(self, token, match):
        #print "Depth %s" % len(self.stack)
        ## These tags need to be ignored because often they do not balance
        for t in ['br', 'p']:
            if self.tag['_name']==t:
                #print "Self closing"
                self.tag['_type'] = 'selfclose'

        if self.tag['_type']=='close':
            ## Pop the last tag off the stack
            del self.stack[-1]
        else:
            ## Push the tag into the end of the stack and add it to
            ## our parent
            self.stack[-1]['_children'].append(self.tag)
            if self.tag['_type'] != 'selfclose':
                self.stack.append(self.tag)

        if self.tag['_name'] == 'script':
            return "SCRIPT"
                
    def TAG_START(self, token, match):
        self.tag = dict(_cdata = '', _children=[], _name='', _type='open')
        
    def ATTRIBUTE_VALUE(self, token, match):
        self.tag[self.current_attribute] = match.group(1) or match.group(2)

    def search(self, tag, _name):
        """ Generate all objects of given name from the tag provided downwards """
        for c in tag['_children']:
            if c['_name'] == _name:
                yield c

            for match in self.search(c,_name):
                yield match 

    def innerHTML(self, tag):
        result = tag['_cdata']
        for c in tag['_children']:
            result += "<%s>" % c['_name'] + self.innerHTML(c) + "</%s>" % c['_name']

        return result

    def find(self, tag, _name, **regex):
        """ Search all tags below tag for a tag with the name
        specified and all regexes matching attributes
        """
        for m in self.search(tag, _name):
            failed = False
            for k,v in regex.items():
                ## Is the required attribute actually there?
                if k not in m.keys():
                    failed = True
                    break

                ## does it match?
                if not re.compile(v, re.M | re.I).search(m[k]):
                    failed = True
                    break

            if not failed:
                return m

    def p(self, tag):
        result = {}
        for k,v in tag.items():
            if k != "_children":
                result[k] = v
        print result

if __name__ == '__main__':
    l = HTMLParser(verbose=1)

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

        ## This is a test for dom navigation

        ## Find the ComposeHeader table:
        tag = l.find(l.root, 'table', **{"class":'ComposeHeader'})

        ## Iterate over its rows:
        for row in l.search(tag, 'tr'):
            try:
                if not row.has_key('id'): continue
                
                if row['id'] == 'From':
                    option = l.find(row, 'option', selected='.*')
                    print "From: %s" % decode_entity(option['value'])
                    
                elif row['id'] == 'To':
                    option = l.find(row, 'input', type='text')
                    if option:
                        print "To: %s" % decode_entity(option['value'])

                elif row['id'] == 'Cc':
                    option = l.find(row, 'input', name='fCc')
                    if option:
                        print "Cc: %s" % decode_entity(option['value'])

                elif row['id'] == 'Bcc':
                    option = l.find(row, 'input', name='fBcc')
                    if option:
                        print "Bcc: %s" % decode_entity(option['value'])

            except Exception,e:
                print e
                pass

        ## Extract the subject:
        option = l.find(tag, 'input', type='text', name='fSubject')
        if option:
            print "Subject: %s" % decode_entity(option['value'])

        ## Now extract the content of the email:
        for s in l.search(l.root,'script'):
            m=re.match("document\.getElementById\(\"fEditArea\"\)\.innerHTML='([^']*)'", s['_cdata'])
            if m:
                print "Message: %s" % m.group(1).decode("string_escape")
                break
