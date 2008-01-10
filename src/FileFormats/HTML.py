""" This is an implementation of a HTML parser using the pyflag lexer. 

We do not use pythons native sgml parser because that is too fragile
for us. The native parser will raise when encountering invalid html,
causing us to mis-parse many pages we see in the wild.

We concentrate on robustness here - we detect errors and flag them, but we try
to keep going as much as possible. 

"""

import lexer
import sys,re,urllib,os
import pyflag.DB as DB
from FlagFramework import query_type, normpath, get_bt_string

XML_SPECIAL_CHARS_TO_ENTITIES = { "'" : "squot",
                                  '"' : "quote",
                                  "&" : "amp",
                                  " " : "nbsp",
                                  "<" : "lt",
                                  ">" : "gt" }

def unquote(string):
    for k,v in XML_SPECIAL_CHARS_TO_ENTITIES.items():
        string = string.replace("&%s;" % v, k)

    return string

def decode_entity(string):
    return re.sub("&#(\d+);", lambda x: chr(int(x.group(1)) % 256), string)

def decode_unicode(string):
    return re.sub(r"\\u(..)(..)", lambda x: (chr(int(x.group(1),16)) + chr(int(x.group(2),16))).decode("utf_16_be").encode('utf8'), string)

def decode(string):
    return decode_unicode(decode_entity(unquote(string)))

class Tag:
    def __init__(self, name=None, attributes=None):
        if not attributes: attributes={}
        self.name = name
        self.attributes = attributes
        self.children = []
        self.type = 'open'

    def __setitem__(self, item, value):
        self.attributes[item.lower()] = value

    def __getitem__(self, item):
        return self.attributes[item.lower()]

    def __str__(self):
        attributes = "".join([" %s='%s'" % (k,urllib.quote(v)) for k,v \
                               in self.attributes.items()])
        if self.type == 'selfclose':
            return "<%s%s/>" % (self.name, attributes)
        else:
            return "<%s%s>%s</%s>" % (self.name, attributes,
                                      self.innerHTML(), self.name)

    def innerHTML(self):
        result = ''
        for c in self.children:
            result += c.__str__()

        return result

    def add_child(self, child):
        ## Try to augment CDATAs together for efficiency:
        try:
            ## CDATAs are strings, but tags are classes without __add__
            self.children[-1] += child
        except (IndexError, TypeError):
            self.children.append(child)

    def tree(self, width=''):
        result = "%s%s\n" % (width, self.name)
        width += ' '
        for c in self.children:
            try:
                result += c.tree(width)
            except AttributeError:
                result += "%sCDATA: %r\n" % (width, c)
                
        return result

    def search(self, name):
        """ Generates all the tags of a given name under this DOM
        element in order
        """

        ## Return ourselves first:
        if self.name == name:
            yield self
        
        for c in self.children:
            try:
                for match in c.search(name):
                    yield match
            except AttributeError:
                pass


    def find(self, name, regex=None):
        """ Search our subtree for tags with the name specified and
        all regexes matching the attributes. regex is a dict with keys
        as attribute names, and values are regexes that should all
        match for that element to be returned.
        """
        for m in self.search(name):
            failed = False
            if regex:
                for k,v in regex.items():
                    ## Is the required attribute actually there?
                    try:
                        value = m[k]
                    except KeyError:
                        failed = True
                        break

                    ## does it match?
                    if not re.compile(v, re.M | re.I).search(value):
                        failed = True
                        break

            if not failed:
                return m

    def __iter__(self):
        self.i = 0
        return self

    def next(self):
        try:
            result = self.children[self.i]
            self.i +=1
            return result
        except IndexError:
            raise StopIteration()


class TextTag(Tag):
    """ A Sanitising Tag to print the DOM as plain text.

    We basically remove all the tags, and try to clean up the text a
    bit.
    """
    def __str__(self):
        if self.name in ['br','p']: 
            return "\n"

        if self.name in ['script','style']:
	    return ''

        data = decode_unicode(self.innerHTML())
        data = re.sub("[\r\n]+","\n",data)	

	return data
        return "%s" % data.replace("\n","<br>")


class SanitizingTag(Tag):
    """ This is a version of Tag which restricts the attributes
    printed and tags printed to a safe set. This can be used
    everywhere to sanitize html.
    """
    
    ## No other tags will be allowed (especially script tags)
    allowable_tags = [ 'b','i','a','img','em','br','strong', 'blockquote',
                       'tt', 'li', 'ol', 'ul', 'p', 'table', 'td', 'tr','th',
                       'h1', 'h2', 'h3', 'pre', 'html', 'font', 'body',
                       'code', 'head', 'meta', 'title','style', 'form',
                       'sup', 'input', 'span', 'label', 'option','select',
                       'div','span','nobr','u', 'frameset','frame','iframe',
                       'textarea','tbody','thead','center','hr','small', 'link']

    ## These tags will have their contents deleted
    forbidden_tag = [ 'script' ]

    ## Only these attributes are allowed (note that href and src
    ## attributes are handled especially):
    allowable_attributes = ['color', 'bgolor', 'width', 'border',
                            'rules', 'cellspacing', 'id',
                            'cellpadding', 'height',
                            'align', 'bgcolor', 'rowspan', 
                            'colspan', 'valign','id', 'class','name', 
                            'compact', 'type', 'start', 'rel',
                            'value', 'checked', 'rows','cols',
                            'framespacing','frameborder','contenteditable'
                            ]

    def css_filter(self, data):
        def resolve_css_references(m):
            result = self.resolve_reference(m.group(1), build_reference = False)
            return "url(%s)" % result
        
        return re.sub("(?i)url\(\"?([^\)\"]+)\"?\)",
                      resolve_css_references,
                      data)

    def __str__(self):
        ## Some tags are never allowed to be outputted
        if self.name not in self.allowable_tags:
            if self.name in self.forbidden_tag:
                return ''
            #print "Rejected tag %s" % self.name
            return self.innerHTML()

        ## Frames without src are filtered because IE Whinges:
        if self.name == 'iframe' and 'src' not in self.attributes:
		return ''

        attributes = "".join([" %s='%s'" % (k,v) for k,v \
                              in self.attributes.items() if k in \
                              self.allowable_attributes])

	if 'style' in self.attributes:
            attributes += ' style=%r' % self.css_filter(self.attributes['style'])

        if 'src' in self.attributes:
            attributes += ' src=%s' % self.resolve_reference(self.attributes['src'])

        if 'href' in self.attributes:
            if self.name == 'link':
                attributes += " href=%s" % self.resolve_reference(self.attributes['href'], 'text/css')
            else:
                attributes += ' href="javascript: alert(%r)"' % urllib.quote(self.attributes['href'][:100])

        ## CSS needs to be filtered extra well
        if self.name == 'style':
            return "<style %s>%s</style>" % (attributes,
                                             self.css_filter(self.innerHTML()))
        
        if self.type == 'selfclose':
            return "<%s%s/>" % (self.name, attributes)
        else:
            return "<%s%s>%s</%s>" % (self.name, attributes,
                                      self.innerHTML(), self.name)


    def resolve_reference(self, reference, hint=''):
        return 'images/spacer.png'

class ResolvingHTMLTag(SanitizingTag):
    """ A special tag which resolves src and href back into the
    database. This is useful in order to show embedded images etc from
    the traffic.

    Note that you would probably want to Curry this before passing it
    to the parser because we need to know the inode and case (our
    constructor takes more parameters.
    """

    def __init__(self, case, inode_id, name=None, attributes=None):
        self.case = case
        self.inode_id = inode_id
        SanitizingTag.__init__(self, name, attributes)

        ## Collect some information about this inode:
        try:
            dbh = DB.DBO(case)
            dbh.execute("select url from http where inode_id=%r", inode_id)
            row = dbh.fetch()

            url = row['url']
            m=re.search("(http|ftp)://([^/]+)/([^?]*)",url)
            self.method = m.group(1)
            self.host = m.group(2)
            self.base_url = os.path.dirname(m.group(3))
            if not self.base_url.startswith("/"):
                self.base_url = "/"+self.base_url

            if self.base_url.endswith("/"):
                self.base_url = self.base_url[:-1]

        except Exception,e:
            self.method = ''
            self.host = ''
            self.base_url = ''

        self.comment = False

    def resolve_reference(self, reference, hint='', build_reference=True):
        original_reference = reference

        ## Absolute reference
        if reference.startswith('http'):
            pass
        elif reference.startswith("/"):
            path = normpath("%s" % (reference))
            reference="%s://%s%s" % (self.method, self.host, path)
        else:
            path = normpath("/%s/%s" % (self.base_url,reference))
            reference="%s://%s%s" % (self.method, self.host, path)

        ## Try to make reference more url friendly:
#        reference = reference.replace(" ","%20")
        reference = decode_entity(reference)
        dbh = DB.DBO(self.case)
        dbh.execute("select inode_id from http where url=%r and not isnull(http.inode_id) limit 1", reference)
        row = dbh.fetch()
        if row and row['inode_id']:
            result = '"f?%s"' % query_type(case=self.case,
                                           family="Network Forensics",
                                           report="ViewFile",
                                           inode_id=row['inode_id'],
                                           hint=hint)
            if build_reference:
                result += " reference=\"%s\" " % reference

            return result

        ## Maybe its in the sundry table:
        dbh.execute("select id from http_sundry where url = %r and present = 'yes'",
                    reference)
        row = dbh.fetch()
        if row and row['id']:
            result = '"f?%s"' % query_type(case=self.case,
                                           family="Network Forensics",
                                           report="ViewFile",
                                           sundry_id=row['id'],
                                           hint=hint)
            if build_reference:
                result += " reference=\"%s\" " % reference

            return result

        ## We could not find it, so we try to insert to the sundry table
        dbh.check_index('http_sundry','url')
        dbh.execute("select * from http_sundry where url=%r", reference)
        row = dbh.fetch()
        if not row:
            dbh.insert('http_sundry', url = reference)

        result = "images/spacer.png"
        if build_reference:
            result += " reference=\"%s\" " % reference

        return result

class HTMLParser(lexer.Lexer):
    state = "CDATA"
    flags = re.I
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
        [ "SCRIPT", "(.*?)</script[^>]*>", "SCRIPT_END", "CDATA" ],
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
        [ "ATTRIBUTE LIST", "(?ms)\s+", "SPACE", "ATTRIBUTE LIST"],

        ## End tag:
        [ "ATTRIBUTE LIST", "/>", "SELF_CLOSING_TAG,END_TAG", "CDATA" ],

        ## Attribute without a value - we look ahead after the name to
        ## confirm that there is no =. The lookahead is important to
        ## ensure we dont match an attribute with a value but the
        ## "=value" is just not here yet but will be in the next feed
        [ "ATTRIBUTE LIST", r"([-a-z0=9A-Z]+)(?=( [^\s]|[/>]))", "ATTRIBUTE_NAME", "ATTRIBUTE LIST"],

        ## Quoted attribute values
        [ "ATTRIBUTE VALUE", "(?ms)'([^']*)'|\"([^\"]*)\"", "ATTRIBUTE_VALUE", "ATTRIBUTE LIST" ],
        
        ## Non quoted attribute value
        [ "ATTRIBUTE VALUE", " *([^ <>\"\']+) ?", "ATTRIBUTE_VALUE", "ATTRIBUTE LIST" ],
        ]

    def __init__(self, verbose = 0, tag_class = None):
        lexer.Lexer.__init__(self, verbose)
        self.Tag = tag_class or Tag
        
        ## First we create the root of the DOM
        self.TAG_START(None, None)
        self.root = self.tag
        self.stack = [self.root,]
        self.tag.name = 'root'
        
    def CDATA(self, token, match):
        self.tag.add_child(match.group(0))

    def CLOSING_TAG(self, token, match):
        self.tag.type = 'close'

    def SELF_CLOSING_TAG(self, token, match):
        self.tag.type = 'selfclose'

    def TAG_NAME(self, token,match):
        self.tag.name = match.group(0).lower()

    def SCRIPT(self, token, match):
        self.tag.add_child(match.group(1))

    def SCRIPT_END(self, t, m):
        self.SCRIPT(t,m)
        self.tag.type = 'close'
        self.END_TAG(t,m)

    def ATTRIBUTE_NAME(self, token, match):
        self.current_attribute = match.group(1)
        self.tag[self.current_attribute] = ''

    def END_TAG(self, token, match):
        ## These tags need to be ignored because often they do not balance
        for t in ['br', 'p', 'meta', 'link']:
            if self.tag.name==t:
                self.tag.type = 'selfclose'

        if self.tag.type=='close':
            ## Pop the last tag off the stack
            try:
                ## We go back in the stack until we find the matching
                ## opening tag for this closing tag. This helps us fix
                ## situations where tags are not properly balanced.
                while 1:
                    old_tag = self.stack.pop(-1)
                    if old_tag.name == self.tag.name:
                        self.tag = self.stack[-1]
                        break
                    
            except IndexError: pass
        elif self.tag.type=='selfclose':
            try:
                self.stack[-1].add_child(self.tag)
                self.tag = self.stack[-1]
            except IndexError:
                self.TAG_START(None, None)
            
        elif self.tag.type=='open':
            ## Push the tag into the end of the stack and add it to
            ## our parent
            try:
                self.stack[-1].add_child(self.tag)
            except IndexError: pass
            
            self.stack.append(self.tag)

        if self.tag.name == 'script' and self.tag.type=='open':
            return "SCRIPT"
                
    def TAG_START(self, token, match):
        self.tag = self.Tag()
        
    def ATTRIBUTE_VALUE(self, token, match):
        self.tag[self.current_attribute] = match.group(1) or match.group(2)

    def close(self):
        """ Just a conveniece function to force us to parse all the data """
        while self.next_token(): pass

if __name__ == '__main__':
    l = HTMLParser(verbose=1, tag_class = SanitizingTag)

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
            while l.next_token(end=False): pass

        while l.next_token(): pass
        print "Total error rate %s" % l.error

        ## This is a test for dom navigation
        root = l.root
        print root.tree()
        print "Inner HTML %s" % root.innerHTML()

        print l.Tag
        
        tag = root.find('pre')
        print tag.innerHTML()
