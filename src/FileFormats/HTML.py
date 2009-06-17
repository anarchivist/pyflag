#!/usr/bin/env python
""" This is an implementation of a HTML parser using the pyflag lexer. 

We do not use pythons native sgml parser because that is too fragile
for us. The native parser will raise when encountering invalid html,
causing us to mis-parse many pages we see in the wild.

We concentrate on robustness here - we detect errors and flag them, but we try
to keep going as much as possible. 

"""

import lexer, struct, posixpath
import sys,re,urllib,os
import pyflag.DB as DB
from pyflag.DB import expand
from FlagFramework import query_type, normpath, get_bt_string, smart_str, smart_unicode, iri_to_uri
import pyflag.FileSystem as FileSystem
import pyflag.FlagFramework as FlagFramework

XML_SPECIAL_CHARS_TO_ENTITIES = { "'" : "squot",
                                  '"' : "quote",
                                  '"' : "quot",
                                  "&" : "amp",
                                  " " : "nbsp",
                                  "<" : "lt",
                                  ">" : "gt" }

def unquote(string):
    for k,v in XML_SPECIAL_CHARS_TO_ENTITIES.items():
        string = string.replace("&%s;" % v, k)

    return string

def url_unquote(string):
    def decoder(x):
        return x.group(1).decode("hex")

    ## we can use this to handle arbitrary levels of quoting
    string = re.sub("%(..)", decoder, string)
        
    ## references seem to _always_ be encoded using utf8 - even if the
    ## page is encoded using a different charset??? This whole quoting
    ## thing is very confusing.
    return smart_unicode(string, 'utf8')

def decode_entity(string):
    def decoder(x):
        return struct.pack("H",int(x.group(1))).decode("utf16")
        
    return re.sub("&#(\d+);", decoder, string)

def decode_unicode(string):
    try:
        return re.sub(r"\\u(....)", lambda x: struct.pack("H",int(x.group(1),16)).decode("utf16").encode("utf8"), string)
    except:
        return string

def decode(string):
    return decode_unicode(decode_entity(unquote(string)))

def join_urls(first, last):
    """ Joins the first url with the last, returnning a normalised
    url. If last url is absolute we dont join them. This function can
    be used to ensure that urls are converted to absolute urls."""
    if last.startswith("http"):
        return last

    m = re.match("(https?://[^/]+/)([^?]+)/", first)
    if first:
        return m.group(1) + posixpath.normpath("%s/%s" % (m.group(2), last))
    
    else:
        return posixpath.normpath("%s/%s" % (first, last))

## NOTE: All data within the tag and parser is kept as binary
## strings. The parser can discover the charset while parsing the
## page, but defaults to utf8. Data is converted to unicode when the
## tag is printed or attributes are fetched using __getitem__. We must
## ensure that the lexer operates on byte strings (not unicode)
## because unicode regular expressions are very slow.
class Tag:
    ## This will be replaced by a shared reference to the parsers
    ## charset. This allows the lexer to change everyone's charset by
    ## updating this array.
    charset = ['utf8',]
    def __init__(self, name=None, attributes=None, charset=None):
        self.name = name
        self.attributes = attributes or {}
        self.children = []
        self.type = 'open'
        if charset:
            self.charset = charset

    def __setitem__(self, item, value):
        self.attributes[item.lower()] = value

    def __getitem__(self, item):
        return smart_unicode(self.attributes[item.lower()], self.charset[0],'ignore')

    def __str__(self):
        attributes = "".join([expand(" %s='%s'",(k,iri_to_uri(v))) for k,v \
                              in self.attributes.items() if v != None ])
        
        if self.type == 'selfclose':
            return expand("<%s%s/>", (self.name, attributes))
        else:
            return expand("<%s%s>%s</%s>", (self.name, attributes,
                                      self.innerHTML(), self.name))

    def __unicode__(self):
        return smart_unicode(self.__str__(), encoding = self.charset[0])

    def innerHTML(self):
        """ charset is the desired output charset """
        result = u''
        for c in self.children:
            result += smart_unicode(c, encoding = self.charset[0])

        return result

    def add_child(self, child):
        ## Try to augment CDATAs together for efficiency:
        try:
            ## CDATAs are strings, but tags are classes without __add__
            self.children[-1] += child
        except (IndexError, TypeError):
            self.children.append(child)

    def prune(self):
        """ Remove all children of this node """
        self.children = []

    def tree(self, width=''):
        result = expand("%s%s\n", (width, self.name))
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
	    return ' '

        data = decode_unicode(self.innerHTML())
        data = re.sub(r"[\r\n]+","\n",data)
        data = re.sub(r" +"," ",data)
        data = unquote(data)
        #data = data.replace("\n","<br />")

        return data+" "

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
                            'value', 'checked', 'rows','cols','media',
                            'framespacing','frameborder','contenteditable', "dir",
                            "nowrap"
                            ]

    ## This header is automatically appended to each HTML <head/>
    header = '''<link rel="stylesheet" type="text/css" href="images/html_render.css" ></link>

    '''

    body_extra = '''<div class="overlaymenu"><a href="#" onclick="javascript:show_links();"  id="pf_link_menu">Show all links</a></div>
    <script src="javascript/html_render.js" type="text/javascript" language="javascript" ></script>'''     
    def css_filter(self, data):
        def resolve_css_references(m):
            action = m.group(1)
            url = m.group(2)
            args={}
            ## This is a bit of a hack - magic detection of css is
            ## quite hard
            if url.endswith("css"):
                args['hint'] = 'text/css'
                
            result = self.resolve_reference(url, build_reference = False, **args)
            return "%s(%s)" % (action,result)
        
        data = re.sub("(?i)(url)\(\"?([^\)\"]+)\"?\)",
                      resolve_css_references,
                      data)
        data = re.sub("(?i)(@import)\s+'([^']+)'",
                      resolve_css_references,
                      data)
        return data

    def __str__(self):
        postfix = ''
        ## Some tags are never allowed to be outputted
        if self.name not in self.allowable_tags:
            if self.name in self.forbidden_tag:
                return ''
            #print "Rejected tag %s" % self.name
            return self.innerHTML()

        if self.name == 'head':
            self.children = [self.header,] + self.children
        elif self.name =='body':
            self.children = [self.body_extra, ] + self.children

        ## Frames without src are filtered because IE Whinges:
        if self.name == 'iframe' and 'src' not in self.attributes:
		return ''

        attributes = "".join([" %s='%s'" % (k,v) for k,v \
                              in self.attributes.items() if k in \
                              self.allowable_attributes])

	if 'style' in self.attributes:
            attributes += ' style=%r' % self.css_filter(self.attributes['style'] or '')

        if 'http-equiv' in self.attributes:
            if self.attributes['http-equiv'].lower() == "content-type":
                ## PF _always_ outputs in utf8
                attributes += ' http-equiv = "Content-Type" content="text/html; charset=UTF-8"'
                
        if 'src' in self.attributes:
            attributes += ' src=%s' % self.resolve_reference(self.attributes['src'])

        try:
            if 'href' in self.attributes:
                if self.name == 'link':
                    attributes += " href=%s" % self.resolve_reference(self.attributes['href'], 'text/css')
                else:
                    attributes += DB.expand(' href="javascript: alert(%r)"',
                                            iri_to_uri(DB.expand("%s",self.attributes['href'])[:100]))
                    postfix = self.mark_link(self.attributes['href'])
        except: pass
        
        ## CSS needs to be filtered extra well
        if self.name == 'style':
            return expand("<style %s>%s</style>" , (attributes,
                                             self.css_filter(self.innerHTML())))
        
        if self.type == 'selfclose':
            return expand("<%s%s/>%s" , (self.name, attributes, postfix))
        else:
            return expand("<%s%s>%s</%s>%s", (self.name, attributes,
                                            self.innerHTML(),
                                            self.name,postfix))


    def resolve_reference(self, reference, hint=''):
        return '"images/spacer.png"  '

    def mark_link(self, reference):
        """ Create markup to indicate the link.

        We just add an overlay to represent the link.
        """
        if not reference: return ''
        postfix = ''
        ## Absolute reference
        if reference.startswith('http'):
            pass
        elif reference.startswith("/"):
            path = normpath("%s" % (reference))
            reference="%s://%s%s" % (self.method, self.host, path)
        elif self.method:
            ## FIXME: This leads to references without methods:
            reference="%s/%s" % (self.base_url, reference)
            if reference.startswith("http://"):
                reference='http:/'+FlagFramework.normpath(reference[6:])

        reference = url_unquote(decode_entity(unquote(reference)))
        dbh = DB.DBO(self.case)
        dbh.execute("select mtime from inode where inode_id=%r", self.inode_id)
        row = dbh.fetch()

        dbh.execute("select inode.inode_id, inode.mtime, datediff(inode.mtime, %r) as diff, url "\
                    "from http join inode on "\
                    "inode.inode_id=http.inode_id where url=%r and not "\
#                    "isnull(http.inode_id) and size > 0 and inode.mtime >= %r "\
                    "isnull(http.inode_id) "\
                    "order by inode.mtime asc limit 1", (row['mtime'],
                                                         reference, ))
        row = dbh.fetch()
        if row:
            print "Fetched %s %s ago" % (row['url'], row['diff'])
            postfix = "<div class='overlay'>Linked <a href=%s>%s</a><br>After %s</div>" % (
                self.make_reference_to_inode(row['inode_id'],None),
                row['url'][:50],
                row['diff'])

        return postfix
    
class SanitizingTag2(SanitizingTag):
    """ A more restrictive sanitiser which removes e.g. body tags etc """
    allowable_tags = [ 'b','i','a','img','em','br','strong',
                       'tt', 'li', 'ol', 'ul', 'p', 'table', 'td', 'tr',
                       'h1', 'h2', 'h3', 'pre',
                       'form', 'html', 'pre', 'body',
                       'sup', 'input', 'label', 'option','select',
                       'div','span','nobr','u', 
                       'textarea','center','small']

    forbidden_tag = [ 'script', 'style', 'meta', 'head' ]


import pyflag.Store as Store
URL_STORE = Store.Store()

def get_url(inode_id, case):
    try:
        store = URL_STORE.get(case)
    except KeyError:
        store = Store.Store()
        URL_STORE.put(store, key=case)

    ## Now try to retrieve the URL:
    try:
        url = store.get(inode_id)
    except KeyError:
        url = ''
        dbh = DB.DBO(case)
        dbh.execute("select url from http where inode_id=%r limit 1", inode_id)
        row = dbh.fetch()
        if not row:
            dbh.execute("select url from http_sundry where id=%r limit 1", inode_id)
            row = dbh.fetch()
            
        if row:
            url = row['url']
        else:
            ## Its not in the http take, maybe its in the VFS:
            dbh.execute("select concat(path,name) as path from file where inode_id = %r limit 1", inode_id)
            row = dbh.fetch()
            if row:
                url = row['path']

        store.put(url, key=inode_id)

    return url

class ResolvingHTMLTag(SanitizingTag):
    """ A special tag which resolves src and href back into the
    database. This is useful in order to show embedded images etc from
    the traffic.

    Note that you would probably want to Curry this before passing it
    to the parser because we need to know the inode and case (our
    constructor takes more parameters.
    """
    url_re = re.compile("(http|ftp|HTTP|FTP)://([^/]+)(/[^?]*)")
    def __init__(self, case, inode_id, name=None, attributes=None, charset=None):
        self.case = case
        self.inode_id = inode_id
        SanitizingTag.__init__(self, name, attributes, charset)

        ## Collect some information about this inode:
        url = get_url(inode_id, case)
        self.url=url
        m=self.url_re.search(url)
        if m:
            self.method = m.group(1).lower()
            self.host = m.group(2).lower()
            self.base_url = posixpath.dirname(m.group(3))
        else:
            self.method = ''
            self.host = ''
            self.base_url = url

        ##if not self.base_url.startswith("/"):
##            self.base_url = "/"+self.base_url
            
##        if self.base_url.endswith("/"):
##            self.base_url = self.base_url[:-1]
##        else:
##            self.base_url = posixpath.dirname(url)
            
        self.comment = False

    def make_reference_to_inode(self, inode_id, hint=None):
        """ Returns a reference to the given Inode ID.

        This needs to provide a URL to the specified resource.
        """
        result = query_type(case=self.case,
                                     family="Network Forensics",
                                     report="ViewFile",
                                     inode_id=inode_id)

        if hint:
            result['hint'] = hint

        return '"f?%s"' % result

    def follow_redirect(self, dbh, inode_id):
        """ Follows a redirect in inode_id and return the new inode_id """
        ## FIXME implement this
        return inode_id

    def resolve_reference(self, reference, hint='', build_reference=True):
        original_reference = reference

        ## Absolute reference
        if re.match("(http|ftp)", reference, re.I):
            pass
        elif reference.startswith("/"):
            path = normpath("%s" % (reference))
            reference="%s://%s%s" % (self.method, self.host, path)
        elif self.method:
            ## FIXME: This leads to references without methods:
            reference="%s://%s%s" % (self.method, self.host,
                                     FlagFramework.normpath("%s/%s" % (self.base_url, reference)))
            if reference.startswith("http://"):
                reference='http:/'+FlagFramework.normpath(reference[6:])

        ## If we get here the reference is not absolute, and we dont
        ## have a method - chances are that its in the VFS:
        else:
            fsfd = FileSystem.DBFS(self.case)
            new_reference = decode_entity(url_unquote(reference))
            url = posixpath.normpath(posixpath.join(posixpath.dirname(self.base_url),
                                                    new_reference))
            try:
                path, inode, inode_id = fsfd.lookup(path = url)
                if inode_id:
                    return self.make_reference_to_inode(inode_id)
            except RuntimeError: pass

        ## Try to make reference more url friendly:
        reference = reference.strip(" \"'\t")
        reference = url_unquote(decode_entity(unquote(reference)))
##        print reference, self.method, self.host, self.base_url, original_reference


        dbh = DB.DBO(self.case)
        dbh.execute("select http.status,http.inode_id from http join inode on "\
                    "inode.inode_id=http.inode_id where url=%r and not "\
                    "isnull(http.inode_id) and size > 0 limit 1", reference)
        row = dbh.fetch()
        if row and row['inode_id']:
            ## If the target was redirected - take care of that:
            ## (DANGER - a circular redirection could be problematic)
            ## FIXME - do this (we need to store the location header)
            if row['status'] == 302:
                inode_id = self.follow_redirect(dbh, row['inode_id'])
            else:
                inode_id = row['inode_id']

            ## This is needed to stop dbh leaks due to the highly
            ## recursive nature of this function.
            del dbh

            result = self.make_reference_to_inode(inode_id, hint)
            
            if build_reference:
                result += " reference=\"%s\" " % reference

            return result

        ## Maybe its in the sundry table:
        dbh.execute("select id from http_sundry where url = %r and present = 'yes'",
                    reference)
        row = dbh.fetch()
        if row and row['id']:
            del dbh
            result = self.make_reference_to_inode(row['id'], hint)

            if build_reference:
                result += " reference=\"%s\" " % reference

            return result

        ## We could not find it, so we try to insert to the sundry table
        dbh.check_index('http_sundry','url')
        dbh.execute("select * from http_sundry where url=%r", reference)
        row = dbh.fetch()
        if not row:
            dbh.insert("inode",
                       inode = "x", _fast=True)
            inode_id = dbh.autoincrement()
            dbh.execute("update inode set inode = 'xHTTP%s' where inode_id = %s " %(inode_id, inode_id))
            dbh.insert("file",
                       inode_id = inode_id,
                       inode = "xHTTP%s" % inode_id,
                       path = "/http_sundry/",
                       name = "xHTTP%s" % inode_id)
            
            dbh.insert('http_sundry', url = reference, id=inode_id)

        result = "images/spacer.png"
        if build_reference:
            result += " reference=\"%s\" " % reference

        print "Not found '%s' (%s + %s)" % (reference,original_reference, self.url)
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
        [ "TAG", "(?sm)\s+", "SPACE", "TAG" ],
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
        [ "TAG", "(?sm)[^\s/<>]+", "TAG_NAME", "ATTRIBUTE LIST"],

        ## An attribute list is a list of key=value pairs within a tag
        [ "ATTRIBUTE LIST", "([-a-z0-9A-Z_]+)\s*=", "ATTRIBUTE_NAME", "ATTRIBUTE VALUE"],
        [ "ATTRIBUTE LIST", ">", "END_TAG", "CDATA"],
        
        ## Swallow spaces
        [ "ATTRIBUTE LIST", r"(?ms)[\s\r\n]+", "SPACE", "ATTRIBUTE LIST"],

        ## End tag:
        [ "ATTRIBUTE LIST", "/>", "SELF_CLOSING_TAG,END_TAG", "CDATA" ],

        ## Attribute without a value - we look ahead after the name to
        ## confirm that there is no =. The lookahead is important to
        ## ensure we dont match an attribute with a value but the
        ## "=value" is just not here yet but will be in the next feed
        [ "ATTRIBUTE LIST", r"([-a-z0=9A-Z]+)(?=( [^\s]|[/>]))", "ATTRIBUTE_NAME", "ATTRIBUTE LIST"],

        ## Quoted attribute values
        [ "ATTRIBUTE VALUE", "(?ms)'([^'#]*)'|\"([^\"]*)\"", "ATTRIBUTE_VALUE", "ATTRIBUTE LIST" ],
        
        ## Non quoted attribute value
        [ "ATTRIBUTE VALUE", " *([^ <>\"\']+) ?", "ATTRIBUTE_VALUE", "ATTRIBUTE LIST" ],
        ]

    def __init__(self, verbose = 0, tag_class = None):
        lexer.Lexer.__init__(self, verbose)
        self.Tag = tag_class or Tag
        ## Default charset we use to decode our input. Note that this
        ## is an array in order to have all tags keep a reference to
        ## this. This way we can change our charset half way through
        ## parsing the document and have all existing tag objects
        ## update.
        self.charset = ["utf8",]
        
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
                while len(self.stack)>1:
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
            ## Nested tds are not allowed - a nested td implicitly
            ## closes the previous td - this handles code like
            ## <tr><td><td><td><td>
            if self.tag.name == 'td' and self.stack[-1].name == 'td':
                try:
                    self.stack.pop(-1)
                except: pass
            
            ## Push the tag into the end of the stack and add it to
            ## our parent
            try:
                self.stack[-1].add_child(self.tag)
            except IndexError: pass
            
            self.stack.append(self.tag)

        if self.tag.name == 'script' and self.tag.type=='open':
            return "SCRIPT"
                
    def TAG_START(self, token, match):
        self.tag = self.Tag(charset = self.charset)
        
    def ATTRIBUTE_VALUE(self, token, match):
        self.tag[self.current_attribute] = match.group(1) or match.group(2)
        if self.tag.name=='meta' and self.current_attribute=='content':
            m = re.search("charset=([^ \"]+)", self.tag[self.current_attribute])
            if m:
                self.charset[0] = m.group(1)

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
        while 1:
            line=fd.read(1024*10)
            if not(line): break
            l.feed(line)
            
            ## Get all the tokens
            while l.next_token(end=False): pass

        while l.next_token(): pass
        print "Total error rate %s" % l.error

        ## This is a test for dom navigation
        root = l.root
        print root.tree()
        print root.innerHTML()
        sys.exit(0)
        print "Inner HTML %s" % root.innerHTML()

        print l.Tag
        
        tag = root.find('pre')
        print tag.innerHTML()
