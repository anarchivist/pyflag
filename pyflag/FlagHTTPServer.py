#!/usr/bin/env python
# ******************************************************
# Copyright 2004: Commonwealth of Australia.
#
# Developed by the Computer Network Vulnerability Team,
# Information Security Group.
# Department of Defence.
#
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.76 Date: Sun Apr 17 21:48:37 EST 2005$
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

""" Main HTTP server module """

import BaseHTTPServer, SimpleHTTPServer, SocketServer
import pyflag.Reports as Reports
import pyflag.FlagFramework as FlagFramework
import pyflag.HTMLUI as UI
import cgi
import re,time,sys
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Theme

class FlagServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """ Main flag webserver handler.

    Dispatches the relevant reports depending on HTTP requests """
    
    server_version = "PyFlag Server, "+FlagFramework.flag_version.replace(":",'-')
    def parse_query(self):
        """ Parses the query and prepares a query object.

        Returns query object prepared from the request
        """
        # check for authentication and pull out auth fields to add to
        # query type
        user = passwd = None
        try:
            import base64
            authtype, authtoken = self.headers['Authorization'].split()
            user, passwd = base64.decodestring(authtoken).split(':')
        except KeyError:
            # if authentication is required, the reports will
            # throw an exception later, dont worry about it here.
            pass

        ## Use the cgi module to parse out the request. This allows us
        ## to use POST, upload files etc:
        i = self.path.rfind('?')
        if i>=0:
            rest, query = self.path[:i], self.path[i+1:]
        elif '=' in self.path:
            rest,query = '',self.path[1:]
        else:
            rest,query = self.path,''
            
            
        env = {}
        env['GATEWAY_INTERFACE'] = 'CGI/1.1'
        env['SERVER_PROTOCOL'] = self.protocol_version
        env['REQUEST_METHOD'] = self.command
        if self.headers.typeheader is None:
            env['CONTENT_TYPE'] = self.headers.type
        else:
            env['CONTENT_TYPE'] = self.headers.typeheader
            
        length = self.headers.getheader('content-length')
        if length:
            env['CONTENT_LENGTH'] = length
            
        if query:
            env['QUERY_STRING'] = query

        form = cgi.FieldStorage(fp=self.rfile,headers = None, environ=env)
        query=FlagFramework.query_type(base=rest,user=user, passwd=passwd)
        
        for key in form.keys():
            ## See if key has a filename, if so we store it ala php:
            try:
                if form[key].filename:
                    query["%s_filename" % key] = form[key].filename
            except AttributeError:
                pass
            
            try:
                query[key]=form[key].value
            except AttributeError:
                for value in form[key]:
                    query[key]=value.value

        ## This handles the case where the entire query is submitted
        ## in a single parameter called pseudo_post_query. This is
        ## done for stupid browsers like IE which refuse to handle
        ## long queries using get - so we post the entire query
        ## through javascript:
        try:
            qsl = query['pseudo_post_query']
            if '?' in qsl:
                qsl=qsl[qsl.find('?')+1:]
                
            query = FlagFramework.query_type(cgi.parse_qsl(qsl),user=user, passwd=passwd)
            print "pseudo posted query is %s" % query
        except KeyError:
            if self.command=='POST':
                print "posted query is %s" % query

        self.query=query
        return query
##            self.wfile.write("%s = %s <br>\n" % (key,form[key]))

##        if i >= 0:
##            base, query = self.path[:i], FlagFramework.query_type(cgi.parse_qsl(self.path[i+1:]), user=user, passwd=passwd)
##        else:
##            base, query = (self.path , FlagFramework.query_type([], user=user, passwd=passwd ))

    def do_POST(self):
        self.do_GET()
    
    def do_GET(self):
        headers = {}
        
        result = flag.ui()
        result.generator=UI.HTTPObject()

        ## Calculate the query from the request.
        query=self.parse_query()

        ## Work out if the request was for a static object
        ct=''
        if query.base.endswith(".js"):
            ct="text/javascript"
            
        #Is this a request for an image?
        if re.search("\.(png|jpg|gif)$",query.base):
            ct="image/jpeg"
        
        if re.search("\.(css)$",query.base):
            ct="text/css"
            
        if ct:
            i=query.base.rfind('/')
            try:
                import sys
                self.send_response(200)
                self.send_header("Content-type",ct)
                self.end_headers()
                fd = open(config.IMAGEDIR + query.base[i+1:])
                f = fd.read()
                self.wfile.write(f)
                fd.close()
                return
            except TypeError:
                self.wfile.write("File not found")
                return

        #We need to check the configuration and if it is incorrect, we prompt the user
        if flag.check_config(result,query):
            self.send_response(200)
            self.send_header("Content-type",result.type)
            self.end_headers()
            self.wfile.write(result.display())
            return

        #Is this a request for a saved UI?
        if query.has_key('draw_stored') and UI.HTMLUI.store_dict.has_key(query['draw_stored']):
            result = UI.HTMLUI.store_dict[query['draw_stored']]
            
            ## This expires stored pictures in case pyflag is
            ## restarted
            headers['Expires']='-1'
        elif query.has_key('callback_stored') and UI.HTMLUI.callback_dict.has_key(query['callback_stored']):
            cb = query.getarray('callback_stored')[-1]

            result=flag.ui(query=query)
#            cb=query['callback_stored']
#            del query['callback_stored']
            cb=UI.HTMLUI.callback_dict[cb]
#            del UI.HTMLUI.callback_dict[cb]
            cb(query,result)
            ## This ensures that callbacks are recalled each time they
            ## are drawn
            headers['Expires']='-1'

        #Nope - just do it
        else:            
              #Clear the store if its been there too long:
              expired_time = time.time() - 100
              for k in UI.HTMLUI.store_dict.keys():
                  if expired_time > UI.HTMLUI.time_dict[k]:
                      del UI.HTMLUI.store_dict[k]
                      del UI.HTMLUI.time_dict[k]
                      
              ## We sometimes need to force the gc, this may prove to be a performance hit?
              try:
                  import gc
                  gc.collect()
              except ImportError:
                  pass

              try:
                  #Did the user request a report?
                  if not query.has_key('family') or not query.has_key('report'):
                      query['family'] = None
                      theme=pyflag.Theme.get_theme(query)
                      result = theme.menu(flag,query)
                      result.defaults=query
                  else:
                      try:
                          result = flag.process_request(query)
                      except FlagFramework.AuthError, e:
                          # deal with authentication issues here
                          self.send_response(401)
                          self.send_header("WWW-Authenticate", "Basic realm=%r" % self.server_version)
                          self.end_headers()
                          # if e is a UI, it is what the report wanted us to display as an error page
                          try:
                              self.wfile.write(e.result.display())
                          except (IndexError, AttributeError):
                              self.wfile.write("<html><body>Authentication Required for this page</body></html>")
                          return
              except Exception,e:
                  result = flag.ui()
                  result.defaults = query
                  result.heading("Error")
                  import traceback,sys
                  import cStringIO
                  
                  a = cStringIO.StringIO()
                  traceback.print_tb(sys.exc_info()[2], file=a)
                  a.seek(0)
                  result.para("%s: %s" % (sys.exc_info()[0],sys.exc_info()[1]))
                  result.pre(a.read())
                  a.close()
                  
        ## If the UI has some headers, we send those as well:
        self.send_response(200)
        for k,v in headers.items():
            self.send_header(k,v)
        
        if result.generator and result.generator.generator:
            self.send_header("Content-type", result.generator.content_type)
            
            for i in result.generator.headers:
                self.send_header(i[0],i[1])
                self.end_headers()

            ## Print the data
            for data in result.generator.generator:
                self.wfile.write(data)

            return

        self.send_header("Content-type", result.type)
        self.end_headers()

        self.wfile.write(result.display())
        return

#class FlagHTTPServer( SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
#    pass

class FlagHTTPServer( BaseHTTPServer.HTTPServer):
    pass

def Server(HandlerClass = FlagServerHandler,
           ServerClass = FlagHTTPServer, protocol="HTTP/1.0"):

    ## FIXME: This needs to be properly parsed
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8000

    server_address = ('',port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)
    httpd.socket.settimeout(1.0)
    sa = httpd.socket.getsockname()
    print "Serving PyFlag requests on %s" % (sa,)
    httpd.serve_forever()

if __name__ == "__main__":
    flag = FlagFramework.Flag()
    FlagFramework.GLOBAL_FLAG_OBJ =flag
    #Set the UI module to produce HTML
    flag.ui = UI.HTMLUI

    #Set the default graphing module to produce SVG using ploticus
    import pyflag.Graph as Graph

    Graph.Graph = Graph.Ploticus

    Server(HandlerClass = FlagServerHandler)
