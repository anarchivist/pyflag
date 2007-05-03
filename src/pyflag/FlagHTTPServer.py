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
#  Version: FLAG $Version: 0.84RC1 Date: Fri Feb  9 08:22:13 EST 2007$
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
import pyflag.HTMLUI as HTMLUI
import pyflag.pyflaglog as pyflaglog
import cgi,os
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
            rest, query_str = self.path[:i], self.path[i+1:]
        elif '=' in self.path:
            rest,query_str = '',self.path[1:]
        else:
            rest,query_str = self.path,''

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
            
        if query_str:
            env['QUERY_STRING'] = query_str

        ## FieldStorage does not seem to include GET parameters in POSTs:
        if self.command=="POST":
            query_list=cgi.parse_qsl(query_str)
        else:
            query_list=()
        
        form = cgi.FieldStorage(fp=self.rfile,headers = None, environ=env)
        query=FlagFramework.query_type(query_list, base=rest,user=user, passwd=passwd)

        for key in form.keys():
            ## See if key has a filename, if so we store it ala php:
            try:
                if form[key].filename:
                    query["%s_filename" % key] = form[key].filename
            except AttributeError:
                pass
            
            try:
                value = form[key].value
                ## We only accept non-empty args
                if len(value)>0 and value!='None':
                    query[key]= value
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

        for k,v in query.q:
            if v=='None':
                del query[k]
                
        self.query=query
        return query

    def format_date_time_string(self, sec):
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(sec)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
                self.weekdayname[wd],
                day, self.monthname[month], year,
                hh, mm, ss)
        return s

    def parse_date_time_string(self, s):
        return time.mktime(time.strptime(s, "%a, %d %b %Y %H:%M:%S %Z"))

    def do_POST(self):
        self.do_GET()

    def do_HEAD(self):
        headers = {}
        headers['Expires']='-1'
        for k,v in headers.items():
            self.send_header(k,v)
    
    def do_GET(self):
        headers = {}
        
        ## Calculate the query from the request.
        query=self.parse_query()

        result = flag.ui(query=query)
        result.generator=HTMLUI.HTTPObject()
        
        ## Work out if the request was for a static object
        ct=''
        if query.base.endswith(".js"):
            ct="text/javascript"
            
        #Is this a request for an image?
        elif re.search("\.(png|jpg|gif|ico)$",query.base):
            ct="image/jpeg"
        
        elif re.search("\.(css)$",query.base):
            ct="text/css"

        elif re.search("\.(htm)l?$",query.base):
            ct="text/html"
            
        if ct:
            try:
                import sys
                path = os.path.normpath(config.DATADIR + query.base)
                if path.startswith(os.path.normpath(config.DATADIR)):
                    ## Check if there is a compressed version of this file:
                    try:
                        s=os.stat(path+".gz")
                        path = path+".gz"
                        content_encoding = "gzip"
                    except:
                        s = os.stat(path)
                        content_encoding = None
                        
                    try:
                        ## This is the last modified time the browser
                        ## is asking for in local time (not GMT)
                        last_time = self.parse_date_time_string(
                            self.headers.get('If-Modified-Since','')
                            )-time.timezone

                        #print last_time, s.st_mtime, path

                        ## If the browsers idea of the modified time
                        ## is different that ours, we cant say it was
                        ## not modified and to be safe we return the
                        ## current version.
                        if int(last_time) == int(s.st_mtime):
                            self.send_response(304)
                            self.send_header("Expires","Sun, 17 Jan 2038 19:14:07 GMT")
                            self.send_header("Connection","close")
                            self.end_headers()
                            return
                        
                    except ValueError:
                        print self.headers.get('If-Modified-Since','')
                    
                    self.send_response(200)
                    self.send_header("Content-type",ct)

                    ## Support content encodings. FIXME: This needs to
                    ## do this only when the browser sends the
                    ## Accept-Encodings.
                    if content_encoding:
                        print "Will send %s as %s encoding" % (content_encoding,path)
                        self.send_header("Content-Encoding",content_encoding)
                        
                    self.send_header("Last-Modified",self.format_date_time_string(s.st_mtime))
                    self.send_header("Etag",s.st_ino)
                    self.send_header("Connection","close")
                    self.send_header("Expires","Sun, 17 Jan 2038 19:14:07 GMT")                
                    self.end_headers()
                    fd = open(path)
                    f = fd.read()
                    self.wfile.write(f)
                    fd.close()
                    return
                else: raise TypeError("Forbidden")
            except (TypeError,OSError),e:
                self.wfile.write("File not found: %s"%e)
                return

        #We need to check the configuration and if it is incorrect, we prompt the user
        if flag.check_config(result,query):
            self.send_response(200)
            self.send_header("Content-type",result.type)
            self.end_headers()
            self.wfile.write(result.display())
            return

        # Did the user asked for a complete render of the window?
        if query.has_key('__main__'):
            theme=pyflag.Theme.get_theme(query)
            result = theme.menu(flag,query)
            result.defaults=query
            
        #Is this a request for a saved UI?
        elif query.has_key('draw_stored'):
            result = flag.store.get(query['draw_stored'])
            
            ## This expires stored pictures in case pyflag is
            ## restarted
            headers['Expires']='-1'
        elif query.has_key('callback_stored'):
            cb_key = query.getarray('callback_stored')[-1]

            ## Make a new UI
            result.decoration = 'naked'
            try:
                ## Get the callback from the store
                try:
                    cb=flag.store.get(cb_key)
                except KeyError:
                    raise Exception("Session expired. Please try to select this report from the menu\n")

                ## Note who the cb is: (The UI object knows which cb it was generated from).
                result.callback = cb_key
                
                ## Use it
                cb(query,result)
                ## If the cb raises an exception, we let the user know:
            except Exception,e:
                pyflaglog.log(pyflaglog.ERROR,"Unable to call callback %s: %s" % (cb_key,e))
                result.clear()
                result.heading("Error")
                result.text("%s" % e)
                result.text(FlagFramework.get_bt_string(e))

            ## Return the cb to the store:
            #flag.store.put(cb, key=cb_key)
            
            ## This ensures that callbacks are recalled each time they
            ## are drawn
            headers['Expires']='-1'


        #Nope - just do it
        else:            
              try:
                  #Did the user request a report?
                  if not query.has_key('family') or not query.has_key('report'):
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

    def log_message(self, format, *args):
        pyflaglog.log(pyflaglog.INFO, "%s - - [%s] %s\n" %
                      (self.address_string(),
                       self.log_date_time_string(),
                       format%args))
        
class FlagHTTPServer( SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    pass

#class FlagHTTPServer( BaseHTTPServer.HTTPServer):
#    pass

def Server(HandlerClass = FlagServerHandler,
           ServerClass = FlagHTTPServer, protocol="HTTP/1.0"):
    server_address = (config.HTTPSERVER_BINDIF,config.HTTPSERVER_PORT)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)
    httpd.socket.settimeout(1.0)
    sa = httpd.socket.getsockname()
    print "Serving PyFlag requests on %s" % (sa,)
    httpd.serve_forever()

config.add_option("THEME", default='Menu',
                  help="Theme to use (currently Menu, AJAX)")

config.add_option("HTTPSERVER_BINDIF", default='127.0.0.1',
                  help="Interface to listen on for http connections")

config.add_option("HTTPSERVER_PORT", default=8000, type='int',
                  help="TCP Port to listen on for http connections")

config.add_option("DATADIR", 
                  help="Directory where miscelaneous pyflag data files are found")

if __name__ == "__main__":
    ## Parse the command line args:
    config.set_usage(usage = "The main PyFlag HTTP Server.")

    ## make sure all the modules were parsed to ensure that all the
    ## options are collected
    import pyflag.Registry as Registry

    Registry.Init()

    ## Parse all the command line options:
    config.parse_options()
    
    flag = FlagFramework.Flag()
    FlagFramework.GLOBAL_FLAG_OBJ =flag
    #Set the UI module to produce HTML
    if config.THEME=="AJAX":
        import pyflag.AJAXUI as AJAXUI
        flag.ui = AJAXUI.AJAXUI
    else:
        import pyflag.HTMLUI as HTMLUI
        flag.ui = HTMLUI.HTMLUI

    import pyflag.Graph as Graph
    Graph.Graph = Graph.Ploticus

    ## Start the workers
    import pyflag.Farm as Farm
    Farm.start_workers()

    ## Start the logging thread:
    pyflaglog.start_log_thread()

    try:
        Server(HandlerClass = FlagServerHandler)
    finally:
        pyflaglog.log(0,"Terminating Logger")
