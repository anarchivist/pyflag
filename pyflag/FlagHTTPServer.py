#!/usr/bin/env python2.3
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
#  Version: FLAG $Name:  $ $Date: 2004/10/26 00:02:58 $
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

import SimpleHTTPServer
import pyflag.FlagFramework as FlagFramework
import pyflag.HTMLUI as UI
import pyflag.TypeCheck as TypeCheck
import cgi
import re,time,sys
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.Theme

class FlagServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """ Main flag webserver handler.

    Dispatches the relevant reports depending on HTTP requests """
    
    server_version = "Flag Server, Version "+FlagFramework.flag_version
    def do_GET(self):
        i = self.path.rfind('?')
        result = flag.ui()
        
        if i >= 0:
            base, query = self.path[:i], FlagFramework.query_type(cgi.parse_qsl(self.path[i+1:]))
        else:
            base,query = (self.path , FlagFramework.query_type([]))

        ct=''
        if base.endswith(".js"):
            ct="text/javascript"
            
        #Is this a request for an image?
        if re.search("\.(png|jpg|gif)$",base):
            ct="image/jpeg"
            
        if ct:
            i=base.rfind('/')
            try:
                import sys
                self.send_response(200)
                self.send_header("Content-type",ct)
                self.end_headers()
                fd = open(config.IMAGEDIR + base[i+1:])
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
        print query
        if query.has_key('draw_stored') and UI.HTMLUI.store_dict.has_key(query['draw_stored']):
            result = UI.HTMLUI.store_dict[query['draw_stored']]
        elif query.has_key('callback_stored') and UI.HTMLUI.callback_dict.has_key(query['callback_stored']):
            result=flag.ui()
            result.defaults = query
            cb=query['callback_stored']
#            del query['callback_stored']
            cb=UI.HTMLUI.callback_dict[cb]
            cb(query,result)

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
                      try:
                          theme=pyflag.Theme.factory(query['theme'])
                      except KeyError:
                          theme=pyflag.Theme.factory()
                      result = theme.menu(flag,query)
                      result.defaults=query
                  else:
                      result = flag.process_request(query)              
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
        try:
            for i in result.headers:
                self.send_header(i[0],i[1])
        except AttributeError:
            pass
        
        self.send_header("Content-type", result.type)
        self.end_headers()
        
        self.wfile.write(result.display())
        return

if __name__ == "__main__":
    flag = FlagFramework.Flag()
    #Set the UI module to produce HTML
    flag.ui = UI.HTMLUI

    #Set the default graphing module to produce SVG using ploticus
    import pyflag.Graph as Graph

    Graph.Graph = Graph.Ploticus
    
    SimpleHTTPServer.test(HandlerClass = FlagServerHandler)
